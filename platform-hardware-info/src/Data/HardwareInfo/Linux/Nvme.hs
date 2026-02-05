{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.Nvme
-- Description : Linux NVMe device information collection
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to collect NVMe device information
-- on Linux systems using the nvme-cli tool or sysfs.

#ifdef LINUX
module Data.HardwareInfo.Linux.Nvme
  ( -- * NVMe device enumeration
    getNvmeDevices
  , NvmeDeviceInfo(..)
    -- * Sysfs-based enumeration
  , getNvmeDevicesFromSysfs
  ) where

import Control.Exception (try, SomeException)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Directory (doesDirectoryExist, listDirectory, doesFileExist)
import System.FilePath ((</>))
import System.Process (readProcess)
import Data.Aeson (decode, Value(..), (.:?), (.:))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Types as Aeson
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BL8

import Data.HardwareInfo.Types
import Data.HardwareInfo.Linux.Sysfs (getBlockDeviceBusPath)
import System.Posix.Files (readSymbolicLink)

-- | NVMe device information
data NvmeDeviceInfo = NvmeDeviceInfo
  { nvmeDeviceName     :: !Text
  , nvmeModelNumber    :: !Text
  , nvmeSerialNumber   :: !Text
  , nvmeFirmwareRev    :: !Text
  , nvmeNamespaceId    :: !(Maybe Text)
  , nvmeEui64          :: !(Maybe Text)
  , nvmeNguid          :: !(Maybe Text)
  , nvmePciAddress     :: !(Maybe Text)  -- ^ PCI address (e.g., "0000:03:00.0")
  , nvmeBusPath        :: !(Maybe Text)  -- ^ Bus path (e.g., "pci-0000:03:00.0-nvme-1")
  } deriving (Show, Eq)

-- | Get NVMe devices - tries nvme-cli first, falls back to sysfs
getNvmeDevices :: IO [Component]
getNvmeDevices = do
  -- Try nvme-cli first
  cliResult <- getNvmeDevicesFromCli
  case cliResult of
    Right devices | not (null devices) -> return $ map toComponent devices
    _ -> do
      -- Fall back to sysfs
      sysfsResult <- getNvmeDevicesFromSysfs
      return $ map toComponent sysfsResult

-- | Convert NvmeDeviceInfo to Component
toComponent :: NvmeDeviceInfo -> Component
toComponent nvme = Component
  { componentClass = ClassNVMe
  , componentManufacturer = extractManufacturer (nvmeModelNumber nvme)
  , componentModel = nvmeModelNumber nvme
  , componentSerial = Just $ nvmeSerialNumber nvme
  , componentRevision = Just $ nvmeFirmwareRev nvme
  , componentFieldReplaceable = Just True
  , componentAddresses = buildAddresses nvme
  }
  where
    -- Build list of addresses from PCI and bus path
    buildAddresses :: NvmeDeviceInfo -> [ComponentAddress]
    buildAddresses n =
      let pciAddr = case nvmePciAddress n of
                      Just p -> [PCIAddress p]
                      Nothing -> []
          busAddr = case nvmeBusPath n of
                      Just b -> [NVMeAddress b]
                      Nothing -> []
      in pciAddr ++ busAddr

-- | Extract manufacturer from model number (heuristic)
extractManufacturer :: Text -> Text
extractManufacturer model
  | "Samsung" `T.isInfixOf` model = "Samsung"
  | "WD" `T.isPrefixOf` model = "Western Digital"
  | "WDC" `T.isPrefixOf` model = "Western Digital"
  | "Intel" `T.isInfixOf` model = "Intel"
  | "Micron" `T.isInfixOf` model = "Micron"
  | "SK hynix" `T.isInfixOf` model = "SK hynix"
  | "HYNIX" `T.isInfixOf` model = "SK hynix"
  | "Toshiba" `T.isInfixOf` model = "Toshiba"
  | "KIOXIA" `T.isInfixOf` model = "KIOXIA"
  | "Crucial" `T.isInfixOf` model = "Crucial"
  | "Kingston" `T.isInfixOf` model = "Kingston"
  | "Seagate" `T.isInfixOf` model = "Seagate"
  | otherwise = ""

-- | Get NVMe devices using nvme-cli (nvme list -o json)
getNvmeDevicesFromCli :: IO (Either Text [NvmeDeviceInfo])
getNvmeDevicesFromCli = do
  result <- try $ readProcess "nvme" ["list", "-o", "json"] ""
  case result of
    Left (_ :: SomeException) ->
      return $ Left "nvme-cli not available"
    Right output -> do
      case decode (BL8.pack output) :: Maybe Value of
        Nothing -> return $ Left "Failed to parse nvme list output"
        Just json -> return $ Right $ parseNvmeListJson json

-- | Parse nvme list JSON output
parseNvmeListJson :: Value -> [NvmeDeviceInfo]
parseNvmeListJson (Object obj) =
  case Aeson.parseMaybe (.: "Devices") obj of
    Just (Array devices) -> concatMap parseDevice (foldr (:) [] devices)
    _ -> []
  where
    parseDevice (Object dev) =
      case Aeson.parseMaybe parseNvmeDevice dev of
        Just info -> [info]
        Nothing -> []
    parseDevice _ = []

    parseNvmeDevice obj = do
      name <- obj .: "DevicePath"
      model <- obj .: "ModelNumber"
      serial <- obj .: "SerialNumber"
      firmware <- obj .:? "Firmware"
      return NvmeDeviceInfo
        { nvmeDeviceName = name
        , nvmeModelNumber = T.strip model
        , nvmeSerialNumber = T.strip serial
        , nvmeFirmwareRev = maybe "" T.strip firmware
        , nvmeNamespaceId = Nothing
        , nvmeEui64 = Nothing
        , nvmeNguid = Nothing
        , nvmePciAddress = Nothing  -- Will be populated later
        , nvmeBusPath = Nothing     -- Will be populated later
        }
parseNvmeListJson _ = []

-- | Get NVMe devices from sysfs (/sys/class/nvme/)
getNvmeDevicesFromSysfs :: IO [NvmeDeviceInfo]
getNvmeDevicesFromSysfs = do
  let nvmePath = "/sys/class/nvme"
  exists <- doesDirectoryExist nvmePath
  if not exists
    then return []
    else do
      controllers <- listDirectory nvmePath
      devices <- mapM (readNvmeController nvmePath) controllers
      return $ concat devices

-- | Read NVMe controller information from sysfs
readNvmeController :: FilePath -> String -> IO [NvmeDeviceInfo]
readNvmeController basePath controller = do
  let ctrlPath = basePath </> controller
  model <- readSysfsFile (ctrlPath </> "model")
  serial <- readSysfsFile (ctrlPath </> "serial")
  firmware <- readSysfsFile (ctrlPath </> "firmware_rev")

  -- Get PCI address by following the device symlink
  pciAddr <- getNvmePciAddress ctrlPath

  -- Get bus path from udev for the namespace device (e.g., nvme0n1)
  let nsName = T.pack $ controller ++ "n1"
  busPath <- getBlockDeviceBusPath nsName

  case (model, serial) of
    (Just m, Just s) -> return [NvmeDeviceInfo
      { nvmeDeviceName = T.pack controller
      , nvmeModelNumber = T.strip m
      , nvmeSerialNumber = T.strip s
      , nvmeFirmwareRev = maybe "" T.strip firmware
      , nvmeNamespaceId = Nothing
      , nvmeEui64 = Nothing
      , nvmeNguid = Nothing
      , nvmePciAddress = pciAddr
      , nvmeBusPath = busPath
      }]
    _ -> return []

-- | Get PCI address for an NVMe controller
getNvmePciAddress :: FilePath -> IO (Maybe Text)
getNvmePciAddress ctrlPath = do
  let deviceLink = ctrlPath </> "device"
  exists <- doesFileExist deviceLink
  if not exists
    then return Nothing
    else do
      result <- try $ readSymbolicLink deviceLink
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right target -> do
          -- Extract the PCI address from the symlink target
          -- Target might be something like "../../../0000:03:00.0"
          let pciAddr = T.pack $ takeFileName' target
          -- Verify it looks like a PCI address (DDDD:BB:DD.F format)
          if isPciAddress pciAddr
            then return $ Just pciAddr
            else return Nothing
  where
    takeFileName' = reverse . takeWhile (/= '/') . reverse

    -- PCI address format: DDDD:BB:DD.F (minimum 12 characters)
    isPciAddress addr =
      T.length addr >= 12 &&
      T.index addr 4 == ':' &&
      T.index addr 7 == ':' &&
      T.index addr 10 == '.'

-- | Read a sysfs file safely
readSysfsFile :: FilePath -> IO (Maybe Text)
readSysfsFile path = do
  exists <- doesFileExist path
  if not exists
    then return Nothing
    else do
      result <- try $ TIO.readFile path
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right content -> return $ Just $ T.strip content

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Nvme
  ( getNvmeDevices
  , NvmeDeviceInfo(..)
  ) where

import Data.Text (Text)
import Data.HardwareInfo.Types

data NvmeDeviceInfo = NvmeDeviceInfo
  { nvmeDeviceName     :: !Text
  , nvmeModelNumber    :: !Text
  , nvmeSerialNumber   :: !Text
  , nvmeFirmwareRev    :: !Text
  , nvmeNamespaceId    :: !(Maybe Text)
  , nvmeEui64          :: !(Maybe Text)
  , nvmeNguid          :: !(Maybe Text)
  , nvmePciAddress     :: !(Maybe Text)
  , nvmeBusPath        :: !(Maybe Text)
  } deriving (Show, Eq)

getNvmeDevices :: IO [Component]
getNvmeDevices = return []
#endif
