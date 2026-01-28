{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.Block
-- Description : Linux block device enumeration (SATA, SAS, etc.)
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to enumerate block storage devices on Linux
-- systems using the sysfs interface (/sys/class/block/).

#ifdef LINUX
module Data.HardwareInfo.Linux.Block
  ( -- * Block device enumeration
    getBlockDevices
  , BlockDevice(..)
  , BlockTransport(..)
    -- * Filtering functions
  , getSataDevices
  , getScsiDevices
  , getAllStorageDevices
  ) where

import Control.Exception (try, SomeException)
import Control.Monad (forM, filterM)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Data.Word (Word64)
import System.Directory (listDirectory, doesFileExist, doesDirectoryExist)
import System.FilePath ((</>), takeFileName)
import Text.Read (readMaybe)

import Data.HardwareInfo.Types

-- | Block device information
data BlockDevice = BlockDevice
  { blockName       :: !Text           -- ^ Device name (e.g., "sda", "nvme0n1")
  , blockModel      :: !Text           -- ^ Model name
  , blockVendor     :: !Text           -- ^ Vendor name
  , blockSerial     :: !(Maybe Text)   -- ^ Serial number
  , blockRevision   :: !(Maybe Text)   -- ^ Firmware revision
  , blockSize       :: !Word64         -- ^ Size in bytes
  , blockTransport  :: !BlockTransport -- ^ Transport type
  , blockRotational :: !Bool           -- ^ True if rotational (HDD)
  } deriving (Show, Eq)

-- | Block device transport type
data BlockTransport
  = TransportSATA      -- ^ SATA
  | TransportSAS       -- ^ SAS
  | TransportSCSI      -- ^ SCSI
  | TransportUSB       -- ^ USB
  | TransportNVMe      -- ^ NVMe (handled separately)
  | TransportMMC       -- ^ MMC/SD card
  | TransportVirtual   -- ^ Virtual device
  | TransportUnknown   -- ^ Unknown
  deriving (Show, Eq)

-- | Sysfs block devices path
blockDevicesPath :: FilePath
blockDevicesPath = "/sys/class/block"

-- | Get all block devices (excluding partitions)
getBlockDevices :: IO [BlockDevice]
getBlockDevices = do
  result <- try $ listDirectory blockDevicesPath
  case result of
    Left (_ :: SomeException) -> return []
    Right names -> do
      -- Filter out partitions (those with digits in name like sda1)
      let diskNames = filter isDiskDevice names
      devices <- forM diskNames $ \name -> do
        let devPath = blockDevicesPath </> name
        mDev <- readBlockDevice (T.pack name) devPath
        return mDev
      return [d | Just d <- devices]
  where
    -- Filter out partitions and virtual devices like loop, ram
    isDiskDevice name =
      not (any (`T.isPrefixOf` T.pack name) ["loop", "ram", "dm-", "md"]) &&
      not (hasTrailingDigit name && hasDiskPrefix name)

    hasTrailingDigit s = not (null s) && last s `elem` ['0'..'9'] &&
                         any (`T.isPrefixOf` T.pack s) ["sd", "hd", "vd", "xvd"]

    hasDiskPrefix s = any (`T.isPrefixOf` T.pack s) ["sd", "hd", "vd", "xvd", "nvme"]

-- | Read block device information from sysfs
readBlockDevice :: Text -> FilePath -> IO (Maybe BlockDevice)
readBlockDevice name devPath = do
  -- Check if this is a real disk (has a device subdirectory)
  let devicePath = devPath </> "device"
  hasDevice <- doesDirectoryExist devicePath

  if not hasDevice
    then return Nothing
    else do
      -- Read device attributes
      model <- readSysfsText (devicePath </> "model")
      vendor <- readSysfsText (devicePath </> "vendor")
      rev <- readSysfsText (devicePath </> "rev")

      -- Try to get serial from different locations
      serial <- getSerial devicePath

      -- Get size
      sizeStr <- readSysfsText (devPath </> "size")
      let size = case sizeStr of
                   Just s -> maybe 0 (* 512) (readMaybe (T.unpack s) :: Maybe Word64)
                   Nothing -> 0

      -- Check if rotational
      rotStr <- readSysfsText (devPath </> "queue" </> "rotational")
      let rotational = case rotStr of
                         Just "1" -> True
                         _ -> False

      -- Determine transport type
      transport <- detectTransport devicePath name

      -- Skip if no useful info
      if T.null (maybe "" id model) && T.null (maybe "" id vendor)
        then return Nothing
        else return $ Just BlockDevice
          { blockName = name
          , blockModel = maybe "" T.strip model
          , blockVendor = maybe "" T.strip vendor
          , blockSerial = fmap T.strip serial
          , blockRevision = fmap T.strip rev
          , blockSize = size
          , blockTransport = transport
          , blockRotational = rotational
          }

-- | Get serial number from various locations
getSerial :: FilePath -> IO (Maybe Text)
getSerial devicePath = do
  -- Try different locations
  s1 <- readSysfsText (devicePath </> "serial")
  case s1 of
    Just s -> return $ Just s
    Nothing -> do
      s2 <- readSysfsText (devicePath </> "vpd_pg80")
      case s2 of
        Just s -> return $ Just s
        Nothing -> readSysfsText (devicePath </> "wwid")

-- | Detect transport type
detectTransport :: FilePath -> Text -> IO BlockTransport
detectTransport devicePath name
  | "nvme" `T.isPrefixOf` name = return TransportNVMe
  | "mmcblk" `T.isPrefixOf` name = return TransportMMC
  | "vd" `T.isPrefixOf` name = return TransportVirtual
  | otherwise = do
      -- Check for SATA/SAS by looking at the device tree
      -- SATA devices usually have ata* in their path
      -- SAS devices usually have sas* in their path
      transport <- readSysfsText (devicePath </> "transport")
      case transport of
        Just t | "sata" `T.isInfixOf` T.toLower t -> return TransportSATA
               | "sas" `T.isInfixOf` T.toLower t -> return TransportSAS
               | "usb" `T.isInfixOf` T.toLower t -> return TransportUSB
        _ -> do
          -- Check by looking at symlink target
          subsystem <- readSysfsText (devicePath </> "subsystem")
          case subsystem of
            Just s | "usb" `T.isInfixOf` T.toLower s -> return TransportUSB
            _ -> return TransportSATA  -- Default to SATA for sd* devices

-- | Read text from sysfs file
readSysfsText :: FilePath -> IO (Maybe Text)
readSysfsText path = do
  exists <- doesFileExist path
  if not exists
    then return Nothing
    else do
      result <- try $ TIO.readFile path
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right content ->
          let stripped = T.strip content
          in if T.null stripped then return Nothing else return $ Just stripped

-- | Get SATA devices
getSataDevices :: IO [Component]
getSataDevices = do
  devices <- getBlockDevices
  let sata = filter (\d -> blockTransport d == TransportSATA) devices
  return $ map (blockToComponent ClassSSD) sata

-- | Get SCSI/SAS devices
getScsiDevices :: IO [Component]
getScsiDevices = do
  devices <- getBlockDevices
  let sas = filter (\d -> blockTransport d `elem` [TransportSAS, TransportSCSI]) devices
  return $ map (blockToComponent ClassStorageDrive) sas

-- | Get all storage devices (excluding NVMe, which is handled separately)
getAllStorageDevices :: IO [Component]
getAllStorageDevices = do
  devices <- getBlockDevices
  -- Exclude NVMe (handled by Nvme module) and virtual devices
  let storage = filter (\d -> blockTransport d `notElem` [TransportNVMe, TransportVirtual]) devices
  return $ map toComponent storage
  where
    toComponent dev =
      let cls = case (blockTransport dev, blockRotational dev) of
                  (TransportSATA, True)  -> ClassHDD
                  (TransportSATA, False) -> ClassSSD
                  (TransportSAS, True)   -> ClassHDD
                  (TransportSAS, False)  -> ClassSSD
                  (TransportUSB, _)      -> ClassStorageDrive
                  (TransportMMC, _)      -> ClassStorageDrive
                  _                      -> ClassStorageDrive
      in blockToComponent cls dev

-- | Convert BlockDevice to Component
blockToComponent :: ComponentClass -> BlockDevice -> Component
blockToComponent cls dev = Component
  { componentClass = cls
  , componentManufacturer = blockVendor dev
  , componentModel = if T.null (blockModel dev)
                       then blockName dev
                       else blockModel dev
  , componentSerial = blockSerial dev
  , componentRevision = blockRevision dev
  , componentFieldReplaceable = Just True
  , componentAddresses = []
  }

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Block
  ( getBlockDevices
  , getSataDevices
  , getScsiDevices
  , getAllStorageDevices
  , BlockDevice(..)
  , BlockTransport(..)
  ) where

import Data.Text (Text)
import Data.Word (Word64)
import Data.HardwareInfo.Types

data BlockDevice = BlockDevice
  { blockName       :: !Text
  , blockModel      :: !Text
  , blockVendor     :: !Text
  , blockSerial     :: !(Maybe Text)
  , blockRevision   :: !(Maybe Text)
  , blockSize       :: !Word64
  , blockTransport  :: !BlockTransport
  , blockRotational :: !Bool
  } deriving (Show, Eq)

data BlockTransport = TransportUnknown deriving (Show, Eq)

getBlockDevices :: IO [BlockDevice]
getBlockDevices = return []

getSataDevices :: IO [Component]
getSataDevices = return []

getScsiDevices :: IO [Component]
getScsiDevices = return []

getAllStorageDevices :: IO [Component]
getAllStorageDevices = return []
#endif
