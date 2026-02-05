{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.Firmware
-- Description : Linux firmware information collection
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to collect firmware component
-- information on Linux systems using sysfs and DMI tables.

#ifdef LINUX
module Data.HardwareInfo.Linux.Firmware
  ( -- * Firmware detection
    getFirmwareComponents
  , getBootloaderInfo
  , getUefiFirmwareInfo
  ) where

import Control.Exception (try, SomeException)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Directory (doesFileExist, doesDirectoryExist, listDirectory)
import System.FilePath ((</>))

import Data.HardwareInfo.Types

-- | Get all firmware components
getFirmwareComponents :: IO [Component]
getFirmwareComponents = do
  -- Get UEFI firmware info
  uefiFw <- getUefiFirmwareInfo
  -- Get bootloader info
  bootloader <- getBootloaderInfo
  return $ uefiFw ++ bootloader

-- | Get UEFI firmware information from EFI variables
getUefiFirmwareInfo :: IO [Component]
getUefiFirmwareInfo = do
  -- Check if system is UEFI-based
  efiExists <- doesDirectoryExist "/sys/firmware/efi"
  if not efiExists
    then return []  -- Legacy BIOS system, no UEFI firmware
    else do
      -- Try to read EFI firmware vendor info
      fwVendor <- readEfiVar "fw_vendor"
      fwVersion <- readEfiVar "fw_platform_size"

      -- Get UEFI capsule info if available
      capsules <- getUefiCapsules

      let uefiFw = if T.null (fromMaybe' "" fwVendor)
                     then []
                     else [Component
                       { componentClass = ClassSystemFirmware
                       , componentManufacturer = fromMaybe' "UEFI" fwVendor
                       , componentModel = "UEFI Firmware"
                       , componentSerial = Nothing
                       , componentRevision = fwVersion
                       , componentFieldReplaceable = Just False
                       , componentAddresses = []
                       }]
      return $ uefiFw ++ capsules

-- | Read EFI variable
readEfiVar :: Text -> IO (Maybe Text)
readEfiVar varName = do
  let path = "/sys/firmware/efi" </> T.unpack varName
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

-- | Get UEFI capsule information (firmware update modules)
getUefiCapsules :: IO [Component]
getUefiCapsules = do
  let capsulePath = "/sys/firmware/efi/esrt/entries"
  exists <- doesDirectoryExist capsulePath
  if not exists
    then return []
    else do
      result <- try $ listDirectory capsulePath
      case result of
        Left (_ :: SomeException) -> return []
        Right entries -> do
          components <- mapM (readCapsuleEntry capsulePath) entries
          return $ concat components

-- | Read individual UEFI capsule entry
readCapsuleEntry :: FilePath -> String -> IO [Component]
readCapsuleEntry basePath entryName = do
  let entryPath = basePath </> entryName
  fwClass <- readSysfsText (entryPath </> "fw_class")
  fwType <- readSysfsText (entryPath </> "fw_type")
  fwVersion <- readSysfsText (entryPath </> "fw_version")
  lastAttemptVersion <- readSysfsText (entryPath </> "last_attempt_version")

  case fwClass of
    Nothing -> return []
    Just cls -> return [Component
      { componentClass = case fwType of
          Just "1" -> ClassSystemFirmware
          Just "2" -> ClassDriveFirmware
          _        -> ClassGeneralFirmware
      , componentManufacturer = "UEFI"
      , componentModel = "Firmware Capsule " <> cls
      , componentSerial = Nothing
      , componentRevision = fwVersion
      , componentFieldReplaceable = Just True
      , componentAddresses = []
      }]

-- | Get bootloader information
getBootloaderInfo :: IO [Component]
getBootloaderInfo = do
  -- Try to detect GRUB
  grubInfo <- getGrubInfo
  -- Try to detect systemd-boot
  sdBootInfo <- getSystemdBootInfo
  return $ grubInfo ++ sdBootInfo

-- | Get GRUB bootloader information
getGrubInfo :: IO [Component]
getGrubInfo = do
  -- Check common GRUB installation markers
  grubCfgExists <- doesFileExist "/boot/grub/grub.cfg"
  grub2CfgExists <- doesFileExist "/boot/grub2/grub.cfg"
  efiGrubExists <- doesFileExist "/boot/efi/EFI/grub/grub.cfg"

  if not (grubCfgExists || grub2CfgExists || efiGrubExists)
    then return []
    else do
      -- Try to get GRUB version from /boot/grub/grubenv or similar
      grubVersion <- getGrubVersion
      return [Component
        { componentClass = ClassBootloader
        , componentManufacturer = "GNU"
        , componentModel = "GRUB"
        , componentSerial = Nothing
        , componentRevision = grubVersion
        , componentFieldReplaceable = Just True
        , componentAddresses = []
        }]

-- | Try to get GRUB version
getGrubVersion :: IO (Maybe Text)
getGrubVersion = do
  -- Check grubenv for saved_entry or similar
  let paths = ["/boot/grub/grubenv", "/boot/grub2/grubenv"]
  checkPaths paths
  where
    checkPaths [] = return Nothing
    checkPaths (p:ps) = do
      exists <- doesFileExist p
      if exists
        then return $ Just "2.x"  -- If grubenv exists, it's GRUB 2
        else checkPaths ps

-- | Get systemd-boot information
getSystemdBootInfo :: IO [Component]
getSystemdBootInfo = do
  -- Check for systemd-boot
  let sdBootPaths = ["/boot/efi/EFI/systemd/systemd-bootx64.efi",
                     "/boot/EFI/systemd/systemd-bootx64.efi",
                     "/efi/EFI/systemd/systemd-bootx64.efi"]
  exists <- anyM doesFileExist sdBootPaths
  if not exists
    then return []
    else return [Component
      { componentClass = ClassBootloader
      , componentManufacturer = "systemd"
      , componentModel = "systemd-boot"
      , componentSerial = Nothing
      , componentRevision = Nothing
      , componentFieldReplaceable = Just True
      , componentAddresses = []
      }]

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

-- | Helper: fromMaybe for Text
fromMaybe' :: Text -> Maybe Text -> Text
fromMaybe' def Nothing = def
fromMaybe' _ (Just x) = x

-- | Helper: anyM for IO Bool
anyM :: (a -> IO Bool) -> [a] -> IO Bool
anyM _ [] = return False
anyM f (x:xs) = do
  result <- f x
  if result then return True else anyM f xs

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Firmware
  ( getFirmwareComponents
  , getBootloaderInfo
  , getUefiFirmwareInfo
  ) where

import Data.HardwareInfo.Types

getFirmwareComponents :: IO [Component]
getFirmwareComponents = return []

getBootloaderInfo :: IO [Component]
getBootloaderInfo = return []

getUefiFirmwareInfo :: IO [Component]
getUefiFirmwareInfo = return []
#endif
