{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.Bluetooth
-- Description : Linux Bluetooth device enumeration
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to enumerate Bluetooth adapters on Linux
-- systems using the sysfs interface (/sys/class/bluetooth/).

#ifdef LINUX
module Data.HardwareInfo.Linux.Bluetooth
  ( -- * Bluetooth device enumeration
    getBluetoothDevices
  , BluetoothDevice(..)
  ) where

import Control.Exception (try, SomeException)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Directory (doesDirectoryExist, listDirectory, doesFileExist, canonicalizePath)
import System.FilePath ((</>), takeFileName, takeDirectory)

import Data.HardwareInfo.Types
import Data.HardwareInfo.Linux.PciIds (lookupVendorByIdText)

-- | Bluetooth device information
data BluetoothDevice = BluetoothDevice
  { btName       :: !Text           -- ^ Device name (e.g., "hci0")
  , btAddress    :: !(Maybe Text)   -- ^ Bluetooth MAC address
  , btManufacturer :: !Text         -- ^ Manufacturer name
  , btType       :: !(Maybe Text)   -- ^ Device type
  , btPciAddress :: !(Maybe Text)   -- ^ PCI address if applicable
  } deriving (Show, Eq)

-- | Sysfs bluetooth path
bluetoothPath :: FilePath
bluetoothPath = "/sys/class/bluetooth"

-- | Get all Bluetooth devices
getBluetoothDevices :: IO [Component]
getBluetoothDevices = do
  exists <- doesDirectoryExist bluetoothPath
  if not exists
    then return []
    else do
      result <- try $ listDirectory bluetoothPath
      case result of
        Left (_ :: SomeException) -> return []
        Right devices -> do
          btDevices <- mapM readBluetoothDevice devices
          return $ map toComponent [d | Just d <- btDevices]

-- | Read Bluetooth device information from sysfs
readBluetoothDevice :: String -> IO (Maybe BluetoothDevice)
readBluetoothDevice deviceName = do
  let devPath = bluetoothPath </> deviceName

  -- Read device address (try sysfs first, then debugfs as fallback)
  address <- readBluetoothAddress deviceName devPath

  -- Get manufacturer from PCI device info
  (manufacturer, pciAddr) <- getBluetoothManufacturer devPath

  -- Read device type
  devType <- readSysfsFile (devPath </> "type")

  return $ Just BluetoothDevice
    { btName = T.pack deviceName
    , btAddress = address
    , btManufacturer = manufacturer
    , btType = devType
    , btPciAddress = pciAddr
    }

-- | Read Bluetooth MAC address
-- Tries sysfs 'address' file first, falls back to debugfs identity (requires root)
readBluetoothAddress :: String -> FilePath -> IO (Maybe Text)
readBluetoothAddress deviceName devPath = do
  -- Try sysfs first
  sysfsAddr <- readSysfsFile (devPath </> "address")
  case sysfsAddr of
    Just addr | isValidBtAddress addr -> return (Just addr)
    _ -> do
      -- Fall back to debugfs (requires root)
      let debugPath = "/sys/kernel/debug/bluetooth" </> deviceName </> "identity"
      debugAddr <- readSysfsFile debugPath
      case debugAddr of
        Just raw ->
          -- Format: "14:14:16:03:8e:73 (type 0) ..."
          let addr = T.strip $ head' $ T.splitOn " " raw
          in if isValidBtAddress addr then return (Just addr) else return Nothing
        Nothing -> return Nothing
  where
    head' (x:_) = x
    head' []    = ""
    isValidBtAddress addr =
      T.length addr == 17 &&
      addr /= "00:00:00:00:00:00"

-- | Get manufacturer info by following device symlinks to PCI or USB device
getBluetoothManufacturer :: FilePath -> IO (Text, Maybe Text)
getBluetoothManufacturer devPath = do
  -- Resolve the real path of the device symlink
  let deviceLink = devPath </> "device"
  linkExists <- doesDirectoryExist deviceLink
  if not linkExists
    then return ("", Nothing)
    else do
      realPath <- try $ canonicalizePath deviceLink
      case realPath of
        Left (_ :: SomeException) -> return ("", Nothing)
        Right resolved -> do
          -- First try USB parent (common for BT adapters)
          usbResult <- tryUsbParent resolved
          case usbResult of
            (mfr, _) | not (T.null mfr) -> return usbResult
            -- Fall back to PCI parent
            _ -> findPciParent resolved
  where
    -- | Try to get manufacturer from USB parent device
    -- USB interfaces (e.g., .../5-1:1.0) have parent USB device (e.g., .../5-1)
    tryUsbParent :: FilePath -> IO (Text, Maybe Text)
    tryUsbParent path = do
      let parentPath = takeDirectory path
      mfr <- readSysfsFile (parentPath </> "manufacturer")
      case mfr of
        Just m -> do
          addr <- readSysfsFile (parentPath </> "serial")
          -- Filter out obviously invalid serials (all zeros)
          let validAddr = case addr of
                Just a | T.all (\c -> c == '0') a -> Nothing
                other -> other
          return (m, validAddr)
        Nothing -> return ("", Nothing)

    findPciParent :: FilePath -> IO (Text, Maybe Text)
    findPciParent path = do
      let vendorPath = path </> "vendor"
      hasVendor <- doesFileExist vendorPath
      if hasVendor
        then do
          vendor <- readSysfsFile vendorPath
          let pciAddr = T.pack $ takeFileName path
          let vendorName = case vendor of
                Just v -> lookupBluetoothVendor v
                Nothing -> ""
          return (vendorName, Just pciAddr)
        else do
          let parent = takeDirectory path
          if parent == path || parent == "/"
            then return ("", Nothing)
            else findPciParent parent

-- | Lookup Bluetooth vendor name from PCI vendor ID
-- Uses the pci.ids database (embedded + runtime fallback)
lookupBluetoothVendor :: Text -> Text
lookupBluetoothVendor = lookupVendorByIdText

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
        Right content ->
          let stripped = T.strip content
          in if T.null stripped then return Nothing else return $ Just stripped

-- | Convert BluetoothDevice to Component
toComponent :: BluetoothDevice -> Component
toComponent dev = Component
  { componentClass = ClassBluetoothAdapter
  , componentManufacturer = btManufacturer dev
  , componentModel = btName dev
  , componentSerial = btAddress dev  -- Use BT address as serial
  , componentRevision = Nothing
  , componentFieldReplaceable = Just False  -- Usually integrated
  , componentAddresses = buildAddresses dev
  }
  where
    buildAddresses :: BluetoothDevice -> [ComponentAddress]
    buildAddresses d =
      let btAddr = case btAddress d of
                     Just addr -> [BluetoothMAC (T.toUpper addr)]
                     Nothing -> []
      in btAddr

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Bluetooth
  ( getBluetoothDevices
  , BluetoothDevice(..)
  ) where

import Data.Text (Text)
import Data.HardwareInfo.Types

data BluetoothDevice = BluetoothDevice
  { btName       :: !Text
  , btAddress    :: !(Maybe Text)
  , btManufacturer :: !Text
  , btType       :: !(Maybe Text)
  , btPciAddress :: !(Maybe Text)
  } deriving (Show, Eq)

getBluetoothDevices :: IO [Component]
getBluetoothDevices = return []
#endif
