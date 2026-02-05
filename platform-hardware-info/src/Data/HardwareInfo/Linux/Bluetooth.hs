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
import System.Directory (doesDirectoryExist, listDirectory, doesFileExist)
import System.FilePath ((</>), takeFileName)
import System.Posix.Files (readSymbolicLink)

import Data.HardwareInfo.Types

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

  -- Read device address
  address <- readSysfsFile (devPath </> "address")

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

-- | Get manufacturer info by following device symlinks to PCI device
getBluetoothManufacturer :: FilePath -> IO (Text, Maybe Text)
getBluetoothManufacturer devPath = do
  -- Follow the device symlink to find the parent PCI device
  let deviceLink = devPath </> "device"
  result <- try $ readSymbolicLink deviceLink
  case result of
    Left (_ :: SomeException) -> return ("", Nothing)
    Right target -> do
      -- Walk up the device tree to find PCI device
      findPciParent (resolveRelativePath devPath target)
  where
    findPciParent :: FilePath -> IO (Text, Maybe Text)
    findPciParent path = do
      -- Check if this is a PCI device by looking for vendor file
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
          -- Try parent directory
          let parent = takeDirectory' path
          if parent == path || parent == "/"
            then return ("", Nothing)
            else findPciParent parent

    takeDirectory' :: FilePath -> FilePath
    takeDirectory' p =
      let parts = filter (not . null) $ splitOn '/' p
      in if length parts <= 1
           then "/"
           else "/" ++ foldr1 (\a b -> a ++ "/" ++ b) (init parts)

    splitOn :: Char -> String -> [String]
    splitOn c s = case break (== c) s of
      (a, [])   -> [a]
      (a, _:bs) -> a : splitOn c bs

-- | Resolve a relative path
resolveRelativePath :: FilePath -> FilePath -> FilePath
resolveRelativePath base relPath = go (splitPath base) (splitPath relPath)
  where
    splitPath = filter (not . null) . splitOn '/'
    splitOn c s = case break (== c) s of
      (a, [])   -> [a]
      (a, _:bs) -> a : splitOn c bs

    go baseComps [] = joinPath baseComps
    go [] relComps = joinPath relComps
    go (_:bs) ("..":rs) = go bs rs
    go bs (r:rs) = go (bs ++ [r]) rs

    joinPath [] = "/"
    joinPath ps = "/" ++ foldr1 (\a b -> a ++ "/" ++ b) ps

-- | Lookup Bluetooth vendor name from PCI vendor ID
lookupBluetoothVendor :: Text -> Text
lookupBluetoothVendor vendorId =
  case T.toLower vendorId of
    "0x8086" -> "Intel Corporation"
    "0x8087" -> "Intel Corporation"
    "0x10ec" -> "Realtek Semiconductor Co., Ltd."
    "0x0cf3" -> "Qualcomm Atheros"
    "0x168c" -> "Qualcomm Atheros"
    "0x14e4" -> "Broadcom Inc."
    "0x0a5c" -> "Broadcom Inc."
    "0x13d3" -> "IMC Networks"
    "0x0bda" -> "Realtek Semiconductor Co., Ltd."
    "0x04ca" -> "Lite-On Technology Corp."
    "0x0489" -> "Foxconn / Hon Hai"
    "0x413c" -> "Dell"
    "0x0930" -> "Toshiba Corp."
    _ -> ""

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
                     Just addr -> [BluetoothMAC addr]
                     Nothing -> []
          pciAddr = case btPciAddress d of
                      Just p -> [PCIAddress p]
                      Nothing -> []
      in btAddr ++ pciAddr

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
