{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.Usb
-- Description : Linux USB device enumeration
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to enumerate USB devices on Linux
-- systems using the sysfs interface (/sys/bus/usb/devices/).

#ifdef LINUX
module Data.HardwareInfo.Linux.Usb
  ( -- * USB device enumeration
    getUsbDevices
  , UsbDevice(..)
  , UsbDeviceClass(..)
  ) where

import Control.Exception (try, SomeException)
import Control.Monad (filterM)
import Data.List (isInfixOf)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Directory (doesDirectoryExist, listDirectory, doesFileExist)
import System.FilePath ((</>))
import Data.Char (isDigit)

import Data.HardwareInfo.Types

-- | USB device class codes
data UsbDeviceClass
  = UsbClassPerInterface  -- ^ 0x00: Device class defined per interface
  | UsbClassAudio         -- ^ 0x01: Audio
  | UsbClassComm          -- ^ 0x02: Communications/CDC
  | UsbClassHID           -- ^ 0x03: Human Interface Device
  | UsbClassPhysical      -- ^ 0x05: Physical
  | UsbClassImage         -- ^ 0x06: Image (PTP cameras)
  | UsbClassPrinter       -- ^ 0x07: Printer
  | UsbClassMassStorage   -- ^ 0x08: Mass Storage
  | UsbClassHub           -- ^ 0x09: Hub
  | UsbClassCDCData       -- ^ 0x0A: CDC-Data
  | UsbClassSmartCard     -- ^ 0x0B: Smart Card
  | UsbClassContentSec    -- ^ 0x0D: Content Security
  | UsbClassVideo         -- ^ 0x0E: Video
  | UsbClassHealthcare    -- ^ 0x0F: Personal Healthcare
  | UsbClassAVDevice      -- ^ 0x10: Audio/Video Device
  | UsbClassBillboard     -- ^ 0x11: Billboard
  | UsbClassTypeCBridge   -- ^ 0x12: USB Type-C Bridge
  | UsbClassWireless      -- ^ 0xE0: Wireless Controller
  | UsbClassMisc          -- ^ 0xEF: Miscellaneous
  | UsbClassVendor        -- ^ 0xFF: Vendor Specific
  | UsbClassUnknown       -- ^ Unknown
  deriving (Show, Eq)

-- | USB device information
data UsbDevice = UsbDevice
  { usbBusPort     :: !Text           -- ^ Bus-port address (e.g., "1-2.3")
  , usbVendorId    :: !Text           -- ^ Vendor ID
  , usbProductId   :: !Text           -- ^ Product ID
  , usbManufacturer :: !Text          -- ^ Manufacturer string
  , usbProduct     :: !Text           -- ^ Product string
  , usbSerial      :: !(Maybe Text)   -- ^ Serial number
  , usbDeviceClass :: !UsbDeviceClass -- ^ Device class
  , usbSpeed       :: !(Maybe Text)   -- ^ Speed (e.g., "480")
  , usbVersion     :: !(Maybe Text)   -- ^ USB version
  } deriving (Show, Eq)

-- | Sysfs USB devices path
usbDevicesPath :: FilePath
usbDevicesPath = "/sys/bus/usb/devices"

-- | Get all USB devices (excluding hubs and root hubs)
getUsbDevices :: IO [Component]
getUsbDevices = do
  exists <- doesDirectoryExist usbDevicesPath
  if not exists
    then return []
    else do
      result <- try $ listDirectory usbDevicesPath
      case result of
        Left (_ :: SomeException) -> return []
        Right entries -> do
          -- Filter to actual device entries (bus-port format, not interfaces)
          let devicePaths = filter isDevicePath entries
          devices <- mapM readUsbDevice devicePaths
          -- Filter out hubs and convert to components
          let realDevices = filter (not . isHub) [d | Just d <- devices]
          return $ map toComponent realDevices

-- | Check if path is a USB device (not interface or root hub)
isDevicePath :: String -> Bool
isDevicePath s =
  -- Device paths are like "1-2", "1-2.3", "2-1.4.2"
  -- Interface paths are like "1-2:1.0"
  -- Root hubs are like "usb1", "usb2"
  not (':' `elem` s) &&
  not ("usb" `isInfixOf` s) &&
  any isDigit s &&
  '-' `elem` s

-- | Check if device is a hub
isHub :: UsbDevice -> Bool
isHub dev = usbDeviceClass dev == UsbClassHub

-- | Read USB device information from sysfs
readUsbDevice :: String -> IO (Maybe UsbDevice)
readUsbDevice busPort = do
  let devPath = usbDevicesPath </> busPort

  -- Check if device directory exists
  exists <- doesDirectoryExist devPath
  if not exists
    then return Nothing
    else do
      -- Read vendor and product IDs
      vendorId <- readSysfsFile (devPath </> "idVendor")
      productId <- readSysfsFile (devPath </> "idProduct")

      case (vendorId, productId) of
        (Just vid, Just pid) -> do
          -- Read other attributes
          manufacturer <- readSysfsFile (devPath </> "manufacturer")
          product <- readSysfsFile (devPath </> "product")
          serial <- readSysfsFile (devPath </> "serial")
          devClass <- readSysfsFile (devPath </> "bDeviceClass")
          speed <- readSysfsFile (devPath </> "speed")
          version <- readSysfsFile (devPath </> "version")

          let mfr = case manufacturer of
                      Just m -> m
                      Nothing -> lookupUsbVendor vid
          let prod = case product of
                       Just p -> p
                       Nothing -> T.pack busPort

          return $ Just UsbDevice
            { usbBusPort = T.pack busPort
            , usbVendorId = vid
            , usbProductId = pid
            , usbManufacturer = mfr
            , usbProduct = prod
            , usbSerial = serial
            , usbDeviceClass = parseDeviceClass devClass
            , usbSpeed = speed
            , usbVersion = version
            }
        _ -> return Nothing

-- | Parse device class from hex string
parseDeviceClass :: Maybe Text -> UsbDeviceClass
parseDeviceClass Nothing = UsbClassUnknown
parseDeviceClass (Just s) =
  case T.toLower s of
    "00" -> UsbClassPerInterface
    "01" -> UsbClassAudio
    "02" -> UsbClassComm
    "03" -> UsbClassHID
    "05" -> UsbClassPhysical
    "06" -> UsbClassImage
    "07" -> UsbClassPrinter
    "08" -> UsbClassMassStorage
    "09" -> UsbClassHub
    "0a" -> UsbClassCDCData
    "0b" -> UsbClassSmartCard
    "0d" -> UsbClassContentSec
    "0e" -> UsbClassVideo
    "0f" -> UsbClassHealthcare
    "10" -> UsbClassAVDevice
    "11" -> UsbClassBillboard
    "12" -> UsbClassTypeCBridge
    "e0" -> UsbClassWireless
    "ef" -> UsbClassMisc
    "ff" -> UsbClassVendor
    _    -> UsbClassUnknown

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

-- | Convert UsbDevice to Component
toComponent :: UsbDevice -> Component
toComponent dev = Component
  { componentClass = usbClassToComponentClass (usbDeviceClass dev)
  , componentManufacturer = usbManufacturer dev
  , componentModel = usbProduct dev
  , componentSerial = usbSerial dev
  , componentRevision = usbVersion dev
  , componentFieldReplaceable = Just True
  , componentAddresses = [USBAddress $ usbBusPort dev]
  }

-- | Convert USB device class to TCG component class
usbClassToComponentClass :: UsbDeviceClass -> ComponentClass
usbClassToComponentClass cls = case cls of
  UsbClassAudio       -> ClassAudioController
  UsbClassHID         -> ClassGeneralInput
  UsbClassImage       -> ClassGenericComponent  -- Camera/Scanner
  UsbClassPrinter     -> ClassGenericComponent  -- Printer
  UsbClassMassStorage -> ClassGeneralStorage    -- USB storage
  UsbClassVideo       -> ClassVideoController   -- USB camera
  UsbClassWireless    -> ClassGeneralNetworkAdapter  -- Wireless adapter
  UsbClassComm        -> ClassGeneralNetworkAdapter  -- CDC (modems, etc.)
  _                   -> ClassGenericComponent

-- | Lookup USB vendor name from vendor ID
lookupUsbVendor :: Text -> Text
lookupUsbVendor vid =
  case T.toLower vid of
    "0781" -> "SanDisk Corp."
    "0951" -> "Kingston Technology"
    "090c" -> "Silicon Motion"
    "13fe" -> "Kingston Technology"
    "058f" -> "Alcor Micro Corp."
    "1005" -> "Apacer Technology"
    "0930" -> "Toshiba Corp."
    "0bda" -> "Realtek Semiconductor"
    "8087" -> "Intel Corp."
    "1d6b" -> "Linux Foundation"
    "046d" -> "Logitech"
    "045e" -> "Microsoft Corp."
    "413c" -> "Dell"
    "17ef" -> "Lenovo"
    "05ac" -> "Apple Inc."
    "04f2" -> "Chicony Electronics"
    "1bcf" -> "Sunplus Innovation"
    "0c45" -> "Microdia"
    "5986" -> "Acer Inc."
    "04e8" -> "Samsung Electronics"
    "2109" -> "VIA Labs"
    "0424" -> "Microchip Technology"
    "05e3" -> "Genesys Logic"
    "1a40" -> "Terminus Technology"
    "0cf3" -> "Qualcomm Atheros"
    "0489" -> "Foxconn / Hon Hai"
    "13d3" -> "IMC Networks"
    "1058" -> "Western Digital"
    "0480" -> "Toshiba America"
    "174c" -> "ASMedia Technology"
    "152d" -> "JMicron Technology"
    "0bc2" -> "Seagate"
    _      -> ""

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Usb
  ( getUsbDevices
  , UsbDevice(..)
  , UsbDeviceClass(..)
  ) where

import Data.Text (Text)
import Data.HardwareInfo.Types

data UsbDeviceClass = UsbClassUnknown deriving (Show, Eq)

data UsbDevice = UsbDevice
  { usbBusPort     :: !Text
  , usbVendorId    :: !Text
  , usbProductId   :: !Text
  , usbManufacturer :: !Text
  , usbProduct     :: !Text
  , usbSerial      :: !(Maybe Text)
  , usbDeviceClass :: !UsbDeviceClass
  , usbSpeed       :: !(Maybe Text)
  , usbVersion     :: !(Maybe Text)
  } deriving (Show, Eq)

getUsbDevices :: IO [Component]
getUsbDevices = return []
#endif
