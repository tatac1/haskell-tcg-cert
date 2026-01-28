{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.Pci
-- Description : Linux PCI device enumeration
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to enumerate PCI devices on Linux
-- systems using the sysfs interface (/sys/bus/pci/devices/).

#ifdef LINUX
module Data.HardwareInfo.Linux.Pci
  ( -- * PCI device enumeration
    getPciDevices
  , PciDevice(..)
  , PciClass(..)
    -- * Filtering functions
  , getGpuDevices
  , getStorageControllers
  , getNetworkControllers
  , getUsbControllers
  ) where

import Control.Exception (try, SomeException)
import Control.Monad (forM, filterM)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Data.Word (Word16)
import System.Directory (listDirectory, doesFileExist)
import System.FilePath ((</>))
import Text.Read (readMaybe)
import Numeric (readHex)

import Data.HardwareInfo.Types

-- | PCI device information
data PciDevice = PciDevice
  { pciSlot       :: !Text        -- ^ PCI slot (e.g., "0000:00:02.0")
  , pciVendorId   :: !Word16      -- ^ Vendor ID
  , pciDeviceId   :: !Word16      -- ^ Device ID
  , pciClassCode  :: !Word16      -- ^ Class code (high 16 bits)
  , pciVendorName :: !Text        -- ^ Vendor name (if available)
  , pciDeviceName :: !Text        -- ^ Device name (if available)
  , pciSubsystem  :: !(Maybe Text) -- ^ Subsystem info
  , pciRevision   :: !(Maybe Text) -- ^ Revision
  } deriving (Show, Eq)

-- | PCI class codes (high byte)
data PciClass
  = PciClassUnknown
  | PciClassStorage        -- ^ 0x01: Mass Storage Controller
  | PciClassNetwork        -- ^ 0x02: Network Controller
  | PciClassDisplay        -- ^ 0x03: Display Controller
  | PciClassMultimedia     -- ^ 0x04: Multimedia Controller
  | PciClassMemory         -- ^ 0x05: Memory Controller
  | PciClassBridge         -- ^ 0x06: Bridge
  | PciClassCommunication  -- ^ 0x07: Simple Communication Controller
  | PciClassSystem         -- ^ 0x08: Base System Peripheral
  | PciClassInput          -- ^ 0x09: Input Device Controller
  | PciClassDocking        -- ^ 0x0A: Docking Station
  | PciClassProcessor      -- ^ 0x0B: Processor
  | PciClassSerial         -- ^ 0x0C: Serial Bus Controller (USB, etc.)
  | PciClassWireless       -- ^ 0x0D: Wireless Controller
  | PciClassIntelligentIO  -- ^ 0x0E: Intelligent Controller
  | PciClassSatellite      -- ^ 0x0F: Satellite Communication
  | PciClassEncryption     -- ^ 0x10: Encryption Controller
  | PciClassSignal         -- ^ 0x11: Signal Processing Controller
  | PciClassAccelerator    -- ^ 0x12: Processing Accelerator
  | PciClassOther          -- ^ 0xFF: Other
  deriving (Show, Eq)

-- | Sysfs PCI devices path
pciDevicesPath :: FilePath
pciDevicesPath = "/sys/bus/pci/devices"

-- | Get all PCI devices
getPciDevices :: IO [PciDevice]
getPciDevices = do
  result <- try $ listDirectory pciDevicesPath
  case result of
    Left (_ :: SomeException) -> return []
    Right slots -> do
      devices <- forM slots $ \slot -> do
        let slotPath = pciDevicesPath </> slot
        mDev <- readPciDevice (T.pack slot) slotPath
        return mDev
      return [d | Just d <- devices]

-- | Read PCI device information from sysfs
readPciDevice :: Text -> FilePath -> IO (Maybe PciDevice)
readPciDevice slot slotPath = do
  vendorResult <- readSysfsHex (slotPath </> "vendor")
  deviceResult <- readSysfsHex (slotPath </> "device")
  classResult <- readSysfsHex (slotPath </> "class")

  case (vendorResult, deviceResult, classResult) of
    (Just vendor, Just device, Just classCode) -> do
      -- Try to read additional info
      revision <- readSysfsText (slotPath </> "revision")
      subsystemVendor <- readSysfsHex (slotPath </> "subsystem_vendor")
      subsystemDevice <- readSysfsHex (slotPath </> "subsystem_device")

      let subsys = case (subsystemVendor, subsystemDevice) of
                     (Just sv, Just sd) -> Just $ T.pack $
                       formatHex sv ++ ":" ++ formatHex sd
                     _ -> Nothing

      return $ Just PciDevice
        { pciSlot = slot
        , pciVendorId = vendor
        , pciDeviceId = device
        , pciClassCode = fromIntegral (classCode `div` 0x100)  -- High 16 bits
        , pciVendorName = lookupVendorName vendor
        , pciDeviceName = ""  -- Would need pci.ids database
        , pciSubsystem = subsys
        , pciRevision = revision
        }
    _ -> return Nothing

-- | Read hex value from sysfs file
readSysfsHex :: FilePath -> IO (Maybe Word16)
readSysfsHex path = do
  exists <- doesFileExist path
  if not exists
    then return Nothing
    else do
      result <- try $ TIO.readFile path
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right content ->
          let stripped = T.strip content
              -- Remove "0x" prefix if present
              hexStr = if "0x" `T.isPrefixOf` stripped
                         then T.drop 2 stripped
                         else stripped
          in return $ parseHex (T.unpack hexStr)

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

-- | Parse hex string
parseHex :: String -> Maybe Word16
parseHex s = case readHex s of
  [(v, "")] -> Just (fromIntegral (v :: Integer))
  _ -> Nothing

-- | Format as hex
formatHex :: Word16 -> String
formatHex v = let s = showHex' v ""
              in replicate (4 - length s) '0' ++ s
  where
    showHex' 0 acc = if null acc then "0" else acc
    showHex' n acc = showHex' (n `div` 16) (hexDigit (n `mod` 16) : acc)
    hexDigit d = "0123456789abcdef" !! fromIntegral d

-- | Get PCI class from class code
getPciClass :: Word16 -> PciClass
getPciClass code = case code `div` 0x100 of
  0x01 -> PciClassStorage
  0x02 -> PciClassNetwork
  0x03 -> PciClassDisplay
  0x04 -> PciClassMultimedia
  0x05 -> PciClassMemory
  0x06 -> PciClassBridge
  0x07 -> PciClassCommunication
  0x08 -> PciClassSystem
  0x09 -> PciClassInput
  0x0A -> PciClassDocking
  0x0B -> PciClassProcessor
  0x0C -> PciClassSerial
  0x0D -> PciClassWireless
  0x0E -> PciClassIntelligentIO
  0x0F -> PciClassSatellite
  0x10 -> PciClassEncryption
  0x11 -> PciClassSignal
  0x12 -> PciClassAccelerator
  0xFF -> PciClassOther
  _    -> PciClassUnknown

-- | Get GPU devices (Display Controllers)
getGpuDevices :: IO [Component]
getGpuDevices = do
  devices <- getPciDevices
  let gpus = filter isGpu devices
  return $ map gpuToComponent gpus
  where
    isGpu dev = getPciClass (pciClassCode dev) == PciClassDisplay

    gpuToComponent dev = Component
      { componentClass = ClassGPU
      , componentManufacturer = pciVendorName dev
      , componentModel = T.pack $ "GPU [" ++ formatHex (pciVendorId dev) ++ ":"
                                  ++ formatHex (pciDeviceId dev) ++ "]"
      , componentSerial = Nothing
      , componentRevision = pciRevision dev
      , componentFieldReplaceable = Just True
      , componentAddresses = []
      }

-- | Get storage controllers (SATA, SAS, RAID, etc.)
getStorageControllers :: IO [Component]
getStorageControllers = do
  devices <- getPciDevices
  let storage = filter isStorage devices
  return $ map storageToComponent storage
  where
    isStorage dev = getPciClass (pciClassCode dev) == PciClassStorage

    storageToComponent dev =
      let subclass = (pciClassCode dev) `mod` 0x100
          cls = case subclass of
                  0x01 -> ClassSCSIController   -- SCSI
                  0x04 -> ClassRAIDController   -- RAID
                  0x05 -> ClassSATAController   -- ATA (legacy)
                  0x06 -> ClassSATAController   -- SATA
                  0x07 -> ClassSASController    -- SAS
                  0x08 -> ClassNVMe             -- NVMe (though usually 0x0108)
                  _    -> ClassMultiFunctionStorageController
      in Component
        { componentClass = cls
        , componentManufacturer = pciVendorName dev
        , componentModel = T.pack $ "Storage Controller ["
                            ++ formatHex (pciVendorId dev) ++ ":"
                            ++ formatHex (pciDeviceId dev) ++ "]"
        , componentSerial = Nothing
        , componentRevision = pciRevision dev
        , componentFieldReplaceable = Just True
        , componentAddresses = []
        }

-- | Get network controllers
getNetworkControllers :: IO [Component]
getNetworkControllers = do
  devices <- getPciDevices
  let network = filter isNetwork devices
  return $ map networkToComponent network
  where
    isNetwork dev = getPciClass (pciClassCode dev) == PciClassNetwork

    networkToComponent dev = Component
      { componentClass = ClassEthernetController
      , componentManufacturer = pciVendorName dev
      , componentModel = T.pack $ "Network Controller ["
                          ++ formatHex (pciVendorId dev) ++ ":"
                          ++ formatHex (pciDeviceId dev) ++ "]"
      , componentSerial = Nothing
      , componentRevision = pciRevision dev
      , componentFieldReplaceable = Just True
      , componentAddresses = []
      }

-- | Get USB controllers
getUsbControllers :: IO [Component]
getUsbControllers = do
  devices <- getPciDevices
  let usb = filter isUsb devices
  return $ map usbToComponent usb
  where
    -- Serial Bus Controller (0x0C) with USB subclass (0x03)
    isUsb dev = getPciClass (pciClassCode dev) == PciClassSerial &&
                (pciClassCode dev `mod` 0x100) == 0x03

    usbToComponent dev = Component
      { componentClass = ClassUSBController
      , componentManufacturer = pciVendorName dev
      , componentModel = T.pack $ "USB Controller ["
                          ++ formatHex (pciVendorId dev) ++ ":"
                          ++ formatHex (pciDeviceId dev) ++ "]"
      , componentSerial = Nothing
      , componentRevision = pciRevision dev
      , componentFieldReplaceable = Just False
      , componentAddresses = []
      }

-- | Lookup vendor name from vendor ID
-- This is a simplified lookup for common vendors
lookupVendorName :: Word16 -> Text
lookupVendorName vid = case vid of
  0x1002 -> "AMD/ATI"
  0x10DE -> "NVIDIA"
  0x8086 -> "Intel"
  0x1022 -> "AMD"
  0x14E4 -> "Broadcom"
  0x10EC -> "Realtek"
  0x1B4B -> "Marvell"
  0x1000 -> "LSI Logic"
  0x15B3 -> "Mellanox"
  0x1969 -> "Qualcomm Atheros"
  0x168C -> "Qualcomm Atheros"
  0x144D -> "Samsung"
  0x1179 -> "Toshiba"
  0x1C5C -> "SK hynix"
  0x126F -> "Silicon Motion"
  0x1987 -> "Phison"
  0x1CC1 -> "ADATA"
  0x15B7 -> "SanDisk/WD"
  0x2646 -> "Kingston"
  0x1E0F -> "KIOXIA"
  0x025E -> "Solidigm"
  _      -> ""

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Pci
  ( getPciDevices
  , getGpuDevices
  , getStorageControllers
  , getNetworkControllers
  , getUsbControllers
  , PciDevice(..)
  , PciClass(..)
  ) where

import Data.Text (Text)
import Data.Word (Word16)
import Data.HardwareInfo.Types

data PciDevice = PciDevice
  { pciSlot       :: !Text
  , pciVendorId   :: !Word16
  , pciDeviceId   :: !Word16
  , pciClassCode  :: !Word16
  , pciVendorName :: !Text
  , pciDeviceName :: !Text
  , pciSubsystem  :: !(Maybe Text)
  , pciRevision   :: !(Maybe Text)
  } deriving (Show, Eq)

data PciClass = PciClassUnknown deriving (Show, Eq)

getPciDevices :: IO [PciDevice]
getPciDevices = return []

getGpuDevices :: IO [Component]
getGpuDevices = return []

getStorageControllers :: IO [Component]
getStorageControllers = return []

getNetworkControllers :: IO [Component]
getNetworkControllers = return []

getUsbControllers :: IO [Component]
getUsbControllers = return []
#endif
