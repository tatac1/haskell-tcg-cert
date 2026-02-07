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
  , getAudioControllers
  , getAccelerators
  , getEncryptionControllers
  ) where

import Control.Exception (try, SomeException)
import Control.Monad (filterM, forM)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Data.Word (Word16, Word32)
import System.Directory (listDirectory, doesFileExist, doesDirectoryExist)
import System.FilePath ((</>))
import Numeric (readHex)

import Data.HardwareInfo.Types
import Data.HardwareInfo.Linux.PciIds (lookupVendorById, lookupDeviceById)

-- | PCI device information
data PciDevice = PciDevice
  { pciSlot       :: !Text        -- ^ PCI slot (e.g., "0000:00:02.0")
  , pciVendorId   :: !Word16      -- ^ Vendor ID
  , pciDeviceId   :: !Word16      -- ^ Device ID
  , pciClassCode  :: !Word32      -- ^ Class code (24-bit, e.g. 0x030000)
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

-- | Get all PCI devices (excludes SR-IOV virtual functions)
getPciDevices :: IO [PciDevice]
getPciDevices = do
  result <- try $ listDirectory pciDevicesPath
  case result of
    Left (_ :: SomeException) -> return []
    Right slots -> do
      -- Filter out SR-IOV Virtual Functions (they have a 'physfn' symlink)
      physicalSlots <- filterM (fmap not . isVirtualFunction) slots
      devices <- forM physicalSlots $ \slot -> do
        let slotPath = pciDevicesPath </> slot
        mDev <- readPciDevice (T.pack slot) slotPath
        return mDev
      return [d | Just d <- devices]

-- | Check if a PCI device is an SR-IOV Virtual Function
-- VFs have a 'physfn' symlink pointing to their parent Physical Function
isVirtualFunction :: String -> IO Bool
isVirtualFunction slot = do
  let physfnPath = pciDevicesPath </> slot </> "physfn"
  doesDirectoryExist physfnPath  -- physfn is a symlink to a PCI device directory

-- | Read PCI device information from sysfs
readPciDevice :: Text -> FilePath -> IO (Maybe PciDevice)
readPciDevice slot slotPath = do
  vendorResult <- readSysfsHex16 (slotPath </> "vendor")
  deviceResult <- readSysfsHex16 (slotPath </> "device")
  classResult <- readSysfsHex32 (slotPath </> "class")

  case (vendorResult, deviceResult, classResult) of
    (Just vendor, Just device, Just classCode) -> do
      -- Try to read additional info
      revision <- readSysfsText (slotPath </> "revision")
      subsystemVendor <- readSysfsHex16 (slotPath </> "subsystem_vendor")
      subsystemDevice <- readSysfsHex16 (slotPath </> "subsystem_device")

      let subsys = case (subsystemVendor, subsystemDevice) of
                     (Just sv, Just sd) -> Just $ T.pack $
                       formatHex sv ++ ":" ++ formatHex sd
                     _ -> Nothing

      return $ Just PciDevice
        { pciSlot = slot
        , pciVendorId = vendor
        , pciDeviceId = device
        , pciClassCode = classCode  -- Full 24-bit class code (e.g. 0x030000)
        , pciVendorName = lookupVendorById vendor
        , pciDeviceName = lookupDeviceById vendor device
        , pciSubsystem = subsys
        , pciRevision = revision
        }
    _ -> return Nothing

-- | Read 16-bit hex value from sysfs file (for vendor/device IDs)
readSysfsHex16 :: FilePath -> IO (Maybe Word16)
readSysfsHex16 path = do
  exists <- doesFileExist path
  if not exists
    then return Nothing
    else do
      result <- try $ TIO.readFile path
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right content ->
          let stripped = T.strip content
              hexStr = if "0x" `T.isPrefixOf` stripped
                         then T.drop 2 stripped
                         else stripped
          in return $ parseHex16 (T.unpack hexStr)

-- | Read 32-bit hex value from sysfs file (for PCI class codes)
readSysfsHex32 :: FilePath -> IO (Maybe Word32)
readSysfsHex32 path = do
  exists <- doesFileExist path
  if not exists
    then return Nothing
    else do
      result <- try $ TIO.readFile path
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right content ->
          let stripped = T.strip content
              hexStr = if "0x" `T.isPrefixOf` stripped
                         then T.drop 2 stripped
                         else stripped
          in return $ parseHex32 (T.unpack hexStr)

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

-- | Parse hex string to Word16
parseHex16 :: String -> Maybe Word16
parseHex16 s = case readHex s of
  [(v, "")] -> Just (fromIntegral (v :: Integer))
  _ -> Nothing

-- | Parse hex string to Word32
parseHex32 :: String -> Maybe Word32
parseHex32 s = case readHex s of
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

-- | Get PCI class from full 24-bit class code (e.g. 0x030000)
-- Extracts the base class (high byte) for classification
getPciClass :: Word32 -> PciClass
getPciClass code = case code `div` 0x10000 of
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

-- | Get PCI subclass from full 24-bit class code (e.g. 0x010600 -> 0x06)
getPciSubclass :: Word32 -> Word32
getPciSubclass code = (code `div` 0x100) `mod` 0x100

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
      , componentModel = deviceModelName "GPU" dev
      , componentSerial = Nothing
      , componentRevision = pciRevision dev
      , componentFieldReplaceable = Just True
      , componentAddresses = [PCIAddress (pciSlot dev)]
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
      let subclass = getPciSubclass (pciClassCode dev)
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
        , componentModel = deviceModelName "Storage Controller" dev
        , componentSerial = Nothing
        , componentRevision = pciRevision dev
        , componentFieldReplaceable = Just True
        , componentAddresses = [PCIAddress (pciSlot dev)]
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
      , componentModel = deviceModelName "Network Controller" dev
      , componentSerial = Nothing
      , componentRevision = pciRevision dev
      , componentFieldReplaceable = Just True
      , componentAddresses = [PCIAddress (pciSlot dev)]
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
                getPciSubclass (pciClassCode dev) == 0x03

    usbToComponent dev = Component
      { componentClass = ClassUSBController
      , componentManufacturer = pciVendorName dev
      , componentModel = deviceModelName "USB Controller" dev
      , componentSerial = Nothing
      , componentRevision = pciRevision dev
      , componentFieldReplaceable = Just False
      , componentAddresses = [PCIAddress (pciSlot dev)]
      }

-- | Get audio/multimedia controllers
getAudioControllers :: IO [Component]
getAudioControllers = do
  devices <- getPciDevices
  let audio = filter isAudio devices
  return $ map audioToComponent audio
  where
    isAudio dev = getPciClass (pciClassCode dev) == PciClassMultimedia

    audioToComponent dev =
      let subclass = getPciSubclass (pciClassCode dev)
          -- Subclasses: 0x00=Video, 0x01=Audio, 0x02=Telephony, 0x03=HDAudio
          cls = case subclass of
                  0x01 -> ClassAudioController
                  0x03 -> ClassAudioController  -- HD Audio
                  _    -> ClassGeneralController
      in Component
        { componentClass = cls
        , componentManufacturer = pciVendorName dev
        , componentModel = deviceModelName "Audio Controller" dev
        , componentSerial = Nothing
        , componentRevision = pciRevision dev
        , componentFieldReplaceable = Just False
        , componentAddresses = [PCIAddress (pciSlot dev)]
        }

-- | Get processing accelerators (AI/ML accelerators, signal processors)
--
-- Note: TCG Component Class Registry v1.0 rev14 does not have a dedicated
-- accelerator class. We use ClassDPU (0x00010007 - Data Processing Unit)
-- as it's the closest match for processing accelerators in the TCG registry.
-- DPUs are defined as programmable processors specialized for data processing,
-- which encompasses AI/ML accelerators and signal processors.
getAccelerators :: IO [Component]
getAccelerators = do
  devices <- getPciDevices
  let accel = filter isAccelerator devices
  return $ map accelToComponent accel
  where
    isAccelerator dev =
      getPciClass (pciClassCode dev) == PciClassAccelerator ||
      getPciClass (pciClassCode dev) == PciClassSignal

    accelToComponent dev = Component
      { componentClass = ClassDPU  -- DPU: closest TCG match for accelerators
      , componentManufacturer = pciVendorName dev
      , componentModel = deviceModelName "Processing Accelerator" dev
      , componentSerial = Nothing
      , componentRevision = pciRevision dev
      , componentFieldReplaceable = Just True
      , componentAddresses = [PCIAddress (pciSlot dev)]
      }

-- | Get encryption controllers
--
-- Note: TCG Component Class Registry v1.0 rev14 does not define a specific
-- encryption controller class. We use ClassGeneralController (0x00050000)
-- as PCI class 0x10 (Encryption) devices are controller-type components.
-- These include hardware crypto accelerators, security processors, and
-- encrypted storage controllers (distinct from TPM which has its own class).
getEncryptionControllers :: IO [Component]
getEncryptionControllers = do
  devices <- getPciDevices
  let crypto = filter isEncryption devices
  return $ map cryptoToComponent crypto
  where
    isEncryption dev = getPciClass (pciClassCode dev) == PciClassEncryption

    cryptoToComponent dev = Component
      { componentClass = ClassGeneralController  -- No specific TCG class for crypto
      , componentManufacturer = pciVendorName dev
      , componentModel = deviceModelName "Encryption Controller" dev
      , componentSerial = Nothing
      , componentRevision = pciRevision dev
      , componentFieldReplaceable = Just False
      , componentAddresses = [PCIAddress (pciSlot dev)]
      }

-- | Build a model name for a PCI device.
-- Uses pci.ids device name if available, falls back to "Category [vid:did]"
deviceModelName :: Text -> PciDevice -> Text
deviceModelName category dev =
  let devName = pciDeviceName dev
      hexId = T.pack $ formatHex (pciVendorId dev) ++ ":"
                        ++ formatHex (pciDeviceId dev)
  in if T.null devName
       then category <> " [" <> hexId <> "]"
       else devName

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Pci
  ( getPciDevices
  , getGpuDevices
  , getStorageControllers
  , getNetworkControllers
  , getUsbControllers
  , getAudioControllers
  , getAccelerators
  , getEncryptionControllers
  , PciDevice(..)
  , PciClass(..)
  ) where

import Data.Text (Text)
import Data.Word (Word16, Word32)
import Data.HardwareInfo.Types

data PciDevice = PciDevice
  { pciSlot       :: !Text
  , pciVendorId   :: !Word16
  , pciDeviceId   :: !Word16
  , pciClassCode  :: !Word32
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

getAudioControllers :: IO [Component]
getAudioControllers = return []

getAccelerators :: IO [Component]
getAccelerators = return []

getEncryptionControllers :: IO [Component]
getEncryptionControllers = return []
#endif
