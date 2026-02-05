{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux
-- Description : Linux implementation of hardware information collection
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides the Linux-specific implementation for collecting
-- hardware information using sysfs and SMBIOS tables.

#ifdef LINUX
module Data.HardwareInfo.Linux
  ( -- * Linux backend
    LinuxHW(..)
  , runLinuxHW
    -- * Direct access functions
  , getLinuxHardwareInfo
  , getLinuxPlatformInfo
  , getLinuxNetworkInterfaces
  ) where

import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Network.Info (getNetworkInterfaces, NetworkInterface(..), MAC(..))
import Text.Printf (printf)

import Data.HardwareInfo.Types
import Data.HardwareInfo.Class
import Data.HardwareInfo.Smbios.Parser
import Data.HardwareInfo.Smbios.Types
import Data.HardwareInfo.Linux.Sysfs
  ( readDmiId, readSmbiosEntryPoint, readSmbiosTable
  , getNetworkInterfacePciAddress, getNetworkInterfaceVendorDevice
  , getNetworkInterfaceDriver, lookupVendorName
  , getNetworkInterfaceFirmware, getNetworkInterfacePermaddr
  , isWirelessInterface, isCellularInterface, getCellularModemInfo
  )
import Data.HardwareInfo.Linux.Nvme (getNvmeDevices)
import Data.HardwareInfo.Linux.Pci (getGpuDevices, getStorageControllers, getUsbControllers, getAudioControllers, getAccelerators, getEncryptionControllers)
import Data.HardwareInfo.Linux.Block (getAllStorageDevices, getOpticalDrives)
import Data.HardwareInfo.Linux.Bluetooth (getBluetoothDevices)
import Data.HardwareInfo.Linux.Input (getInputDevices)
import Data.HardwareInfo.Linux.Usb (getUsbDevices)
import Data.HardwareInfo.Linux.Firmware (getFirmwareComponents)

-- | Linux hardware collection monad
newtype LinuxHW a = LinuxHW { unLinuxHW :: IO a }
  deriving (Functor, Applicative, Monad, MonadIO)

-- | Run a LinuxHW action
runLinuxHW :: LinuxHW a -> IO a
runLinuxHW = unLinuxHW

instance MonadHardware LinuxHW where
  getPlatformInfo = LinuxHW getLinuxPlatformInfo

  getBaseboardInfo = LinuxHW $ do
    tableResult <- getSmbiosTableParsed
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        case extractBaseboardInfo table of
          Nothing -> return $ Left $ ParseError "Baseboard info not found"
          Just comp -> return $ Right comp

  getChassisInfo = LinuxHW $ do
    tableResult <- getSmbiosTableParsed
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        case extractChassisInfo table of
          Nothing -> return $ Left $ ParseError "Chassis info not found"
          Just comp -> return $ Right comp

  getBiosInfo = LinuxHW $ do
    tableResult <- getSmbiosTableParsed
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        case extractBiosInfo table of
          Nothing -> return $ Left $ ParseError "BIOS info not found"
          Just comp -> return $ Right comp

  getProcessorInfo = LinuxHW $ do
    tableResult <- getSmbiosTableParsed
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        return $ Right $ extractProcessorInfo table

  getMemoryInfo = LinuxHW $ do
    tableResult <- getSmbiosTableParsed
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        return $ Right $ extractMemoryDevices table

  getNetworkInfo = LinuxHW $ do
    -- Get NICs (Ethernet and WiFi)
    nics <- getLinuxNetworkInterfaces
    -- Get Bluetooth adapters
    btDevices <- getBluetoothDevices
    return $ Right $ nics ++ btDevices

  getStorageInfo = LinuxHW $ do
    -- Get NVMe devices
    nvmeDevs <- getNvmeDevices
    -- Get SATA/SAS/other block devices
    blockDevs <- getAllStorageDevices
    return $ Right $ nvmeDevs ++ blockDevs

  getTpmInfo = LinuxHW $ do
    tableResult <- getSmbiosTableParsed
    case tableResult of
      Left _ -> return $ Right Nothing
      Right table ->
        return $ Right $ extractTpmInfo table

  getPowerSupplyInfo = LinuxHW $ do
    tableResult <- getSmbiosTableParsed
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        return $ Right $ extractPowerSupplyInfo table

  getBatteryInfo = LinuxHW $ do
    tableResult <- getSmbiosTableParsed
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        return $ Right $ extractBatteryInfo table

  getCoolingInfo = LinuxHW $ do
    tableResult <- getSmbiosTableParsed
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        return $ Right $ extractCoolingDevices table

  getBmcInfo = LinuxHW $ do
    tableResult <- getSmbiosTableParsed
    case tableResult of
      Left _ -> return $ Right Nothing
      Right table ->
        return $ Right $ extractBmcInfo table

  getGpuInfo = LinuxHW $ do
    gpus <- getGpuDevices
    return $ Right gpus

  getStorageControllerInfo = LinuxHW $ do
    controllers <- getStorageControllers
    return $ Right controllers

  getUsbControllerInfo = LinuxHW $ do
    controllers <- getUsbControllers
    return $ Right controllers

  getInputDeviceInfo = LinuxHW $ do
    devices <- getInputDevices
    return $ Right devices

  getUsbDeviceInfo = LinuxHW $ do
    devices <- getUsbDevices
    return $ Right devices

  getAudioControllerInfo = LinuxHW $ do
    controllers <- getAudioControllers
    return $ Right controllers

  getOpticalDriveInfo = LinuxHW $ do
    drives <- getOpticalDrives
    return $ Right drives

  getAcceleratorInfo = LinuxHW $ do
    accelerators <- getAccelerators
    return $ Right accelerators

  getEncryptionControllerInfo = LinuxHW $ do
    controllers <- getEncryptionControllers
    return $ Right controllers

  getFirmwareInfo = LinuxHW $ do
    firmware <- getFirmwareComponents
    return $ Right firmware

  getSmbiosVersion = LinuxHW $ do
    epResult <- readSmbiosEntryPoint
    case epResult of
      Left err -> return $ Left $ SmbiosNotAvailable err
      Right epData -> do
        let ep = if T.pack "_SM3_" `T.isPrefixOf` T.pack (show epData)
                   then parseEntryPoint64 epData
                   else parseEntryPoint32 epData
        case ep of
          Left err -> return $ Left $ ParseError $ T.pack err
          Right entryPoint ->
            return $ Right SmbiosVersion
              { smbiosMajor = epMajorVersion entryPoint
              , smbiosMinor = epMinorVersion entryPoint
              , smbiosRevision = epRevision entryPoint
              }

-- | Get platform info from sysfs (fast path) or SMBIOS table
getLinuxPlatformInfo :: IO (Either HardwareError PlatformInfo)
getLinuxPlatformInfo = do
  -- Try sysfs first (faster, doesn't require root for most fields)
  sysVendor <- readDmiId "sys_vendor"
  productName <- readDmiId "product_name"
  productVersion <- readDmiId "product_version"
  productSerial <- readDmiId "product_serial"
  productUUID <- readDmiId "product_uuid"
  productSKU <- readDmiId "product_sku"
  productFamily <- readDmiId "product_family"

  case (sysVendor, productName) of
    (Right vendor, Right name) ->
      return $ Right PlatformInfo
        { platformManufacturer = vendor
        , platformModel = name
        , platformVersion = either (const "") id productVersion
        , platformSerial = either (const Nothing) Just productSerial
        , platformUUID = either (const Nothing) Just productUUID
        , platformSKU = either (const Nothing) Just productSKU
        , platformFamily = either (const Nothing) Just productFamily
        }
    _ -> do
      -- Fall back to SMBIOS table parsing
      tableResult <- getSmbiosTableParsed
      case tableResult of
        Left err -> return $ Left err
        Right table ->
          case extractSystemInfo table of
            Nothing -> return $ Left $ ParseError "System info not found in SMBIOS"
            Just info -> return $ Right info

-- | Get and parse SMBIOS table
getSmbiosTableParsed :: IO (Either HardwareError SmbiosTable)
getSmbiosTableParsed = do
  epResult <- readSmbiosEntryPoint
  case epResult of
    Left err -> return $ Left $ SmbiosNotAvailable err
    Right epData -> do
      -- Determine entry point type and parse
      let epParse = if "_SM3_" `elem` chunksOf 5 (show epData)
                      then parseEntryPoint64 epData
                      else parseEntryPoint32 epData
      case epParse of
        Left err -> return $ Left $ ParseError $ T.pack err
        Right ep -> do
          tableResult <- readSmbiosTable
          case tableResult of
            Left err -> return $ Left $ SmbiosNotAvailable err
            Right tableData ->
              case parseSmbiosTable ep tableData of
                Left err -> return $ Left $ ParseError $ T.pack err
                Right table -> return $ Right table
  where
    chunksOf _ [] = []
    chunksOf n xs = take n xs : chunksOf n (drop n xs)

-- | Get network interfaces using network-info package
-- Collects MAC addresses, PCI addresses, manufacturer, and model where available
getLinuxNetworkInterfaces :: IO [Component]
getLinuxNetworkInterfaces = do
  ifaces <- getNetworkInterfaces
  mapM toComponent $ filter isPhysical ifaces
  where
    isPhysical iface =
      let n = name iface
      in n /= "lo" && not ("veth" `T.isPrefixOf` T.pack n)

    toComponent iface = do
      let ifaceName = T.pack $ name iface
      -- Check if this is a wireless (WiFi) interface
      isWifi <- isWirelessInterface ifaceName
      -- Check if this is a cellular (WWAN) interface
      isCellular <- isCellularInterface ifaceName
      -- Get cellular modem info if applicable
      (cellularMfr, cellularModel, cellularTech) <- if isCellular
        then getCellularModemInfo ifaceName
        else return (Nothing, Nothing, Nothing)
      -- Get PCI address for this interface
      pciAddr <- getNetworkInterfacePciAddress ifaceName
      -- Get PCI vendor/device IDs for manufacturer/model
      vendorDevice <- getNetworkInterfaceVendorDevice ifaceName
      -- Get driver name as fallback model info
      driverName <- getNetworkInterfaceDriver ifaceName
      -- Get firmware version from ethtool
      firmwareVer <- getNetworkInterfaceFirmware ifaceName
      -- Get permanent MAC address (can serve as serial identifier)
      permAddr <- getNetworkInterfacePermaddr ifaceName

      -- Use appropriate MAC address type based on interface type
      let macAddrValue = formatMAC $ mac iface
      let macAddr = if isWifi
                      then WirelessMAC macAddrValue
                      else EthernetMAC macAddrValue
      let addresses = case pciAddr of
            Just addr -> [macAddr, PCIAddress addr]
            Nothing   -> [macAddr]

      -- Determine manufacturer from vendor ID or cellular info
      let manufacturer = case (cellularMfr, vendorDevice) of
            (Just mfr, _) -> mfr
            (Nothing, Just (vendorId, _)) ->
              let vendorName = lookupVendorName vendorId
              in if T.null vendorName
                   then vendorId  -- Use raw ID if no mapping
                   else vendorName
            (Nothing, Nothing) -> ""

      -- Determine model: prefer cellular model, device ID info, fallback to driver + interface name
      let model = case (cellularModel, vendorDevice, driverName) of
            (Just cm, _, _) ->
              cm <> " (" <> ifaceName <> ")"
            (Nothing, Just (_, deviceId), Just drv) ->
              -- Format: "driver (interface)" with device ID available
              drv <> " " <> deviceId <> " (" <> ifaceName <> ")"
            (Nothing, Just (_, deviceId), Nothing) ->
              deviceId <> " (" <> ifaceName <> ")"
            (Nothing, Nothing, Just drv) ->
              drv <> " (" <> ifaceName <> ")"
            (Nothing, Nothing, Nothing) ->
              ifaceName

      -- Use appropriate component class based on interface type
      let compClass
            | isCellular = case cellularTech of
                Just "5G" -> Class5GCellular
                Just "4G" -> Class4GCellular
                Just "3G" -> Class3GCellular
                _         -> Class4GCellular  -- Default to 4G for unknown modems
            | isWifi = ClassWiFiAdapter
            | otherwise = ClassEthernetAdapter

      return Component
        { componentClass = compClass
        , componentManufacturer = manufacturer
        , componentModel = model
        , componentSerial = permAddr  -- Permanent MAC as serial identifier
        , componentRevision = firmwareVer  -- Firmware version as revision
        , componentFieldReplaceable = Just True
        , componentAddresses = addresses
        }

    formatMAC (MAC a b c d e f) =
      T.pack $ printf "%02X:%02X:%02X:%02X:%02X:%02X" a b c d e f

-- | Get complete hardware info (convenience function)
getLinuxHardwareInfo :: IO (Either HardwareError HardwareInfo)
getLinuxHardwareInfo = runLinuxHW collectHardwareInfo

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux where

import Data.HardwareInfo.Types

getLinuxHardwareInfo :: IO (Either HardwareError HardwareInfo)
getLinuxHardwareInfo = return $ Left $ UnsupportedPlatform "Linux support not compiled"
#endif