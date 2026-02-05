{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Windows
-- Description : Windows implementation of hardware information collection
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides the Windows-specific implementation for collecting
-- hardware information using Win32 APIs.

#ifdef WINDOWS
module Data.HardwareInfo.Windows
  ( -- * Windows backend
    WindowsHW(..)
  , runWindowsHW
    -- * Direct access functions
  , getWindowsHardwareInfo
  , getWindowsPlatformInfo
  ) where

import Control.Monad.IO.Class (MonadIO)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Network.Info (getNetworkInterfaces, NetworkInterface(..), MAC(..))
import Text.Printf (printf)

import Data.HardwareInfo.Types
import Data.HardwareInfo.Class
import Data.HardwareInfo.Smbios.Parser
import Data.HardwareInfo.Smbios.Types
import Data.HardwareInfo.Windows.Smbios
import Data.HardwareInfo.Windows.Nvme (getAllStorageDevices)
import qualified Data.HardwareInfo.Windows.SetupApi as SetupApi

-- | Windows hardware collection monad
newtype WindowsHW a = WindowsHW { unWindowsHW :: IO a }
  deriving (Functor, Applicative, Monad, MonadIO)

-- | Run a WindowsHW action
runWindowsHW :: WindowsHW a -> IO a
runWindowsHW = unWindowsHW

instance MonadHardware WindowsHW where
  getPlatformInfo = WindowsHW getWindowsPlatformInfo

  getBaseboardInfo = WindowsHW $ do
    tableResult <- getWindowsSmbiosTable
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        case extractBaseboardInfo table of
          Nothing -> return $ Left $ ParseError "Baseboard info not found"
          Just comp -> return $ Right comp

  getChassisInfo = WindowsHW $ do
    tableResult <- getWindowsSmbiosTable
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        case extractChassisInfo table of
          Nothing -> return $ Left $ ParseError "Chassis info not found"
          Just comp -> return $ Right comp

  getBiosInfo = WindowsHW $ do
    tableResult <- getWindowsSmbiosTable
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        case extractBiosInfo table of
          Nothing -> return $ Left $ ParseError "BIOS info not found"
          Just comp -> return $ Right comp

  getProcessorInfo = WindowsHW $ do
    tableResult <- getWindowsSmbiosTable
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        return $ Right $ extractProcessorInfo table

  getMemoryInfo = WindowsHW $ do
    tableResult <- getWindowsSmbiosTable
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        return $ Right $ extractMemoryDevices table

  getNetworkInfo = WindowsHW $ do
    nics <- getWindowsNetworkInterfaces
    return $ Right nics

  getStorageInfo = WindowsHW $ do
    -- Get all storage devices (NVMe, SATA, SAS, etc.) via DeviceIoControl
    storageDevs <- getAllStorageDevices
    return $ Right storageDevs

  getTpmInfo = WindowsHW $ do
    tableResult <- getWindowsSmbiosTable
    case tableResult of
      Left _ -> return $ Right Nothing
      Right table ->
        return $ Right $ extractTpmInfo table

  getPowerSupplyInfo = WindowsHW $ do
    tableResult <- getWindowsSmbiosTable
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        return $ Right $ extractPowerSupplyInfo table

  getBatteryInfo = WindowsHW $ do
    tableResult <- getWindowsSmbiosTable
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        return $ Right $ extractBatteryInfo table

  getCoolingInfo = WindowsHW $ do
    tableResult <- getWindowsSmbiosTable
    case tableResult of
      Left err -> return $ Left err
      Right table ->
        return $ Right $ extractCoolingDevices table

  getBmcInfo = WindowsHW $ do
    tableResult <- getWindowsSmbiosTable
    case tableResult of
      Left _ -> return $ Right Nothing
      Right table ->
        return $ Right $ extractBmcInfo table

  -- PCI enumeration via SetupAPI
  getGpuInfo = WindowsHW $ do
    gpus <- SetupApi.getGpuDevices
    return $ Right gpus

  getStorageControllerInfo = WindowsHW $ do
    controllers <- SetupApi.getStorageControllers
    return $ Right controllers

  getUsbControllerInfo = WindowsHW $ do
    controllers <- SetupApi.getUsbControllers
    return $ Right controllers

  getInputDeviceInfo = WindowsHW $ return $ Right []

  getUsbDeviceInfo = WindowsHW $ return $ Right []

  getAudioControllerInfo = WindowsHW $ return $ Right []

  getOpticalDriveInfo = WindowsHW $ return $ Right []

  getAcceleratorInfo = WindowsHW $ return $ Right []

  getEncryptionControllerInfo = WindowsHW $ return $ Right []

  getFirmwareInfo = WindowsHW $ return $ Right []

  getSmbiosVersion = WindowsHW $ do
    result <- getRawSmbiosData
    case result of
      Left err -> return $ Left $ SmbiosNotAvailable $ T.pack err
      Right wsData ->
        return $ Right SmbiosVersion
          { smbiosMajor = wsMajorVersion wsData
          , smbiosMinor = wsMinorVersion wsData
          , smbiosRevision = wsDmiRevision wsData
          }

-- | Get platform info from SMBIOS
getWindowsPlatformInfo :: IO (Either HardwareError PlatformInfo)
getWindowsPlatformInfo = do
  tableResult <- getWindowsSmbiosTable
  case tableResult of
    Left err -> return $ Left err
    Right table ->
      case extractSystemInfo table of
        Nothing -> return $ Left $ ParseError "System info not found in SMBIOS"
        Just info -> return $ Right info

-- | Get and parse SMBIOS table from Windows
getWindowsSmbiosTable :: IO (Either HardwareError SmbiosTable)
getWindowsSmbiosTable = do
  result <- getRawSmbiosData
  case result of
    Left err -> return $ Left $ SmbiosNotAvailable $ T.pack err
    Right wsData -> do
      let ep = SmbiosEntryPoint
            { epMajorVersion = wsMajorVersion wsData
            , epMinorVersion = wsMinorVersion wsData
            , epRevision = wsDmiRevision wsData
            , epTableLength = fromIntegral $ BS.length $ wsTableData wsData
            , epTableAddress = 0
            , epIs64Bit = False
            }
      case parseSmbiosTable ep (wsTableData wsData) of
        Left err -> return $ Left $ ParseError $ T.pack err
        Right table -> return $ Right table

-- | Get network interfaces using network-info package
getWindowsNetworkInterfaces :: IO [Component]
getWindowsNetworkInterfaces = do
  ifaces <- getNetworkInterfaces
  return $ map toComponent $ filter isPhysical ifaces
  where
    isPhysical iface =
      let n = name iface
      in n /= "lo" && not ("Loopback" `isInfixOf` n)

    isInfixOf needle haystack = needle `T.isInfixOf` T.pack haystack

    toComponent iface = Component
      { componentClass = ClassNIC
      , componentManufacturer = ""
      , componentModel = T.pack $ name iface
      , componentSerial = Nothing
      , componentRevision = Nothing
      , componentFieldReplaceable = Just True
      , componentAddresses = [EthernetMAC $ formatMAC $ mac iface]
      }

    formatMAC (MAC a b c d e f) =
      T.pack $ printf "%02X:%02X:%02X:%02X:%02X:%02X" a b c d e f

-- | Get complete hardware info (convenience function)
getWindowsHardwareInfo :: IO (Either HardwareError HardwareInfo)
getWindowsHardwareInfo = runWindowsHW collectHardwareInfo

#else
-- Non-Windows stub
module Data.HardwareInfo.Windows
  ( getWindowsHardwareInfo
  ) where

import Data.HardwareInfo.Types

getWindowsHardwareInfo :: IO (Either HardwareError HardwareInfo)
getWindowsHardwareInfo = return $ Left $ UnsupportedPlatform "Windows support not compiled"
#endif
