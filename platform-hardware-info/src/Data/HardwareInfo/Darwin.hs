{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Darwin
-- Description : macOS implementation of hardware information collection
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides the macOS-specific implementation for collecting
-- hardware information using system_profiler and IOKit.
--
-- Note: This is a basic implementation. Full support would require
-- IOKit FFI bindings.

#ifdef darwin_HOST_OS
module Data.HardwareInfo.Darwin
  ( -- * Darwin backend
    DarwinHW(..)
  , runDarwinHW
    -- * Direct access functions
  , getDarwinHardwareInfo
  , getDarwinPlatformInfo
  ) where

import Control.Exception (try, SomeException)
import Control.Monad.IO.Class (MonadIO)
import Data.Text (Text)
import qualified Data.Text as T
import Network.Info (getNetworkInterfaces, NetworkInterface(..), MAC(..))
import System.Process (readProcess)
import Text.Printf (printf)

import Data.HardwareInfo.Types
import Data.HardwareInfo.Class

-- | Darwin hardware collection monad
newtype DarwinHW a = DarwinHW { unDarwinHW :: IO a }
  deriving (Functor, Applicative, Monad, MonadIO)

-- | Run a DarwinHW action
runDarwinHW :: DarwinHW a -> IO a
runDarwinHW = unDarwinHW

instance MonadHardware DarwinHW where
  getPlatformInfo = DarwinHW getDarwinPlatformInfo

  getBaseboardInfo = DarwinHW $ return $ Left $
    UnsupportedPlatform "Baseboard info not available on macOS"

  getChassisInfo = DarwinHW $ return $ Left $
    UnsupportedPlatform "Chassis info not available on macOS"

  getBiosInfo = DarwinHW $ return $ Left $
    UnsupportedPlatform "BIOS info not available on macOS"

  getProcessorInfo = DarwinHW $ do
    result <- try $ readProcess "sysctl" ["-n", "machdep.cpu.brand_string"] ""
    case result of
      Left (_ :: SomeException) -> return $ Right []
      Right cpuModel -> return $ Right [Component
        { componentClass = ClassCPU
        , componentManufacturer = "Apple"  -- or detect Intel/Apple
        , componentModel = T.strip $ T.pack cpuModel
        , componentSerial = Nothing
        , componentRevision = Nothing
        , componentFieldReplaceable = Just False
        , componentAddresses = []
        }]

  getMemoryInfo = DarwinHW $ return $ Right []

  getNetworkInfo = DarwinHW $ do
    nics <- getDarwinNetworkInterfaces
    return $ Right nics

  getStorageInfo = DarwinHW $ return $ Right []

  getTpmInfo = DarwinHW $ return $ Right Nothing

  getPowerSupplyInfo = DarwinHW $ return $ Right []

  getBatteryInfo = DarwinHW $ return $ Right []

  getCoolingInfo = DarwinHW $ return $ Right []

  getBmcInfo = DarwinHW $ return $ Right Nothing

  -- PCI enumeration would require IOKit on macOS
  getGpuInfo = DarwinHW $ return $ Right []

  getStorageControllerInfo = DarwinHW $ return $ Right []

  getUsbControllerInfo = DarwinHW $ return $ Right []

  getInputDeviceInfo = DarwinHW $ return $ Right []

  getUsbDeviceInfo = DarwinHW $ return $ Right []

  getAudioControllerInfo = DarwinHW $ return $ Right []

  getOpticalDriveInfo = DarwinHW $ return $ Right []

  getAcceleratorInfo = DarwinHW $ return $ Right []

  getEncryptionControllerInfo = DarwinHW $ return $ Right []

  getFirmwareInfo = DarwinHW $ return $ Right []

  getSmbiosVersion = DarwinHW $ return $ Left $
    SmbiosNotAvailable "SMBIOS not directly accessible on macOS"

-- | Get platform info from system_profiler
getDarwinPlatformInfo :: IO (Either HardwareError PlatformInfo)
getDarwinPlatformInfo = do
  -- Get hardware model
  modelResult <- try $ readProcess "sysctl" ["-n", "hw.model"] ""

  -- Get serial number (requires root)
  serialResult <- try $ readProcess "system_profiler"
    ["SPHardwareDataType", "-detailLevel", "mini"] ""

  let model = case modelResult of
        Left (_ :: SomeException) -> ""
        Right m -> T.strip $ T.pack m

  let serial = case serialResult of
        Left (_ :: SomeException) -> Nothing
        Right output -> extractSerial (T.pack output)

  return $ Right PlatformInfo
    { platformManufacturer = "Apple Inc."
    , platformModel = model
    , platformVersion = ""
    , platformSerial = serial
    , platformUUID = Nothing
    , platformSKU = Nothing
    , platformFamily = Nothing
    }

-- | Extract serial number from system_profiler output
extractSerial :: Text -> Maybe Text
extractSerial output =
  case filter ("Serial Number" `T.isInfixOf`) (T.lines output) of
    (line:_) ->
      let parts = T.splitOn ":" line
      in if length parts >= 2
           then Just $ T.strip $ parts !! 1
           else Nothing
    [] -> Nothing

-- | Get network interfaces using network-info package
getDarwinNetworkInterfaces :: IO [Component]
getDarwinNetworkInterfaces = do
  ifaces <- getNetworkInterfaces
  return $ map toComponent $ filter isPhysical ifaces
  where
    isPhysical iface =
      let n = name iface
      in n /= "lo0" &&
         not ("utun" `T.isPrefixOf` T.pack n) &&
         not ("bridge" `T.isPrefixOf` T.pack n)

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
getDarwinHardwareInfo :: IO (Either HardwareError HardwareInfo)
getDarwinHardwareInfo = runDarwinHW collectHardwareInfo

#else
-- Non-Darwin stub
module Data.HardwareInfo.Darwin
  ( getDarwinHardwareInfo
  ) where

import Data.HardwareInfo.Types

getDarwinHardwareInfo :: IO (Either HardwareError HardwareInfo)
getDarwinHardwareInfo = return $ Left $ UnsupportedPlatform "macOS support not compiled"
#endif
