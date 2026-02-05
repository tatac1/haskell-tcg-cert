{-# LANGUAGE FlexibleContexts #-}
-- |
-- Module      : Data.HardwareInfo.Class
-- Description : Abstract interface for hardware information collection
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module defines the abstract interface for collecting hardware
-- information across different platforms.

module Data.HardwareInfo.Class
  ( -- * Type class
    MonadHardware(..)
    -- * High-level functions
  , collectHardwareInfo
    -- * Re-exports
  , HardwareInfo(..)
  , HardwareError(..)
  ) where

import Data.HardwareInfo.Types

-- | Abstract interface for hardware information collection
--
-- This type class defines the operations needed to collect hardware
-- information from the system. Platform-specific implementations
-- (Linux, Windows) provide concrete instances.
class Monad m => MonadHardware m where
  -- | Get platform/system information from SMBIOS Type 1
  getPlatformInfo :: m (Either HardwareError PlatformInfo)

  -- | Get baseboard (motherboard) information from SMBIOS Type 2
  getBaseboardInfo :: m (Either HardwareError Component)

  -- | Get chassis information from SMBIOS Type 3
  getChassisInfo :: m (Either HardwareError Component)

  -- | Get BIOS information from SMBIOS Type 0
  getBiosInfo :: m (Either HardwareError Component)

  -- | Get processor information from SMBIOS Type 4
  getProcessorInfo :: m (Either HardwareError [Component])

  -- | Get memory device information from SMBIOS Type 17
  getMemoryInfo :: m (Either HardwareError [Component])

  -- | Get network interface information (including MAC addresses)
  getNetworkInfo :: m (Either HardwareError [Component])

  -- | Get storage device information
  getStorageInfo :: m (Either HardwareError [Component])

  -- | Get TPM device information from SMBIOS Type 43
  getTpmInfo :: m (Either HardwareError (Maybe Component))

  -- | Get power supply information from SMBIOS Type 39
  getPowerSupplyInfo :: m (Either HardwareError [Component])

  -- | Get battery information from SMBIOS Type 22
  getBatteryInfo :: m (Either HardwareError [Component])

  -- | Get cooling device information from SMBIOS Type 27
  getCoolingInfo :: m (Either HardwareError [Component])

  -- | Get BMC (Baseboard Management Controller) information from SMBIOS Type 38
  getBmcInfo :: m (Either HardwareError (Maybe Component))

  -- | Get GPU devices (via PCI enumeration)
  getGpuInfo :: m (Either HardwareError [Component])

  -- | Get storage controllers (SATA, SAS, RAID via PCI)
  getStorageControllerInfo :: m (Either HardwareError [Component])

  -- | Get USB controllers (via PCI)
  getUsbControllerInfo :: m (Either HardwareError [Component])

  -- | Get input devices (keyboard, mouse, touchpad)
  getInputDeviceInfo :: m (Either HardwareError [Component])

  -- | Get USB devices (individual devices, not just controllers)
  getUsbDeviceInfo :: m (Either HardwareError [Component])

  -- | Get audio controllers (via PCI)
  getAudioControllerInfo :: m (Either HardwareError [Component])

  -- | Get optical drives (CD/DVD/Blu-Ray)
  getOpticalDriveInfo :: m (Either HardwareError [Component])

  -- | Get processing accelerators (AI/ML accelerators)
  getAcceleratorInfo :: m (Either HardwareError [Component])

  -- | Get encryption controllers (via PCI)
  getEncryptionControllerInfo :: m (Either HardwareError [Component])

  -- | Get firmware components (BIOS, bootloader, drive firmware)
  getFirmwareInfo :: m (Either HardwareError [Component])

  -- | Get SMBIOS version
  getSmbiosVersion :: m (Either HardwareError SmbiosVersion)

-- | Collect all hardware information
--
-- This function collects all available hardware information by calling
-- the individual collection functions and combining the results.
-- Errors in individual components are logged but don't prevent collection
-- of other components.
collectHardwareInfo :: MonadHardware m => m (Either HardwareError HardwareInfo)
collectHardwareInfo = do
  -- Get platform info (required)
  platformResult <- getPlatformInfo
  case platformResult of
    Left err -> return $ Left err
    Right platform -> do
      -- Collect components (optional - errors are ignored)
      components <- collectComponents
      version <- getSmbiosVersion

      return $ Right HardwareInfo
        { hwPlatform = platform
        , hwComponents = components
        , hwSmbiosVersion = either (const Nothing) Just version
        }

-- | Collect all components, ignoring individual errors
collectComponents :: MonadHardware m => m [Component]
collectComponents = do
  results <- sequence
    [ fmap (either (const []) (:[])) getBaseboardInfo
    , fmap (either (const []) (:[])) getChassisInfo
    , fmap (either (const []) (:[])) getBiosInfo
    , fmap (either (const []) id) getProcessorInfo
    , fmap (either (const []) id) getMemoryInfo
    , fmap (either (const []) id) getNetworkInfo
    , fmap (either (const []) id) getStorageInfo
    , fmap (either (const []) (maybe [] (:[]))) getTpmInfo
    , fmap (either (const []) id) getPowerSupplyInfo
    , fmap (either (const []) id) getBatteryInfo
    , fmap (either (const []) id) getCoolingInfo
    , fmap (either (const []) (maybe [] (:[]))) getBmcInfo
    , fmap (either (const []) id) getGpuInfo
    , fmap (either (const []) id) getStorageControllerInfo
    , fmap (either (const []) id) getUsbControllerInfo
    , fmap (either (const []) id) getInputDeviceInfo
    , fmap (either (const []) id) getUsbDeviceInfo
    , fmap (either (const []) id) getAudioControllerInfo
    , fmap (either (const []) id) getOpticalDriveInfo
    , fmap (either (const []) id) getAcceleratorInfo
    , fmap (either (const []) id) getEncryptionControllerInfo
    , fmap (either (const []) id) getFirmwareInfo
    ]
  return $ concat results