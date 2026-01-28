{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Data.HardwareInfo
-- Description : Cross-platform hardware information collection
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides a cross-platform interface for collecting hardware
-- information. It automatically selects the appropriate backend based on
-- the operating system.
--
-- = Usage
--
-- @
-- import Data.HardwareInfo
--
-- main :: IO ()
-- main = do
--   result <- getHardwareInfo
--   case result of
--     Left err -> putStrLn $ "Error: " ++ show err
--     Right info -> do
--       putStrLn $ "Manufacturer: " ++ show (platformManufacturer (hwPlatform info))
--       putStrLn $ "Model: " ++ show (platformModel (hwPlatform info))
--       mapM_ print (hwComponents info)
-- @
--
-- = Platform Support
--
-- * __Linux__: Uses sysfs (@\/sys\/class\/dmi\/id\/@) and SMBIOS tables
-- * __Windows__: Uses @GetSystemFirmwareTable@ Win32 API
--

module Data.HardwareInfo
  ( -- * Main function
    getHardwareInfo
    -- * Types (re-exported)
  , HardwareInfo(..)
  , PlatformInfo(..)
  , Component(..)
  , ComponentClass(..)
  , ComponentAddress(..)
  , SmbiosVersion(..)
  , HardwareError(..)
    -- * Component class utilities
  , componentClassToTcgValue
  , componentClassFromTcgValue
  , tcgComponentClassRegistry
    -- * Helper functions
  , emptyHardwareInfo
  , emptyPlatformInfo
  ) where

import Data.HardwareInfo.Types

#if defined(LINUX)
import Data.HardwareInfo.Linux (getLinuxHardwareInfo)
#elif defined(WINDOWS)
import Data.HardwareInfo.Windows (getWindowsHardwareInfo)
#elif defined(darwin_HOST_OS)
import Data.HardwareInfo.Darwin (getDarwinHardwareInfo)
#endif

-- | Collect hardware information from the current system.
--
-- This function automatically selects the appropriate backend based on
-- the operating system the program was compiled for.
--
-- Returns either a 'HardwareError' if collection fails, or 'HardwareInfo'
-- containing all collected hardware information.
--
-- Note: Some information (like serial numbers) may require elevated
-- privileges to access.
getHardwareInfo :: IO (Either HardwareError HardwareInfo)
#if defined(LINUX)
getHardwareInfo = getLinuxHardwareInfo
#elif defined(WINDOWS)
getHardwareInfo = getWindowsHardwareInfo
#elif defined(darwin_HOST_OS)
getHardwareInfo = getDarwinHardwareInfo
#else
getHardwareInfo = return $ Left $ UnsupportedPlatform "This platform is not supported"
#endif
