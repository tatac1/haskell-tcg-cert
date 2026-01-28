{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.Sysfs
-- Description : Linux sysfs interface for hardware information
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to read hardware information from
-- Linux sysfs filesystem.

#ifdef LINUX
module Data.HardwareInfo.Linux.Sysfs
  ( -- * DMI/SMBIOS paths
    dmiIdPath
  , dmiTablesPath
  , smbiosEntryPointPath
    -- * Reading functions
  , readDmiId
  , readSmbiosEntryPoint
  , readSmbiosTable
    -- * PCI device enumeration
  , listPciDevices
  , readPciDeviceInfo
    -- * Network interface enumeration
  , listNetworkInterfaces
  , readNetworkInterfaceMAC
  ) where

import Control.Exception (try, SomeException)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Directory (doesFileExist, doesDirectoryExist, listDirectory)
import System.FilePath ((</>))

-- | Base path for DMI ID information
dmiIdPath :: FilePath
dmiIdPath = "/sys/class/dmi/id"

-- | Path to SMBIOS tables
dmiTablesPath :: FilePath
dmiTablesPath = "/sys/firmware/dmi/tables/DMI"

-- | Path to SMBIOS entry point
smbiosEntryPointPath :: FilePath
smbiosEntryPointPath = "/sys/firmware/dmi/tables/smbios_entry_point"

-- | Read a DMI ID attribute
readDmiId :: Text -> IO (Either Text Text)
readDmiId attr = do
  let path = dmiIdPath </> T.unpack attr
  exists <- doesFileExist path
  if not exists
    then return $ Left $ "File not found: " <> T.pack path
    else do
      result <- try $ TIO.readFile path
      case result of
        Left (e :: SomeException) ->
          return $ Left $ "Error reading " <> attr <> ": " <> T.pack (show e)
        Right content ->
          return $ Right $ sanitize content

-- | Read SMBIOS entry point
readSmbiosEntryPoint :: IO (Either Text ByteString)
readSmbiosEntryPoint = do
  exists <- doesFileExist smbiosEntryPointPath
  if not exists
    then return $ Left "SMBIOS entry point not available"
    else do
      result <- try $ BS.readFile smbiosEntryPointPath
      case result of
        Left (e :: SomeException) ->
          return $ Left $ "Error reading entry point: " <> T.pack (show e)
        Right content ->
          return $ Right content

-- | Read raw SMBIOS table data
readSmbiosTable :: IO (Either Text ByteString)
readSmbiosTable = do
  exists <- doesFileExist dmiTablesPath
  if not exists
    then return $ Left "SMBIOS table not available"
    else do
      result <- try $ BS.readFile dmiTablesPath
      case result of
        Left (e :: SomeException) ->
          return $ Left $ "Error reading SMBIOS table: " <> T.pack (show e)
        Right content ->
          return $ Right content

-- | List PCI devices
listPciDevices :: IO [FilePath]
listPciDevices = do
  let pciPath = "/sys/bus/pci/devices"
  exists <- doesDirectoryExist pciPath
  if not exists
    then return []
    else do
      result <- try $ listDirectory pciPath
      case result of
        Left (_ :: SomeException) -> return []
        Right devices -> return $ map (pciPath </>) devices

-- | Read PCI device vendor and device IDs
readPciDeviceInfo :: FilePath -> IO (Maybe (Text, Text))
readPciDeviceInfo devicePath = do
  vendorResult <- try $ TIO.readFile (devicePath </> "vendor") :: IO (Either SomeException Text)
  deviceResult <- try $ TIO.readFile (devicePath </> "device") :: IO (Either SomeException Text)
  case (vendorResult, deviceResult) of
    (Right vendor, Right device) ->
      return $ Just (sanitize vendor, sanitize device)
    _ -> return Nothing

-- | List network interfaces
listNetworkInterfaces :: IO [Text]
listNetworkInterfaces = do
  let netPath = "/sys/class/net"
  exists <- doesDirectoryExist netPath
  if not exists
    then return []
    else do
      result <- try $ listDirectory netPath
      case result of
        Left (_ :: SomeException) -> return []
        Right ifaces -> return $ map T.pack $ filter (not . isLoopback) ifaces
  where
    isLoopback name = name == "lo"

-- | Read MAC address for a network interface
readNetworkInterfaceMAC :: Text -> IO (Maybe Text)
readNetworkInterfaceMAC iface = do
  let path = "/sys/class/net" </> T.unpack iface </> "address"
  exists <- doesFileExist path
  if not exists
    then return Nothing
    else do
      result <- try $ TIO.readFile path
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right content ->
          let mac = sanitize content
          in if isValidMAC mac
               then return $ Just $ T.toUpper mac
               else return Nothing

-- | Check if MAC address is valid (not all zeros)
isValidMAC :: Text -> Bool
isValidMAC mac =
  not (T.null mac) &&
  mac /= "00:00:00:00:00:00"

-- | Sanitize text (trim whitespace)
sanitize :: Text -> Text
sanitize = T.strip

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Sysfs where
#endif