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
  , getPciAddressFromPath
    -- * Network interface enumeration
  , listNetworkInterfaces
  , readNetworkInterfaceMAC
  , getNetworkInterfacePciAddress
  , getNetworkInterfaceVendorDevice
  , getNetworkInterfaceDriver
  , lookupVendorName
    -- * Ethtool interface
  , getNetworkInterfaceFirmware
  , getNetworkInterfacePermaddr
    -- * WiFi detection
  , isWirelessInterface
  , getWirelessInterfaceInfo
    -- * Cellular modem detection
  , isCellularInterface
  , getCellularModemInfo
    -- * Block device enumeration
  , getBlockDeviceUdevInfo
  , getBlockDeviceWWN
  , getBlockDeviceBusPath
  , getBlockDeviceSerial
    -- * General sysfs utilities
  , readSysfsFile
  , resolveSymlinkToPciAddress
  ) where

import Control.Applicative ((<|>))
import Control.Exception (try, SomeException)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M
import System.Directory (doesFileExist, doesDirectoryExist, listDirectory)
import System.FilePath ((</>), takeFileName, takeDirectory)
import System.Posix.Files (readSymbolicLink)
import System.Process (readProcess)

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

-- | Read a generic sysfs file
readSysfsFile :: FilePath -> IO (Maybe Text)
readSysfsFile path = do
  exists <- doesFileExist path
  if not exists
    then return Nothing
    else do
      result <- try $ TIO.readFile path
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right content -> return $ Just $ sanitize content

-- | Get PCI address from a device path by following symlinks
-- Returns the PCI address (e.g., "0000:00:1f.6")
getPciAddressFromPath :: FilePath -> IO (Maybe Text)
getPciAddressFromPath devicePath = do
  -- Try to read the 'device' symlink which points to the PCI device
  let symlinkPath = devicePath </> "device"
  exists <- doesFileExist symlinkPath
  if not exists
    then return Nothing
    else resolveSymlinkToPciAddress symlinkPath

-- | Resolve a symlink to find the PCI address
resolveSymlinkToPciAddress :: FilePath -> IO (Maybe Text)
resolveSymlinkToPciAddress symlinkPath = do
  result <- try $ readSymbolicLink symlinkPath
  case result of
    Left (_ :: SomeException) -> return Nothing
    Right target -> do
      -- The target might be something like "../../../0000:00:1f.6"
      -- We need to check if it's a PCI bus path
      let resolved = resolveRelativePath (takeDirectory symlinkPath) target
      -- Check if 'subsystem' points to /bus/pci
      let subsystemPath = resolved </> "subsystem"
      subsystemResult <- try $ readSymbolicLink subsystemPath
      case subsystemResult of
        Left (_ :: SomeException) -> return Nothing
        Right subsystemTarget ->
          if "/bus/pci" `T.isSuffixOf` T.pack subsystemTarget
            then return $ Just $ T.pack $ takeFileName resolved
            else return Nothing

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

-- | Get PCI address for a network interface
getNetworkInterfacePciAddress :: Text -> IO (Maybe Text)
getNetworkInterfacePciAddress iface = do
  let netPath = "/sys/class/net" </> T.unpack iface
  -- First check if the device symlink exists
  let deviceLink = netPath </> "device"
  exists <- doesFileExist deviceLink
  if not exists
    then return Nothing
    else do
      result <- try $ readSymbolicLink deviceLink
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right target -> do
          -- Resolve the symlink and check if it's PCI
          let resolved = resolveRelativePath netPath target
          let subsystemPath = resolved </> "subsystem"
          subsystemResult <- try $ readSymbolicLink subsystemPath
          case subsystemResult of
            Left (_ :: SomeException) -> return Nothing
            Right subsystemTarget ->
              if "/bus/pci" `T.isSuffixOf` T.pack subsystemTarget
                then return $ Just $ T.pack $ takeFileName resolved
                else return Nothing

-- | Get PCI vendor and device IDs for a network interface
-- Returns (vendorId, deviceId) e.g. ("0x8086", "0x15b8")
getNetworkInterfaceVendorDevice :: Text -> IO (Maybe (Text, Text))
getNetworkInterfaceVendorDevice iface = do
  let basePath = "/sys/class/net" </> T.unpack iface </> "device"
  vendorResult <- readSysfsFile (basePath </> "vendor")
  deviceResult <- readSysfsFile (basePath </> "device")
  case (vendorResult, deviceResult) of
    (Just vendor, Just device) ->
      return $ Just (vendor, device)
    _ -> return Nothing

-- | Get driver name for a network interface
getNetworkInterfaceDriver :: Text -> IO (Maybe Text)
getNetworkInterfaceDriver iface = do
  let driverPath = "/sys/class/net" </> T.unpack iface </> "device" </> "driver"
  result <- try $ readSymbolicLink driverPath
  case result of
    Left (_ :: SomeException) -> return Nothing
    Right target -> return $ Just $ T.pack $ takeFileName target

-- | Lookup vendor name from PCI vendor ID
-- Maps common PCI vendor IDs to human-readable names
lookupVendorName :: Text -> Text
lookupVendorName vendorId =
  case T.toLower vendorId of
    "0x8086" -> "Intel Corporation"
    "0x10de" -> "NVIDIA Corporation"
    "0x1022" -> "Advanced Micro Devices, Inc. [AMD]"
    "0x1002" -> "Advanced Micro Devices, Inc. [AMD/ATI]"
    "0x14e4" -> "Broadcom Inc."
    "0x8087" -> "Intel Corporation"
    "0x10ec" -> "Realtek Semiconductor Co., Ltd."
    "0x168c" -> "Qualcomm Atheros"
    "0x1969" -> "Qualcomm Atheros"
    "0x15b3" -> "Mellanox Technologies"
    "0x1077" -> "QLogic Corp."
    "0x19a2" -> "Emulex Corporation"
    "0x1137" -> "Cisco Systems Inc"
    "0x1d6a" -> "Aquantia Corp."
    "0x1425" -> "Chelsio Communications Inc"
    "0x15ad" -> "VMware"
    "0x1af4" -> "Red Hat, Inc. (virtio)"
    "0x1ab8" -> "Parallels, Inc."
    "0x80ee" -> "Oracle Corporation (VirtualBox)"
    "0x5853" -> "XenSource, Inc."
    "0x1c5c" -> "SK Hynix"
    "0x144d" -> "Samsung Electronics Co Ltd"
    "0x1179" -> "Toshiba Corporation"
    "0x1987" -> "Phison Electronics Corporation"
    "0x126f" -> "Silicon Motion, Inc."
    "0x1cc1" -> "ADATA Technology Co., Ltd."
    "0x2646" -> "Kingston Technology Company, Inc."
    "0xc0a9" -> "Micron/Crucial Technology"
    "0x1c5f" -> "Memblaze Technology Co., Ltd."
    "0x1e0f" -> "KIOXIA Corporation"
    _ -> ""

-- | Get firmware version for a network interface using ethtool
-- Parses output of "ethtool -i <iface>" for firmware-version field
getNetworkInterfaceFirmware :: Text -> IO (Maybe Text)
getNetworkInterfaceFirmware iface = do
  result <- try $ readProcess "ethtool" ["-i", T.unpack iface] ""
  case result of
    Left (_ :: SomeException) -> return Nothing
    Right output ->
      return $ parseEthtoolField "firmware-version:" (T.pack output)

-- | Get permanent MAC address for a network interface using ethtool
-- This can serve as a stable identifier (serial-like) for NICs
-- Parses output of "ethtool -P <iface>"
getNetworkInterfacePermaddr :: Text -> IO (Maybe Text)
getNetworkInterfacePermaddr iface = do
  result <- try $ readProcess "ethtool" ["-P", T.unpack iface] ""
  case result of
    Left (_ :: SomeException) -> return Nothing
    Right output ->
      -- Output format: "Permanent address: XX:XX:XX:XX:XX:XX"
      let text = T.strip $ T.pack output
      in if "Permanent address:" `T.isPrefixOf` text
           then let addr = T.strip $ T.drop (T.length "Permanent address:") text
                in if isValidMAC addr && addr /= "00:00:00:00:00:00"
                     then return $ Just $ T.toUpper addr
                     else return Nothing
           else return Nothing

-- | Parse a field from ethtool output
parseEthtoolField :: Text -> Text -> Maybe Text
parseEthtoolField fieldName output =
  let lines' = T.lines output
      matchingLines = filter (T.isPrefixOf fieldName) $ map T.strip lines'
  in case matchingLines of
       (line:_) ->
         let value = T.strip $ T.drop (T.length fieldName) line
         in if T.null value || value == "N/A" || value == "n/a"
              then Nothing
              else Just value
       [] -> Nothing

-- | Check if a network interface is wireless (WiFi)
-- Wireless interfaces have a /sys/class/net/{iface}/wireless directory
isWirelessInterface :: Text -> IO Bool
isWirelessInterface iface = do
  let wirelessPath = "/sys/class/net" </> T.unpack iface </> "wireless"
  doesDirectoryExist wirelessPath

-- | Get wireless interface information
-- Returns (phy name, type) if available
getWirelessInterfaceInfo :: Text -> IO (Maybe Text, Maybe Text)
getWirelessInterfaceInfo iface = do
  isWireless <- isWirelessInterface iface
  if not isWireless
    then return (Nothing, Nothing)
    else do
      -- Try to get phy name from /sys/class/net/{iface}/phy80211/name
      let phyNamePath = "/sys/class/net" </> T.unpack iface </> "phy80211" </> "name"
      phyName <- readSysfsFile phyNamePath
      -- Try to get interface type from iw command or sysfs
      let typePath = "/sys/class/net" </> T.unpack iface </> "type"
      ifType <- readSysfsFile typePath
      return (phyName, ifType)

-- | Check if a network interface is a cellular modem (WWAN)
-- WWAN interfaces typically have names like wwan*, wwp*, or are in
-- @\/sys\/class\/net\/{iface}\/device\/subsystem@ pointing to wwan
isCellularInterface :: Text -> IO Bool
isCellularInterface iface = do
  -- Check by name prefix (wwan*, wwp*)
  let nameMatches = "wwan" `T.isPrefixOf` iface || "wwp" `T.isPrefixOf` iface

  if nameMatches
    then return True
    else do
      -- Check subsystem
      let subsystemPath = "/sys/class/net" </> T.unpack iface </> "device" </> "subsystem"
      result <- try $ readSymbolicLink subsystemPath
      case result of
        Left (_ :: SomeException) -> return False
        Right target -> return $ "wwan" `T.isInfixOf` T.pack target ||
                                  "usb" `T.isInfixOf` T.pack target &&
                                  ("wwan" `T.isPrefixOf` iface || "wwp" `T.isPrefixOf` iface)

-- | Get cellular modem information
-- Returns (manufacturer, model, technology) if available
-- Technology: 3G, 4G/LTE, 5G/NR
getCellularModemInfo :: Text -> IO (Maybe Text, Maybe Text, Maybe Text)
getCellularModemInfo iface = do
  isCellular <- isCellularInterface iface
  if not isCellular
    then return (Nothing, Nothing, Nothing)
    else do
      -- Try to get device info from parent USB device
      let devicePath = "/sys/class/net" </> T.unpack iface </> "device"

      -- Read manufacturer and model from USB device
      manufacturer <- readSysfsFile (devicePath </> "manufacturer")
                  <|> readSysfsFile (devicePath </> "../manufacturer")
      model <- readSysfsFile (devicePath </> "product")
           <|> readSysfsFile (devicePath </> "../product")

      -- Try to determine technology from model name
      let technology = case model of
            Just m -> detectCellularTechnology m
            Nothing -> Nothing

      return (manufacturer, model, technology)
  where
    (<|>) :: IO (Maybe a) -> IO (Maybe a) -> IO (Maybe a)
    a <|> b = do
      r <- a
      case r of
        Just _ -> return r
        Nothing -> b

    detectCellularTechnology :: Text -> Maybe Text
    detectCellularTechnology model =
      let modelLower = T.toLower model
      in case () of
           _ | "5g" `T.isInfixOf` modelLower -> Just "5G"
             | "nr" `T.isInfixOf` modelLower -> Just "5G"
             | "lte" `T.isInfixOf` modelLower -> Just "4G"
             | "4g" `T.isInfixOf` modelLower -> Just "4G"
             | "hspa" `T.isInfixOf` modelLower -> Just "3G"
             | "3g" `T.isInfixOf` modelLower -> Just "3G"
             | "wcdma" `T.isInfixOf` modelLower -> Just "3G"
             | otherwise -> Nothing

-- | Read udev info for a block device
-- Returns a map of key-value pairs from /run/udev/data/
getBlockDeviceUdevInfo :: Text -> IO (Map Text Text)
getBlockDeviceUdevInfo deviceName = do
  -- First get the major:minor numbers from /sys/block/{device}/dev
  let devPath = "/sys/block" </> T.unpack deviceName </> "dev"
  devNoResult <- readSysfsFile devPath
  case devNoResult of
    Nothing -> return M.empty
    Just devNo -> do
      -- Look up in udev database
      let udevId = "b" <> T.strip devNo
      let udevPath = "/run/udev/data" </> T.unpack udevId
      exists <- doesFileExist udevPath
      if not exists
        then return M.empty
        else do
          result <- try $ TIO.readFile udevPath
          case result of
            Left (_ :: SomeException) -> return M.empty
            Right content -> return $ parseUdevData content

-- | Parse udev data file content
parseUdevData :: Text -> Map Text Text
parseUdevData content = M.fromList $ concatMap parseLine $ T.lines content
  where
    parseLine line
      | "E:" `T.isPrefixOf` line =
          case T.breakOn "=" (T.drop 2 line) of
            (key, value)
              | not (T.null value) -> [(key, T.drop 1 value)]  -- drop the '='
              | otherwise -> []
      | otherwise = []

-- | Get World Wide Name for a block device
getBlockDeviceWWN :: Text -> IO (Maybe Text)
getBlockDeviceWWN deviceName = do
  info <- getBlockDeviceUdevInfo deviceName
  -- Try ID_WWN_WITH_EXTENSION first, then ID_WWN, then DM_WWN
  return $ M.lookup "ID_WWN_WITH_EXTENSION" info
       <|> M.lookup "ID_WWN" info
       <|> M.lookup "DM_WWN" info

-- | Get bus path for a block device (SATA/SAS path)
getBlockDeviceBusPath :: Text -> IO (Maybe Text)
getBlockDeviceBusPath deviceName = do
  info <- getBlockDeviceUdevInfo deviceName
  return $ M.lookup "ID_PATH" info

-- | Get serial number for a block device
getBlockDeviceSerial :: Text -> IO (Maybe Text)
getBlockDeviceSerial deviceName = do
  info <- getBlockDeviceUdevInfo deviceName
  -- Try multiple serial keys in order of preference
  return $ M.lookup "SCSI_IDENT_SERIAL" info
       <|> M.lookup "ID_SCSI_SERIAL" info
       <|> M.lookup "ID_SERIAL_SHORT" info
       <|> M.lookup "ID_SERIAL" info

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Sysfs
  ( dmiIdPath
  , dmiTablesPath
  , smbiosEntryPointPath
  , readDmiId
  , readSmbiosEntryPoint
  , readSmbiosTable
  , listPciDevices
  , readPciDeviceInfo
  , getPciAddressFromPath
  , listNetworkInterfaces
  , readNetworkInterfaceMAC
  , getNetworkInterfacePciAddress
  , getNetworkInterfaceVendorDevice
  , getNetworkInterfaceDriver
  , lookupVendorName
  , getNetworkInterfaceFirmware
  , getNetworkInterfacePermaddr
  , isWirelessInterface
  , getWirelessInterfaceInfo
  , isCellularInterface
  , getCellularModemInfo
  , getBlockDeviceUdevInfo
  , getBlockDeviceWWN
  , getBlockDeviceBusPath
  , getBlockDeviceSerial
  , readSysfsFile
  , resolveSymlinkToPciAddress
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M

dmiIdPath :: FilePath
dmiIdPath = "/sys/class/dmi/id"

dmiTablesPath :: FilePath
dmiTablesPath = "/sys/firmware/dmi/tables/DMI"

smbiosEntryPointPath :: FilePath
smbiosEntryPointPath = "/sys/firmware/dmi/tables/smbios_entry_point"

readDmiId :: Text -> IO (Either Text Text)
readDmiId _ = return $ Left "Not supported on this platform"

readSmbiosEntryPoint :: IO (Either Text ByteString)
readSmbiosEntryPoint = return $ Left "Not supported on this platform"

readSmbiosTable :: IO (Either Text ByteString)
readSmbiosTable = return $ Left "Not supported on this platform"

listPciDevices :: IO [FilePath]
listPciDevices = return []

readPciDeviceInfo :: FilePath -> IO (Maybe (Text, Text, Text))
readPciDeviceInfo _ = return Nothing

getPciAddressFromPath :: FilePath -> IO (Maybe Text)
getPciAddressFromPath _ = return Nothing

listNetworkInterfaces :: IO [Text]
listNetworkInterfaces = return []

readNetworkInterfaceMAC :: Text -> IO (Maybe Text)
readNetworkInterfaceMAC _ = return Nothing

getNetworkInterfacePciAddress :: Text -> IO (Maybe Text)
getNetworkInterfacePciAddress _ = return Nothing

getNetworkInterfaceVendorDevice :: Text -> IO (Maybe (Text, Text))
getNetworkInterfaceVendorDevice _ = return Nothing

getNetworkInterfaceDriver :: Text -> IO (Maybe Text)
getNetworkInterfaceDriver _ = return Nothing

lookupVendorName :: Text -> Text
lookupVendorName _ = ""

getNetworkInterfaceFirmware :: Text -> IO (Maybe Text)
getNetworkInterfaceFirmware _ = return Nothing

getNetworkInterfacePermaddr :: Text -> IO (Maybe Text)
getNetworkInterfacePermaddr _ = return Nothing

isWirelessInterface :: Text -> IO Bool
isWirelessInterface _ = return False

getWirelessInterfaceInfo :: Text -> IO (Maybe Text, Maybe Text)
getWirelessInterfaceInfo _ = return (Nothing, Nothing)

isCellularInterface :: Text -> IO Bool
isCellularInterface _ = return False

getCellularModemInfo :: Text -> IO (Maybe Text, Maybe Text, Maybe Text)
getCellularModemInfo _ = return (Nothing, Nothing, Nothing)

getBlockDeviceUdevInfo :: Text -> IO (Map Text Text)
getBlockDeviceUdevInfo _ = return M.empty

getBlockDeviceWWN :: Text -> IO (Maybe Text)
getBlockDeviceWWN _ = return Nothing

getBlockDeviceBusPath :: Text -> IO (Maybe Text)
getBlockDeviceBusPath _ = return Nothing

getBlockDeviceSerial :: Text -> IO (Maybe Text)
getBlockDeviceSerial _ = return Nothing

readSysfsFile :: FilePath -> IO (Maybe Text)
readSysfsFile _ = return Nothing

resolveSymlinkToPciAddress :: FilePath -> IO (Maybe Text)
resolveSymlinkToPciAddress _ = return Nothing
#endif
