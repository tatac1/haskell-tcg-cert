{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.PciIds
-- Description : PCI ID database for vendor and device name resolution
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to resolve PCI vendor and device IDs to
-- human-readable names using the pci.ids database. The database is embedded
-- in the binary at compile time and can be overridden by a runtime file
-- from /usr/share/hwdata/pci.ids (preferred if available, as it may be newer).

#ifdef LINUX
module Data.HardwareInfo.Linux.PciIds
  ( -- * PCI ID database
    PciIdDb
  , loadPciIdDb
    -- * Lookup functions (use global cached database)
  , lookupVendorById
  , lookupDeviceById
  , lookupVendorByIdText
  ) where

import Control.Exception (try, SomeException)
import Data.FileEmbed (embedFile)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import Data.Word (Word16)
import Numeric (readHex)
import System.Directory (doesFileExist)
import System.IO.Unsafe (unsafePerformIO)

-- | PCI ID database containing vendor and device name mappings
data PciIdDb = PciIdDb
  { pciVendors :: !(Map Word16 Text)
    -- ^ Vendor ID -> Vendor Name
  , pciDevices :: !(Map (Word16, Word16) Text)
    -- ^ (Vendor ID, Device ID) -> Device Name
  } deriving (Show)

-- | Embedded pci.ids database (compiled into the binary)
embeddedPciIds :: Text
embeddedPciIds = TE.decodeUtf8 $(embedFile "data/pci.ids")

-- | Runtime paths for pci.ids (preferred over embedded if available)
runtimePciIdsPaths :: [FilePath]
runtimePciIdsPaths =
  [ "/usr/share/hwdata/pci.ids"
  , "/usr/share/misc/pci.ids"
  , "/usr/share/pci.ids"
  ]

-- | Load PCI ID database.
-- Tries runtime files first (may be more up-to-date), falls back to embedded data.
loadPciIdDb :: IO PciIdDb
loadPciIdDb = do
  runtimeDb <- tryRuntimePaths runtimePciIdsPaths
  case runtimeDb of
    Just db -> return db
    Nothing -> return $ parsePciIds embeddedPciIds
  where
    tryRuntimePaths [] = return Nothing
    tryRuntimePaths (p:ps) = do
      exists <- doesFileExist p
      if exists
        then do
          result <- try $ TIO.readFile p
          case result of
            Right content -> return $ Just $ parsePciIds content
            Left (_ :: SomeException) -> tryRuntimePaths ps
        else tryRuntimePaths ps

-- | Global cached PCI ID database (loaded once, reused across all lookups)
{-# NOINLINE globalPciIdDb #-}
globalPciIdDb :: PciIdDb
globalPciIdDb = unsafePerformIO loadPciIdDb

-- | Lookup vendor name by numeric vendor ID
-- Returns empty text if not found
lookupVendorById :: Word16 -> Text
lookupVendorById vid =
  case M.lookup vid (pciVendors globalPciIdDb) of
    Just name -> name
    Nothing   -> ""

-- | Lookup device name by numeric vendor and device IDs
-- Returns empty text if not found
lookupDeviceById :: Word16 -> Word16 -> Text
lookupDeviceById vid did =
  case M.lookup (vid, did) (pciDevices globalPciIdDb) of
    Just name -> name
    Nothing   -> ""

-- | Lookup vendor name from text vendor ID (e.g., "0x8086")
-- Parses the hex string and looks up in the database
lookupVendorByIdText :: Text -> Text
lookupVendorByIdText vendorIdText =
  let hexStr = if "0x" `T.isPrefixOf` T.toLower vendorIdText
                 then T.drop 2 vendorIdText
                 else vendorIdText
  in case readHex (T.unpack hexStr) of
       [(v, "")] -> lookupVendorById (fromIntegral (v :: Integer))
       _         -> ""

-- | Parse pci.ids file content into a PciIdDb
--
-- Format:
--   vendor_id  vendor_name
--   \tdevice_id  device_name
--   \t\tsubvendor subdevice  subsystem_name  (ignored)
parsePciIds :: Text -> PciIdDb
parsePciIds content =
  let ls = T.lines content
      (vendors, devices) = go Nothing M.empty M.empty ls
  in PciIdDb vendors devices
  where
    go _ vendors devices [] = (vendors, devices)
    go currentVendor vendors devices (line:rest)
      -- Skip comments and empty lines
      | T.null line = go currentVendor vendors devices rest
      | T.head line == '#' = go currentVendor vendors devices rest
      -- Subsystem line (two tabs) - skip
      | "\t\t" `T.isPrefixOf` line = go currentVendor vendors devices rest
      -- Device line (one tab)
      | "\t" `T.isPrefixOf` line =
          case currentVendor of
            Nothing -> go currentVendor vendors devices rest
            Just vid ->
              case parseDeviceLine (T.drop 1 line) of
                Just (did, name) ->
                  go currentVendor vendors (M.insert (vid, did) name devices) rest
                Nothing -> go currentVendor vendors devices rest
      -- Vendor line (no tab, starts with hex)
      | otherwise =
          case parseVendorLine line of
            Just (vid, name) ->
              go (Just vid) (M.insert vid name vendors) devices rest
            Nothing -> go currentVendor vendors devices rest

    parseVendorLine :: Text -> Maybe (Word16, Text)
    parseVendorLine line =
      let (hexPart, rest) = T.break (== ' ') line
      in case parseHexId hexPart of
           Just vid -> Just (vid, T.strip (T.drop 1 rest))
           Nothing -> Nothing

    parseDeviceLine :: Text -> Maybe (Word16, Text)
    parseDeviceLine line =
      let (hexPart, rest) = T.break (== ' ') line
      in case parseHexId hexPart of
           Just did -> Just (did, T.strip (T.drop 1 rest))
           Nothing -> Nothing

    parseHexId :: Text -> Maybe Word16
    parseHexId t =
      case readHex (T.unpack t) of
        [(v, "")] -> Just (fromIntegral (v :: Integer))
        _ -> Nothing

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.PciIds
  ( PciIdDb
  , loadPciIdDb
  , lookupVendorById
  , lookupDeviceById
  , lookupVendorByIdText
  ) where

import Data.Text (Text)
import Data.Word (Word16)

data PciIdDb = PciIdDb deriving (Show)

loadPciIdDb :: IO PciIdDb
loadPciIdDb = return PciIdDb

lookupVendorById :: Word16 -> Text
lookupVendorById _ = ""

lookupDeviceById :: Word16 -> Word16 -> Text
lookupDeviceById _ _ = ""

lookupVendorByIdText :: Text -> Text
lookupVendorByIdText _ = ""
#endif