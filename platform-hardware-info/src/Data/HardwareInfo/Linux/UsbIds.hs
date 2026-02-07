{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.UsbIds
-- Description : USB ID database for vendor and device name resolution
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to resolve USB vendor and product IDs to
-- human-readable names using the usb.ids database. The database is embedded
-- in the binary at compile time and can be overridden by a runtime file
-- from /usr/share/hwdata/usb.ids (preferred if available, as it may be newer).

#ifdef LINUX
module Data.HardwareInfo.Linux.UsbIds
  ( -- * USB ID database
    UsbIdDb
  , loadUsbIdDb
    -- * Lookup functions (use global cached database)
  , lookupUsbVendorById
  , lookupUsbProductById
  , lookupUsbVendorByIdText
  , lookupUsbProductByIdText
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

-- | USB ID database containing vendor and product name mappings
data UsbIdDb = UsbIdDb
  { usbVendors  :: !(Map Word16 Text)
    -- ^ Vendor ID -> Vendor Name
  , usbProducts :: !(Map (Word16, Word16) Text)
    -- ^ (Vendor ID, Product ID) -> Product Name
  } deriving (Show)

-- | Embedded usb.ids database (compiled into the binary)
embeddedUsbIds :: Text
embeddedUsbIds = TE.decodeUtf8 $(embedFile "data/usb.ids")

-- | Runtime paths for usb.ids (preferred over embedded if available)
runtimeUsbIdsPaths :: [FilePath]
runtimeUsbIdsPaths =
  [ "/usr/share/hwdata/usb.ids"
  , "/usr/share/misc/usb.ids"
  , "/usr/share/usb.ids"
  ]

-- | Load USB ID database.
-- Tries runtime files first (may be more up-to-date), falls back to embedded data.
loadUsbIdDb :: IO UsbIdDb
loadUsbIdDb = do
  runtimeDb <- tryRuntimePaths runtimeUsbIdsPaths
  case runtimeDb of
    Just db -> return db
    Nothing -> return $ parseUsbIds embeddedUsbIds
  where
    tryRuntimePaths [] = return Nothing
    tryRuntimePaths (p:ps) = do
      exists <- doesFileExist p
      if exists
        then do
          result <- try $ TIO.readFile p
          case result of
            Right content -> return $ Just $ parseUsbIds content
            Left (_ :: SomeException) -> tryRuntimePaths ps
        else tryRuntimePaths ps

-- | Global cached USB ID database (loaded once, reused across all lookups)
{-# NOINLINE globalUsbIdDb #-}
globalUsbIdDb :: UsbIdDb
globalUsbIdDb = unsafePerformIO loadUsbIdDb

-- | Lookup vendor name by numeric vendor ID
lookupUsbVendorById :: Word16 -> Text
lookupUsbVendorById vid =
  case M.lookup vid (usbVendors globalUsbIdDb) of
    Just name -> name
    Nothing   -> ""

-- | Lookup product name by numeric vendor and product IDs
lookupUsbProductById :: Word16 -> Word16 -> Text
lookupUsbProductById vid pid =
  case M.lookup (vid, pid) (usbProducts globalUsbIdDb) of
    Just name -> name
    Nothing   -> ""

-- | Lookup vendor name from text vendor ID (e.g., "0bda" or "0x0bda")
lookupUsbVendorByIdText :: Text -> Text
lookupUsbVendorByIdText vendorIdText =
  let hexStr = if "0x" `T.isPrefixOf` T.toLower vendorIdText
                 then T.drop 2 vendorIdText
                 else vendorIdText
  in case readHex (T.unpack hexStr) of
       [(v, "")] -> lookupUsbVendorById (fromIntegral (v :: Integer))
       _         -> ""

-- | Lookup product name from text vendor and product IDs
lookupUsbProductByIdText :: Text -> Text -> Text
lookupUsbProductByIdText vendorIdText productIdText =
  let parseId t = let hexStr = if "0x" `T.isPrefixOf` T.toLower t
                                 then T.drop 2 t
                                 else t
                  in case readHex (T.unpack hexStr) of
                       [(v, "")] -> Just (fromIntegral (v :: Integer) :: Word16)
                       _         -> Nothing
  in case (parseId vendorIdText, parseId productIdText) of
       (Just vid, Just pid) -> lookupUsbProductById vid pid
       _                    -> ""

-- | Parse usb.ids file content into a UsbIdDb
--
-- Format (same as pci.ids):
--   vendor_id  vendor_name
--   \tproduct_id  product_name
--   \t\tinterface  interface_name  (ignored)
parseUsbIds :: Text -> UsbIdDb
parseUsbIds content =
  let ls = T.lines content
      (vendors, products) = go Nothing M.empty M.empty ls
  in UsbIdDb vendors products
  where
    go _ vendors products [] = (vendors, products)
    go currentVendor vendors products (line:rest)
      | T.null line = go currentVendor vendors products rest
      | T.head line == '#' = go currentVendor vendors products rest
      -- Interface line (two tabs) or class definitions - skip
      | "\t\t" `T.isPrefixOf` line = go currentVendor vendors products rest
      -- Product line (one tab)
      | "\t" `T.isPrefixOf` line =
          case currentVendor of
            Nothing -> go currentVendor vendors products rest
            Just vid ->
              case parseProductLine (T.drop 1 line) of
                Just (pid, name) ->
                  go currentVendor vendors (M.insert (vid, pid) name products) rest
                Nothing -> go currentVendor vendors products rest
      -- Vendor line (no tab, starts with hex)
      | otherwise =
          case parseVendorLine line of
            Just (vid, name) ->
              go (Just vid) (M.insert vid name vendors) products rest
            Nothing -> go currentVendor vendors products rest

    parseVendorLine :: Text -> Maybe (Word16, Text)
    parseVendorLine line =
      let (hexPart, rest) = T.break (== ' ') line
      in case parseHexId hexPart of
           Just vid -> Just (vid, T.strip (T.drop 1 rest))
           Nothing -> Nothing

    parseProductLine :: Text -> Maybe (Word16, Text)
    parseProductLine line =
      let (hexPart, rest) = T.break (== ' ') line
      in case parseHexId hexPart of
           Just pid -> Just (pid, T.strip (T.drop 1 rest))
           Nothing -> Nothing

    parseHexId :: Text -> Maybe Word16
    parseHexId t =
      case readHex (T.unpack t) of
        [(v, "")] -> Just (fromIntegral (v :: Integer))
        _ -> Nothing

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.UsbIds
  ( UsbIdDb
  , loadUsbIdDb
  , lookupUsbVendorById
  , lookupUsbProductById
  , lookupUsbVendorByIdText
  , lookupUsbProductByIdText
  ) where

import Data.Text (Text)
import Data.Word (Word16)

data UsbIdDb = UsbIdDb deriving (Show)

loadUsbIdDb :: IO UsbIdDb
loadUsbIdDb = return UsbIdDb

lookupUsbVendorById :: Word16 -> Text
lookupUsbVendorById _ = ""

lookupUsbProductById :: Word16 -> Word16 -> Text
lookupUsbProductById _ _ = ""

lookupUsbVendorByIdText :: Text -> Text
lookupUsbVendorByIdText _ = ""

lookupUsbProductByIdText :: Text -> Text -> Text
lookupUsbProductByIdText _ _ = ""
#endif