{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Data.X509.TCG.Util.IanaPen
-- Description : IANA Private Enterprise Number (PEN) lookup for manufacturer OID resolution
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides a static lookup table mapping common hardware manufacturer
-- names to their IANA Private Enterprise Numbers (PEN). The PEN is used to
-- construct the manufacturer OID in the format @1.3.6.1.4.1.{PEN}@, which is
-- the standard IANA PEN OID arc.
--
-- The TCG Platform Certificate Profile uses these OIDs for the
-- @platformManufacturerId@ and @componentManufacturerId@ fields
-- (see IWG Profile v1.1 \S 3.1.2, lines 437-465).

module Data.X509.TCG.Util.IanaPen
  ( -- * Lookup functions
    lookupManufacturerPen
  , lookupManufacturerOid
    -- * Conversion
  , penToOid
    -- * Reverse lookup
  , penToManufacturer
    -- * Table access
  , manufacturerPenTable
  ) where

import Data.List (find)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T

-- | The IANA PEN OID arc prefix.
ianaPenPrefix :: String
ianaPenPrefix = "1.3.6.1.4.1."

-- | Convert a PEN number to a full OID string.
--
-- >>> penToOid 343
-- "1.3.6.1.4.1.343"
penToOid :: Int -> String
penToOid pen = ianaPenPrefix ++ show pen

-- | Look up a manufacturer's IANA PEN by name.
--
-- Performs case-insensitive matching. First tries exact match on the
-- normalized (lowercased) name, then falls back to substring matching
-- against known manufacturer keywords.
--
-- >>> lookupManufacturerPen "Intel Corporation"
-- Just 343
-- >>> lookupManufacturerPen "SAMSUNG"
-- Just 236
-- >>> lookupManufacturerPen "Unknown Vendor"
-- Nothing
lookupManufacturerPen :: Text -> Maybe Int
lookupManufacturerPen name =
  let lower = T.toLower (T.strip name)
  in case Map.lookup lower exactTable of
    Just pen -> Just pen
    Nothing  -> substringLookup lower

-- | Look up a manufacturer's full OID by name.
--
-- >>> lookupManufacturerOid "Dell Inc."
-- Just "1.3.6.1.4.1.674"
lookupManufacturerOid :: Text -> Maybe String
lookupManufacturerOid = fmap penToOid . lookupManufacturerPen

-- | Reverse lookup: get the manufacturer name from a PEN number.
--
-- >>> penToManufacturer 343
-- Just "Intel"
penToManufacturer :: Int -> Maybe Text
penToManufacturer pen = Map.lookup pen reversePenTable

-- | The manufacturer PEN table as an association list.
-- Each entry is @(canonical name, PEN number)@.
manufacturerPenTable :: [(Text, Int)]
manufacturerPenTable =
  [ ("Intel",            343)
  , ("Dell",             674)
  , ("HP",                11)
  , ("HPE",            47196)
  , ("Lenovo",         19046)
  , ("Apple",             63)
  , ("Samsung",          236)
  , ("Broadcom",        4413)
  , ("Qualcomm",        1449)
  , ("NVIDIA",          5703)
  , ("AMD",             3704)
  , ("ASUSTeK",         2623)
  , ("Gigabyte",       15370)
  , ("MSI",             9091)
  , ("Toshiba",          186)
  , ("Western Digital",  5127)
  , ("Seagate",          347)
  , ("Micron",          4525)
  , ("IBM",                2)
  , ("Cisco",              9)
  , ("Supermicro",     10876)
  , ("Fujitsu",          211)
  , ("Acer",            1050)
  , ("Microsoft",        311)
  , ("Huawei",          2011)
  , ("Texas Instruments", 294)
  , ("Marvell",        26696)
  , ("Realtek",        27282)
  , ("Kingston",        1562)
  , ("Sony",             122)
  ]

-- | Exact match table: lowercased canonical name -> PEN
-- Also includes common aliases and full names.
exactTable :: Map Text Int
exactTable = Map.fromList $ concatMap expand manufacturerPenTable
  where
    expand (name, pen) =
      (T.toLower name, pen) : aliases name pen

    aliases :: Text -> Int -> [(Text, Int)]
    aliases "Intel"   pen = [ ("intel corporation", pen) ]
    aliases "Dell"    pen = [ ("dell inc.", pen), ("dell inc", pen)
                            , ("dell technologies", pen) ]
    aliases "HP"      pen = [ ("hewlett-packard", pen), ("hewlett packard", pen)
                            , ("hp inc.", pen), ("hp inc", pen) ]
    aliases "HPE"     pen = [ ("hewlett packard enterprise", pen) ]
    aliases "Lenovo"  pen = [ ("lenovo enterprise business group", pen) ]
    aliases "Apple"   pen = [ ("apple inc.", pen), ("apple inc", pen)
                            , ("apple computer, inc.", pen) ]
    aliases "Samsung" pen = [ ("samsung electronics", pen)
                            , ("samsung electronics co., ltd.", pen) ]
    aliases "Broadcom" pen = [ ("broadcom limited", pen)
                             , ("broadcom inc.", pen), ("broadcom inc", pen) ]
    aliases "Qualcomm" pen = [ ("qualcomm incorporated", pen) ]
    aliases "NVIDIA"  pen = [ ("nvidia corporation", pen) ]
    aliases "AMD"     pen = [ ("advanced micro devices", pen)
                            , ("advanced micro devices, inc.", pen)
                            , ("advanced micro devices, inc", pen) ]
    aliases "ASUSTeK" pen = [ ("asus", pen), ("asustek computer inc.", pen)
                            , ("asustek computer", pen) ]
    aliases "Gigabyte" pen = [ ("giga-byte technology", pen)
                             , ("giga-byte technology co., ltd", pen)
                             , ("gigabyte technology", pen) ]
    aliases "MSI"     pen = [ ("micro-star international", pen)
                            , ("micro-star int'l co., ltd.", pen) ]
    aliases "Toshiba" pen = [ ("toshiba corporation", pen) ]
    aliases "Western Digital" pen = [ ("western digital corporation", pen), ("wdc", pen) ]
    aliases "Seagate" pen = [ ("seagate technology", pen) ]
    aliases "Micron"  pen = [ ("micron technology", pen)
                            , ("micron technology, inc.", pen) ]
    aliases "IBM"     _   = []
    aliases "Cisco"   pen = [ ("ciscosystems", pen), ("cisco systems", pen)
                            , ("cisco systems, inc.", pen) ]
    aliases "Supermicro" pen = [ ("super micro computer", pen)
                               , ("super micro computer inc.", pen) ]
    aliases "Fujitsu" pen = [ ("fujitsu limited", pen) ]
    aliases "Acer"    pen = [ ("acer, inc.", pen), ("acer inc.", pen) ]
    aliases "Microsoft" pen = [ ("microsoft corporation", pen) ]
    aliases "Huawei"  pen = [ ("huawei technology", pen)
                            , ("huawei technologies", pen) ]
    aliases "Texas Instruments" pen = [ ("ti", pen) ]
    aliases "Marvell" pen = [ ("marvell technology", pen)
                            , ("marvell technology inc", pen) ]
    aliases "Realtek" pen = [ ("realtek semiconductor", pen)
                            , ("realtek semiconductor corp.", pen) ]
    aliases "Kingston" pen = [ ("kingston technology", pen)
                             , ("kingston technology company", pen) ]
    aliases "Sony"    pen = [ ("sony corporation", pen) ]
    aliases _         _   = []

-- | Substring-based fallback lookup.
-- Checks if the input contains any known manufacturer keyword.
substringLookup :: Text -> Maybe Int
substringLookup input =
  fmap snd $ find (\(kw, _) -> kw `T.isInfixOf` input) keywords
  where
    keywords :: [(Text, Int)]
    keywords = map (\(n, p) -> (T.toLower n, p)) manufacturerPenTable

-- | Reverse table: PEN -> canonical manufacturer name
reversePenTable :: Map Int Text
reversePenTable = Map.fromList $ map (\(n, p) -> (p, n)) manufacturerPenTable