{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Util.ASN1
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Utility
-- Stability   : experimental
-- Portability : unknown
--
-- ASN.1 utilities for TCG Platform Certificate analysis and display.
-- This module provides functions for parsing, analyzing, and pretty-printing ASN.1 structures.
module Data.X509.TCG.Util.ASN1
  ( -- * ASN.1 Display
    showASN1,
    analyzeBasicCertificateInfo,
    validateBasicASN1Structure,
    validateASN1Elements,

    -- * ASN.1 Analysis
    extractComponentsFromASN1,
    findPlatformAttributes,
    findOctetStringsInASN1,

    -- * Utility Functions
    hexdump,
    isAsciiPrintable,
  )
where

import Control.Monad (when)
import Data.ASN1.BitArray
import Data.ASN1.Types
import qualified Data.ByteString as B
import Data.Maybe (mapMaybe)
import Data.Word
import Data.X509.TCG.Util.OID (formatOIDWithName)
import Numeric (showHex)

-- | Convert ByteString to hex string
hexdump :: B.ByteString -> String
hexdump bs = concatMap hex $ B.unpack bs
  where
    hex n
      | n > 0xf = showHex n ""
      | otherwise = "0" ++ showHex n ""

-- | Check if a byte is ASCII printable
isAsciiPrintable :: Word8 -> Bool
isAsciiPrintable w = w >= 32 && w <= 126

-- | Show ASN.1 structures with proper indentation (based on x509-util)
showASN1 :: Int -> [ASN1] -> IO ()
showASN1 at = prettyPrint at
  where
    indent n = putStr (replicate n ' ')

    prettyPrint _ [] = return ()
    prettyPrint n (x@(Start _) : xs) = indent n >> p x >> putStrLn "" >> prettyPrint (n + 1) xs
    prettyPrint n (x@(End _) : xs) = indent (n - 1) >> p x >> putStrLn "" >> prettyPrint (n - 1) xs
    prettyPrint n (x : xs) = indent n >> p x >> putStrLn "" >> prettyPrint n xs

    p (Boolean b) = putStr ("bool: " ++ show b)
    p (IntVal i) = putStr ("int: " ++ showHex i "")
    p (BitString bits) = putStr ("bitstring: " ++ (hexdump $ bitArrayGetData bits))
    p (OctetString bs) = putStr ("octetstring: " ++ hexdump bs)
    p (Null) = putStr "null"
    p (OID is) = putStr ("OID: " ++ formatOIDWithName is)
    p (Real _) = putStr "real"
    p (Enumerated _) = putStr "enum"
    p (Start Sequence) = putStr "{"
    p (End Sequence) = putStr "}"
    p (Start Set) = putStr "["
    p (End Set) = putStr "]"
    p (Start (Container x y)) = putStr ("< " ++ show x ++ " " ++ show y)
    p (End (Container x y)) = putStr ("> " ++ show x ++ " " ++ show y)
    p (ASN1String cs) = putCS cs
    p (ASN1Time TimeUTC time _) = putStr ("utctime: " ++ show time)
    p (ASN1Time TimeGeneralized time _) = putStr ("generalizedtime: " ++ show time)
    p (Other tc tn _) = putStr ("other(" ++ show tc ++ "," ++ show tn ++ ")")

    putCS (ASN1CharacterString UTF8 t) = putStr ("utf8string:" ++ show t)
    putCS (ASN1CharacterString Numeric _) = putStr "numericstring:"
    putCS (ASN1CharacterString Printable t) = putStr ("printablestring: " ++ show t)
    putCS (ASN1CharacterString T61 bs) = putStr ("t61string:" ++ show bs)
    putCS (ASN1CharacterString VideoTex _) = putStr "videotexstring:"
    putCS (ASN1CharacterString IA5 bs) = putStr ("ia5string:" ++ show bs)
    putCS (ASN1CharacterString Graphic _) = putStr "graphicstring:"
    putCS (ASN1CharacterString Visible _) = putStr "visiblestring:"
    putCS (ASN1CharacterString General _) = putStr "generalstring:"
    putCS (ASN1CharacterString UTF32 t) = putStr ("universalstring:" ++ show t)
    putCS (ASN1CharacterString Character _) = putStr "characterstring:"
    putCS (ASN1CharacterString BMP t) = putStr ("bmpstring: " ++ show t)

-- | Analyze basic certificate information from ASN.1 structure
analyzeBasicCertificateInfo :: [ASN1] -> IO ()
analyzeBasicCertificateInfo asn1 = do
  putStrLn "Basic Certificate Analysis:"

  -- Look for version information
  case findVersion asn1 of
    Just version -> putStrLn $ "  Version: " ++ show version
    Nothing -> putStrLn "  Version: Not found"

  -- Look for serial number
  case findSerial asn1 of
    Just serial -> putStrLn $ "  Serial Number: " ++ show serial
    Nothing -> putStrLn "  Serial Number: Not found"

  -- Look for OctetString attributes (likely platform info)
  let octetStrings = findOctetStringsInASN1 asn1
  when (not $ null octetStrings) $ do
    putStrLn "  Platform Attributes:"
    mapM_ (\(i, bs) -> putStrLn $ "    [" ++ show (i :: Int) ++ "] " ++ show bs) (zip [1 ..] (take 10 octetStrings))
    when (length octetStrings > 10) $
      putStrLn $
        "    ... and " ++ show (length octetStrings - 10) ++ " more"
  where
    findVersion :: [ASN1] -> Maybe Integer
    findVersion (IntVal i : _) = Just i
    findVersion (_ : rest) = findVersion rest
    findVersion [] = Nothing

    findSerial :: [ASN1] -> Maybe Integer
    findSerial (IntVal _ : IntVal serial : _) = Just serial
    findSerial (_ : rest) = findSerial rest
    findSerial [] = Nothing

-- | Validate basic ASN.1 structure
validateBasicASN1Structure :: [ASN1] -> Bool -> IO ()
validateBasicASN1Structure asn1 verbose = do
  putStrLn "=== BASIC ASN.1 VALIDATION ==="
  putStrLn ""

  -- Check if ASN.1 structure is valid
  putStrLn "1. ASN.1 Structure Check:"
  putStrLn "   PASSED: ASN.1 parsing successful"

  -- Look for basic certificate elements
  putStrLn ""
  putStrLn "2. Certificate Elements Check:"
  validateASN1Elements asn1

  when verbose $ do
    putStrLn ""
    putStrLn "3. Detailed ASN.1 Analysis:"
    putStrLn $ "   - Total ASN.1 elements: " ++ show (length asn1)
    putStrLn $ "   - OctetString count: " ++ show (length $ findOctetStringsInASN1 asn1)
    putStrLn $ "   - OID count: " ++ show (length $ findOIDs asn1)
  where
    findOIDs :: [ASN1] -> [OID]
    findOIDs [] = []
    findOIDs (OID oid : rest) = oid : findOIDs rest
    findOIDs (_ : rest) = findOIDs rest

-- | Validate ASN.1 elements
validateASN1Elements :: [ASN1] -> IO ()
validateASN1Elements asn1 = do
  let hasSequence = any isSequenceStart asn1
      hasVersion = any isVersion asn1
      hasOctetStrings = not $ null $ findOctetStringsInASN1 asn1

  putStrLn $ "   Sequence structure: " ++ if hasSequence then " PASSED" else " FAILED"
  putStrLn $ "   Version field: " ++ if hasVersion then " PASSED" else " FAILED"
  putStrLn $ "   Attribute data: " ++ if hasOctetStrings then " PASSED" else " FAILED"
  where
    isSequenceStart (Start Sequence) = True
    isSequenceStart _ = False

    isVersion (IntVal _) = True
    isVersion _ = False

-- | Extract components from raw ASN.1 structure
extractComponentsFromASN1 :: [ASN1] -> Bool -> IO ()
extractComponentsFromASN1 asn1 verbose = do
  putStrLn "Component Analysis from ASN.1 Structure:"
  putStrLn ""

  -- Look for TCG-specific OIDs that indicate component information
  let componentOIDs = findTCGComponentOIDs asn1
      platformAttrs = findPlatformAttributes asn1

  if null componentOIDs && null platformAttrs
    then putStrLn "No component information found in certificate"
    else do
      when (not $ null platformAttrs) $ do
        putStrLn "=== Platform Attributes ==="
        mapM_ showPlatformAttribute (zip [1 ..] platformAttrs)
        putStrLn ""

      when (not $ null componentOIDs) $ do
        putStrLn "=== TCG Component OIDs Found ==="
        mapM_
          (\(i, oid) -> putStrLn $ "  [" ++ show (i :: Int) ++ "] " ++ formatOIDWithName oid)
          (zip [1 ..] componentOIDs)
        putStrLn ""

      when verbose $ do
        putStrLn "=== All OctetString Values ==="
        let allOctetStrings = findOctetStringsInASN1 asn1
        mapM_
          (\(i, bs) -> putStrLn $ "  [" ++ show (i :: Int) ++ "] " ++ show bs ++ " (hex: " ++ hexdump bs ++ ")")
          (zip [1 ..] (take 20 allOctetStrings))
        when (length allOctetStrings > 20) $
          putStrLn $
            "  ... and " ++ show (length allOctetStrings - 20) ++ " more"
  where
    findTCGComponentOIDs :: [ASN1] -> [OID]
    findTCGComponentOIDs [] = []
    findTCGComponentOIDs (OID oid : rest)
      | isTCGOID oid = oid : findTCGComponentOIDs rest
      | otherwise = findTCGComponentOIDs rest
    findTCGComponentOIDs (_ : rest) = findTCGComponentOIDs rest

    isTCGOID :: OID -> Bool
    isTCGOID (2 : 23 : 133 : _) = True -- TCG OID prefix
    isTCGOID _ = False

-- | Helper function to find OctetStrings in ASN.1
findOctetStringsInASN1 :: [ASN1] -> [B.ByteString]
findOctetStringsInASN1 [] = []
findOctetStringsInASN1 (OctetString bs : rest) = bs : findOctetStringsInASN1 rest
findOctetStringsInASN1 (_ : rest) = findOctetStringsInASN1 rest

-- | Find platform attributes from ASN.1 structure
findPlatformAttributes :: [ASN1] -> [(String, B.ByteString)]
findPlatformAttributes asn1 =
  let octetStrings = findOctetStringsInASN1 asn1
      decodedStrings = mapMaybe decodeIfText octetStrings
   in zip ["Manufacturer", "Model", "Serial", "Version"] decodedStrings
  where
    decodeIfText :: B.ByteString -> Maybe B.ByteString
    decodeIfText bs
      | B.all isAsciiPrintable bs = Just bs
      | otherwise = Nothing

-- | Show platform attribute
showPlatformAttribute :: (Int, (String, B.ByteString)) -> IO ()
showPlatformAttribute (i, (name, value)) = do
  putStrLn $ "  [" ++ show i ++ "] " ++ name ++ ": " ++ show value