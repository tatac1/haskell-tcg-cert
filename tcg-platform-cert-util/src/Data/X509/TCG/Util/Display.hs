{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Util.Display
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Utility
-- Stability   : experimental
-- Portability : unknown
--
-- Display and formatting utilities for TCG Platform Certificates.
-- This module provides functions for pretty-printing certificate information,
-- components, and attributes in human-readable format.
module Data.X509.TCG.Util.Display
  ( -- * Certificate Display
    showPlatformCert,
    showPlatformCertSmall,
    showComponentInformation,
    showSingleComponent,

    -- * Delta Certificate Display
    showDeltaPlatformCert,
    showDeltaOperation,
    showComponentDelta,

    -- * Attribute Display
    showTCGAttribute,
    showExtendedPlatformAttributes,
    isExtendedAttribute,

    -- * Utility Functions
    certificationLevelName,
    rtmTypeName,
    componentClassName,
    formatDeltaOperation,
  )
where

import Control.Monad (forM_, unless)
import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.Types (ASN1 (..), ASN1CharacterString (..), ASN1ConstructionType (..), ASN1Class (..))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Hourglass (timePrint)
import Data.List (intercalate)
import Data.X509 (AltName (..), DistinguishedName (..), ExtensionRaw (..), Extensions (..))
import Data.X509.AttCert (AttCertIssuer (..), AttCertValidityPeriod (..), Holder (..), IssuerSerial (..), V2Form (v2formIssuerName))
import Data.X509.Attribute (Attribute (..), Attributes (..))
import Data.X509.TCG
import Data.X509.TCG.Util.ASN1 (hexdump)
import Data.X509.TCG.Util.OID (formatOIDWithName, lookupComponentClassName)
import Numeric (showHex)
import Data.Bits (shiftL, (.|.))
import Data.Word (Word32)

-- * Helper Functions for Formatting

-- | Format a DistinguishedName as a readable string (e.g., "CN=Name, O=Org")
formatDN :: DistinguishedName -> String
formatDN (DistinguishedName elements) =
  intercalate ", " $ map formatElement elements
  where
    formatElement (oid, charStr) =
      oidToAttrName oid ++ "=" ++ getCharStrValue charStr

    oidToAttrName oid = case oid of
      [2, 5, 4, 3] -> "CN"
      [2, 5, 4, 6] -> "C"
      [2, 5, 4, 7] -> "L"
      [2, 5, 4, 8] -> "ST"
      [2, 5, 4, 10] -> "O"
      [2, 5, 4, 11] -> "OU"
      [2, 5, 4, 5] -> "serialNumber"
      _ -> formatOIDWithName oid

    getCharStrValue (ASN1CharacterString _ bs) = BC.unpack bs

-- | Format a list of AltNames for display
formatAltNames :: [AltName] -> String
formatAltNames names = intercalate ", " $ map formatAltName names
  where
    formatAltName (AltNameDNS dns) = "DNS:" ++ dns
    formatAltName (AltNameRFC822 email) = "email:" ++ email
    formatAltName (AltNameURI uri) = "URI:" ++ uri
    formatAltName (AltNameIP ip) = "IP:" ++ show ip
    formatAltName (AltNameXMPP xmpp) = "XMPP:" ++ xmpp
    formatAltName (AltNameDNSSRV srv) = "SRV:" ++ srv
    formatAltName (AltDirectoryName dn) = formatDN dn

-- | Format ByteString as UTF-8 string (without quotes)
formatBS :: B.ByteString -> String
formatBS = BC.unpack

-- | Show detailed platform certificate information
--
-- Displays certificate in the improved format with:
-- - Header with version and serial number
-- - Issuer DN
-- - Holder (EK Certificate) information
-- - Validity period
-- - TCG Attributes with full content (Table 3 fields)
-- - Components with class values
-- - Extensions with OID names
showPlatformCert :: SignedPlatformCertificate -> IO ()
showPlatformCert signedCert = do
  let certInfo = getPlatformCertificate signedCert
      validity = pciValidity certInfo
      Attributes rawAttrs = pciAttributes certInfo
      isDelta = isDeltaPlatformCert rawAttrs

  -- Header
  if isDelta
    then putStrLn "Delta Platform Certificate Information:"
    else putStrLn "Platform Certificate Information:"
  putStrLn $ "  Version: v" ++ show (pciVersion certInfo)
  putStrLn $ "  Serial Number: 0x" ++ showHex (pciSerialNumber certInfo) ""
  putStrLn ""

  -- Signature Algorithm
  putStrLn $ "  Signature Algorithm: " ++ show (pciSignature certInfo)
  putStrLn ""

  -- Issuer
  showIssuer (pciIssuer certInfo)
  putStrLn ""

  -- Holder (EK Certificate)
  showHolder (pciHolder certInfo)
  putStrLn ""

  -- Validity
  putStrLn "  Validity:"
  showValidityPeriod validity
  putStrLn ""

  -- TCG Attributes (Table 3 fields) - Display ALL raw attributes
  putStrLn "  Attributes:"
  if null rawAttrs
    then putStrLn "    (No attributes found)"
    else forM_ rawAttrs $ \attr -> do
      showRawAttribute "    " attr
  putStrLn ""

  -- Extensions with OID names
  showExtensionsImproved (pciExtensions certInfo)

-- | Display a raw attribute with its OID and parsed content
showRawAttribute :: String -> Attribute -> IO ()
showRawAttribute indent attr = do
  let oid = attrType attr
      values = attrValues attr
  -- Parse the attribute values based on OID
  case oid of
    -- tcg-at-platformManufacturer (2.23.133.2.4)
    [2, 23, 133, 2, 4] -> showPlatformStringAttribute indent "tcg-at-platformManufacturer" values
    -- tcg-at-platformModel (2.23.133.2.5)
    [2, 23, 133, 2, 5] -> showPlatformStringAttribute indent "tcg-at-platformModel" values
    -- tcg-at-platformSerial (2.23.133.2.6)
    [2, 23, 133, 2, 6] -> showPlatformStringAttribute indent "tcg-at-platformSerial" values
    -- tcg-at-platformVersion (2.23.133.2.7)
    [2, 23, 133, 2, 7] -> showPlatformStringAttribute indent "tcg-at-platformVersion" values
    -- tcg-at-tcgPlatformSpecification (2.23.133.2.17)
    [2, 23, 133, 2, 17] -> do
      putStrLn $ indent ++ formatOIDWithName oid ++ ":"
      showTCGPlatformSpecification (indent ++ "  ") values
    -- tcg-at-tcgCredentialType (2.23.133.2.25)
    [2, 23, 133, 2, 25] -> do
      putStrLn $ indent ++ formatOIDWithName oid ++ ":"
      showTCGCredentialType (indent ++ "  ") values
    -- tcg-at-tcgCredentialSpecification (2.23.133.2.23)
    [2, 23, 133, 2, 23] -> do
      putStrLn $ indent ++ formatOIDWithName oid ++ ":"
      showTCGCredentialSpecification (indent ++ "  ") values
    -- tcg-at-tbbSecurityAssertions (2.23.133.2.19)
    [2, 23, 133, 2, 19] -> do
      putStrLn $ indent ++ formatOIDWithName oid ++ ":"
      showTBBSecurityAssertions (indent ++ "  ") values
    -- tcg-at-platformConfiguration-v2 (2.23.133.5.1.7.2)
    [2, 23, 133, 5, 1, 7, 2] -> do
      putStrLn $ indent ++ formatOIDWithName oid ++ ":"
      showPlatformConfigurationV2 (indent ++ "  ") values
    -- tcg-at-platformConfiguration (2.23.133.5.1.7.1)
    [2, 23, 133, 5, 1, 7, 1] -> do
      putStrLn $ indent ++ formatOIDWithName oid ++ ":"
      showPlatformConfigurationV1 (indent ++ "  ") values
    -- Default: show raw ASN.1 values with OID header
    _ -> do
      putStrLn $ indent ++ formatOIDWithName oid ++ ":"
      showRawAttributeValues (indent ++ "  ") values

-- | Show platform string attribute (manufacturer, model, serial, version)
-- These are encoded as OCTET STRING containing UTF8 text
showPlatformStringAttribute :: String -> String -> [[ASN1]] -> IO ()
showPlatformStringAttribute indent attrName values = do
  let decodedValue = extractOctetStringAsText values
  putStrLn $ indent ++ attrName ++ ": " ++ decodedValue

-- | Extract OCTET STRING content as UTF8 text
extractOctetStringAsText :: [[ASN1]] -> String
extractOctetStringAsText values =
  case concat values of
    [OctetString bs] -> BC.unpack bs
    (OctetString bs : _) -> BC.unpack bs
    _ -> "(unable to decode)"

-- | Show raw attribute values as ASN.1
showRawAttributeValues :: String -> [[ASN1]] -> IO ()
showRawAttributeValues indent values =
  forM_ values $ \valueList ->
    forM_ valueList $ \asn1 ->
      putStrLn $ indent ++ showASN1Short asn1

-- | Show ASN.1 value in short format
showASN1Short :: ASN1 -> String
showASN1Short asn1 = case asn1 of
  IntVal i -> "INTEGER: " ++ show i
  OID oid -> "OBJECT IDENTIFIER: " ++ formatOIDWithName oid
  OctetString bs -> "OCTET STRING: " ++ hexdump bs
  ASN1String (ASN1CharacterString _ bs) -> "STRING: " ++ BC.unpack bs
  Boolean b -> "BOOLEAN: " ++ show b
  Enumerated e -> "ENUMERATED: " ++ show e
  Start Sequence -> "SEQUENCE {"
  End Sequence -> "}"
  Start (Container _ _) -> "CONTEXT {"
  End (Container _ _) -> "}"
  Other _ _ bs -> "OTHER: " ++ hexdump bs
  _ -> show asn1

-- | Show TCG Platform Specification attribute (2.23.133.2.17)
-- TCGPlatformSpecification ::= SEQUENCE {
--   Version SEQUENCE { majorVersion INTEGER, minorVersion INTEGER, revision INTEGER },
--   platformClass OCTET STRING }
showTCGPlatformSpecification :: String -> [[ASN1]] -> IO ()
showTCGPlatformSpecification indent values = do
  forM_ values $ \valueList -> do
    let major = findIntAt valueList 0
        minor = findIntAt valueList 1
        rev = findIntAt valueList 2
        classBytes = findOctetString valueList
    case (major, minor, rev) of
      (Just ma, Just mi, Just r) -> do
        putStrLn $ indent ++ "Version: " ++ show ma ++ "." ++ show mi ++ " rev " ++ show r
        case classBytes of
          Just bs -> putStrLn $ indent ++ "Platform Class: " ++ hexdump bs ++ " (" ++ show (bytesToWord32 bs) ++ ")"
          Nothing -> return ()
      _ -> showRawAttributeValues indent [valueList]

-- | Show TCG Credential Type attribute (2.23.133.2.25)
-- TCGCredentialType ::= SEQUENCE { credentialType OBJECT IDENTIFIER }
showTCGCredentialType :: String -> [[ASN1]] -> IO ()
showTCGCredentialType indent values = do
  forM_ values $ \valueList -> do
    case findOID valueList of
      Just oid -> putStrLn $ indent ++ "Credential Type: " ++ formatOIDWithName oid
      Nothing -> showRawAttributeValues indent [valueList]

-- | Show TCG Credential Specification attribute (2.23.133.2.23)
-- TCGCredentialSpecification ::= SEQUENCE { majorVersion INTEGER, minorVersion INTEGER, revision INTEGER }
showTCGCredentialSpecification :: String -> [[ASN1]] -> IO ()
showTCGCredentialSpecification indent values = do
  forM_ values $ \valueList -> do
    let major = findIntAt valueList 0
        minor = findIntAt valueList 1
        rev = findIntAt valueList 2
    case (major, minor, rev) of
      (Just ma, Just mi, Just r) ->
        putStrLn $ indent ++ "Version: " ++ show ma ++ "." ++ show mi ++ " rev " ++ show r
      _ -> showRawAttributeValues indent [valueList]

-- | Find nth integer in ASN1 list
findIntAt :: [ASN1] -> Int -> Maybe Integer
findIntAt asn1List n =
  let ints = [i | IntVal i <- asn1List]
  in if n < length ints then Just (ints !! n) else Nothing

-- | Find first OID in ASN1 list
findOID :: [ASN1] -> Maybe [Integer]
findOID asn1List = case [oid | OID oid <- asn1List] of
  (oid:_) -> Just oid
  [] -> Nothing

-- | Find first OctetString in ASN1 list
findOctetString :: [ASN1] -> Maybe B.ByteString
findOctetString asn1List = case [bs | OctetString bs <- asn1List] of
  (bs:_) -> Just bs
  [] -> Nothing

-- | Check if certificate is a Delta Platform Certificate
-- Delta Platform Certificate has OID 2.23.133.8.5 (tcg-kp-DeltaPlatformAttributeCertificate)
isDeltaPlatformCert :: [Attribute] -> Bool
isDeltaPlatformCert attrs = any isDeltaCredType attrs
  where
    isDeltaCredType attr =
      attrType attr == [2, 23, 133, 2, 25] &&  -- tcg-at-tcgCredentialType
      any (hasOID [2, 23, 133, 8, 5]) (attrValues attr)  -- tcg-kp-DeltaPlatformAttributeCertificate
    hasOID targetOid asn1List = any (== OID targetOid) asn1List

-- | Show TBB Security Assertions attribute (2.23.133.2.19)
-- TBBSecurityAssertions ::= SEQUENCE {
--   version Version DEFAULT v1,
--   ccInfo [0] IMPLICIT CommonCriteriaMeasures OPTIONAL,
--   fipsLevel [1] IMPLICIT FIPSLevel OPTIONAL,
--   rtmType [2] IMPLICIT MeasurementRootType OPTIONAL,
--   iso9000Certified BOOLEAN DEFAULT FALSE,
--   iso9000Uri IA5String OPTIONAL }
showTBBSecurityAssertions :: String -> [[ASN1]] -> IO ()
showTBBSecurityAssertions indent values = do
  forM_ values $ \valueList -> do
    putStrLn $ indent ++ "TBB Security Assertions:"
    parseTBBAssertions (indent ++ "  ") valueList

-- | Parse TBB Security Assertions content
parseTBBAssertions :: String -> [ASN1] -> IO ()
parseTBBAssertions indent asn1List = go asn1List
  where
    go [] = return ()
    go (Start Sequence : rest) = go rest
    go (End Sequence : rest) = go rest
    go (IntVal v : rest) = do
      putStrLn $ indent ++ "Version: " ++ show v
      go rest
    -- ccInfo [0] - Common Criteria Measures
    go (Start (Container _ 0) : rest) = do
      let (ccContent, remaining) = spanNestedContainer rest
      parseCommonCriteria indent ccContent
      go remaining
    -- fipsLevel [1] - FIPS Level
    go (Start (Container _ 1) : rest) = do
      let (fipsContent, remaining) = spanNestedContainer rest
      parseFIPSLevel indent fipsContent
      go remaining
    -- rtmType [2] - Measurement Root Type
    go (Start (Container _ 2) : rest) = do
      let (_, remaining) = spanNestedContainer rest
      go remaining
    go (Other _ 2 bs : rest) = do
      case B.unpack bs of
        [v] -> putStrLn $ indent ++ "RTM Type: " ++ measurementRootTypeName (fromIntegral v)
        _ -> putStrLn $ indent ++ "RTM Type: " ++ hexdump bs
      go rest
    go (Boolean b : rest) = do
      putStrLn $ indent ++ "ISO 9000 Certified: " ++ show b
      go rest
    go (ASN1String (ASN1CharacterString _ bs) : rest) = do
      putStrLn $ indent ++ "ISO 9000 URI: " ++ BC.unpack bs
      go rest
    go (_ : rest) = go rest

-- | Extract content until matching End Container, handling nested containers
spanNestedContainer :: [ASN1] -> ([ASN1], [ASN1])
spanNestedContainer = go (0 :: Int) []
  where
    go _ acc [] = (reverse acc, [])
    go depth acc (x:xs) = case x of
      Start (Container _ _) -> go (depth + 1) (x:acc) xs
      End (Container _ _)
        | depth == 0 -> (reverse acc, xs)
        | otherwise -> go (depth - 1) (x:acc) xs
      _ -> go depth (x:acc) xs

-- | Parse Common Criteria Measures
-- CommonCriteriaMeasures ::= SEQUENCE {
--   version IA5String,
--   assuranceLevel EvaluationAssuranceLevel,   -- ENUMERATED (EAL 1-7)
--   evaluationStatus EvaluationStatus,         -- ENUMERATED (0-2)
--   plus BOOLEAN DEFAULT FALSE,
--   strengthOfFunction [0] IMPLICIT OPTIONAL,
--   profileOid [1] IMPLICIT OID OPTIONAL,
--   profileUri [2] IMPLICIT URIReference OPTIONAL,
--   targetOid [3] IMPLICIT OID OPTIONAL,
--   targetUri [4] IMPLICIT URIReference OPTIONAL }
parseCommonCriteria :: String -> [ASN1] -> IO ()
parseCommonCriteria indent asn1List = do
  putStrLn $ indent ++ "Common Criteria:"
  -- Find all enumerated values
  let enums = [e | Enumerated e <- asn1List]
      (ealLevel, evalStatus) = case enums of
        (e1:e2:_) -> (Just e1, Just e2)
        [e1] -> (Just e1, Nothing)
        [] -> (Nothing, Nothing)
  go asn1List ealLevel evalStatus
  where
    go [] _ _ = return ()
    go (ASN1String (ASN1CharacterString _ bs) : rest) eal es = do
      putStrLn $ indent ++ "  CC Version: " ++ BC.unpack bs
      go rest eal es
    go (Enumerated e : rest) eal es = do
      case eal of
        Just ealVal | fromIntegral e == ealVal -> do
          putStrLn $ indent ++ "  Evaluation Assurance Level: " ++ ealName (fromIntegral e)
          go rest Nothing es  -- Mark EAL as consumed
        _ -> do
          putStrLn $ indent ++ "  Evaluation Status: " ++ evalStatusName (fromIntegral e)
          go rest eal es
    go (Boolean b : rest) eal es = do
      putStrLn $ indent ++ "  Plus: " ++ show b
      go rest eal es
    -- Strength of Function [0]
    go (Other _ 0 bs : rest) eal es = do
      case B.unpack bs of
        [v] -> putStrLn $ indent ++ "  Strength of Function: " ++ strengthOfFunctionName (fromIntegral v)
        _ -> putStrLn $ indent ++ "  Strength of Function: " ++ hexdump bs
      go rest eal es
    -- Profile OID [1]
    go (Other _ 1 bs : rest) eal es = do
      case decodeASN1' DER bs of
        Right [OID oid] -> putStrLn $ indent ++ "  Protection Profile OID: " ++ formatOIDWithName oid
        _ -> putStrLn $ indent ++ "  Protection Profile OID: " ++ hexdump bs
      go rest eal es
    -- Profile URI [2]
    go (Start (Container _ 2) : rest) eal es = do
      let (content, remaining) = span (not . isEndContainer) rest
      case content of
        [ASN1String (ASN1CharacterString _ bs)] ->
          putStrLn $ indent ++ "  Protection Profile URI: " ++ BC.unpack bs
        _ -> return ()
      go (dropWhile isEndContainer remaining) eal es
    -- Target OID [3]
    go (Other _ 3 bs : rest) eal es = do
      case decodeASN1' DER bs of
        Right [OID oid] -> putStrLn $ indent ++ "  Security Target OID: " ++ formatOIDWithName oid
        _ -> putStrLn $ indent ++ "  Security Target OID: " ++ hexdump bs
      go rest eal es
    -- Target URI [4]
    go (Start (Container _ 4) : rest) eal es = do
      let (content, remaining) = span (not . isEndContainer) rest
      case content of
        [ASN1String (ASN1CharacterString _ bs)] ->
          putStrLn $ indent ++ "  Security Target URI: " ++ BC.unpack bs
        _ -> return ()
      go (dropWhile isEndContainer remaining) eal es
    go (_ : rest) eal es = go rest eal es

    isEndContainer (End _) = True
    isEndContainer _ = False

-- | Strength of Function name
strengthOfFunctionName :: Int -> String
strengthOfFunctionName n = case n of
  0 -> "basic"
  1 -> "medium"
  2 -> "high"
  _ -> "unknown (" ++ show n ++ ")"

-- | Parse FIPS Level
parseFIPSLevel :: String -> [ASN1] -> IO ()
parseFIPSLevel indent asn1List = do
  putStrLn $ indent ++ "FIPS Level:"
  go asn1List
  where
    go [] = return ()
    go (ASN1String (ASN1CharacterString _ bs) : rest) = do
      putStrLn $ indent ++ "  Version: " ++ BC.unpack bs
      go rest
    go (Enumerated e : rest) = do
      putStrLn $ indent ++ "  Security Level: " ++ show e ++ " (" ++ fipsLevelName (fromIntegral e) ++ ")"
      go rest
    go (Boolean b : rest) = do
      putStrLn $ indent ++ "  Plus: " ++ show b
      go rest
    go (_ : rest) = go rest

-- | Show Platform Configuration V2 attribute (2.23.133.5.1.7.2)
showPlatformConfigurationV2 :: String -> [[ASN1]] -> IO ()
showPlatformConfigurationV2 indent values = do
  forM_ values $ \valueList -> do
    putStrLn $ indent ++ "Platform Configuration V2:"
    parsePlatformConfigV2 (indent ++ "  ") valueList

-- | Parse Platform Configuration V2 content
parsePlatformConfigV2 :: String -> [ASN1] -> IO ()
parsePlatformConfigV2 indent asn1List = go asn1List 1
  where
    go [] _ = return ()
    go (Start Sequence : rest) n = go rest n
    go (End Sequence : rest) n = go rest n
    -- componentIdentifiers [0]
    go (Start (Container _ 0) : rest) n = do
      putStrLn $ indent ++ "Component Identifiers:"
      let (compContent, remaining) = spanUntilEndContainer rest
      parseComponentList (indent ++ "  ") compContent n
      go remaining n
    -- platformProperties [2]
    go (Start (Container _ 2) : rest) n = do
      putStrLn $ indent ++ "Platform Properties:"
      let (_, remaining) = spanUntilEndContainer rest
      go remaining n
    go (_ : rest) n = go rest n

    spanUntilEndContainer :: [ASN1] -> ([ASN1], [ASN1])
    spanUntilEndContainer xs = spanNested (0 :: Int) xs []
      where
        spanNested :: Int -> [ASN1] -> [ASN1] -> ([ASN1], [ASN1])
        spanNested _ [] acc = (reverse acc, [])
        spanNested depth (End (Container _ _) : rest) acc
          | depth == 0 = (reverse acc, rest)
          | otherwise = spanNested (depth - 1) rest (End (Container Context 0) : acc)
        spanNested depth (Start c@(Container _ _) : rest) acc =
          spanNested (depth + 1) rest (Start c : acc)
        spanNested depth (x : rest) acc = spanNested depth rest (x : acc)

-- | Parse component list from Platform Configuration
parseComponentList :: String -> [ASN1] -> Int -> IO ()
parseComponentList indent asn1List startIdx = go asn1List startIdx
  where
    go [] _ = return ()
    go (Start Sequence : rest) n = do
      let (compContent, remaining) = spanUntilEndSeq rest
      parseComponentIdentifier indent compContent n
      go remaining (n + 1)
    go (_ : rest) n = go rest n

    spanUntilEndSeq :: [ASN1] -> ([ASN1], [ASN1])
    spanUntilEndSeq xs = spanNested (0 :: Int) xs []
      where
        spanNested :: Int -> [ASN1] -> [ASN1] -> ([ASN1], [ASN1])
        spanNested _ [] acc = (reverse acc, [])
        spanNested depth (End Sequence : rest) acc
          | depth == 0 = (reverse acc, rest)
          | otherwise = spanNested (depth - 1) rest (End Sequence : acc)
        spanNested depth (Start Sequence : rest) acc =
          spanNested (depth + 1) rest (Start Sequence : acc)
        spanNested depth (x : rest) acc = spanNested depth rest (x : acc)

-- | Parse a single ComponentIdentifier
parseComponentIdentifier :: String -> [ASN1] -> Int -> IO ()
parseComponentIdentifier indent asn1List idx = do
  let (classOid, classValue) = extractComponentClass asn1List
      mfg = extractUTF8String asn1List 0
      model = extractUTF8String asn1List 1
      serialNum = extractTaggedUTF8 asn1List 0
      revision = extractTaggedUTF8 asn1List 1
      addresses = extractComponentAddresses asn1List
      status = extractComponentStatus asn1List
  -- Display component info
  let classDisplay = case (classOid, classValue) of
        (Just oid, Just val) ->
          let w32 = bytesToWord32 val
              hexVal = "0x" ++ padHex 8 (showHex w32 "")
              mnemonic = case lookupComponentClassName w32 of
                Just name -> name
                Nothing -> "Unknown"
          in formatOIDWithName oid ++ " / Mnemonic Name: " ++ mnemonic ++ " (Component Class Value: " ++ hexVal ++ ")"
        (Just oid, Nothing) -> formatOIDWithName oid
        (Nothing, Just val) ->
          let w32 = bytesToWord32 val
              hexVal = "0x" ++ padHex 8 (showHex w32 "")
              mnemonic = case lookupComponentClassName w32 of
                Just name -> name
                Nothing -> "Unknown"
          in "Mnemonic Name: " ++ mnemonic ++ " (Component Class Value: " ++ hexVal ++ ")"
        _ -> "Unknown"
  -- Show status for Delta certificate components
  let statusStr = case status of
        Just s -> " [" ++ attributeStatusName s ++ "]"
        Nothing -> ""
  putStrLn $ indent ++ "[" ++ show idx ++ "] Component:" ++ statusStr
  putStrLn $ indent ++ "    Class: " ++ classDisplay
  case mfg of
    Just m -> putStrLn $ indent ++ "    Manufacturer: " ++ BC.unpack m
    Nothing -> return ()
  case model of
    Just m -> putStrLn $ indent ++ "    Model: " ++ BC.unpack m
    Nothing -> return ()
  case serialNum of
    Just s -> putStrLn $ indent ++ "    Serial: " ++ BC.unpack s
    Nothing -> return ()
  case revision of
    Just r -> putStrLn $ indent ++ "    Revision: " ++ BC.unpack r
    Nothing -> return ()
  unless (null addresses) $ do
    putStrLn $ indent ++ "    Addresses:"
    forM_ addresses $ \(addrOid, addrVal) ->
      putStrLn $ indent ++ "      " ++ formatOIDWithName addrOid ++ ": " ++ BC.unpack addrVal

-- | Extract component class (OID and 4-byte value)
extractComponentClass :: [ASN1] -> (Maybe [Integer], Maybe B.ByteString)
extractComponentClass asn1List = go asn1List (Nothing, Nothing)
  where
    go [] acc = acc
    go (Start Sequence : OID oid : OctetString bs : End Sequence : rest) (_, _)
      | [2, 23, 133, 18, 3, 1] `isPrefixOf` oid ||
        [2, 23, 133, 18, 3] `isPrefixOf` oid = go rest (Just oid, Just bs)
    go (OID oid : OctetString bs : rest) (_, _)
      | [2, 23, 133, 18, 3] `isPrefixOf` oid = go rest (Just oid, Just bs)
    go (_ : rest) acc = go rest acc
    isPrefixOf [] _ = True
    isPrefixOf _ [] = False
    isPrefixOf (x:xs) (y:ys) = x == y && isPrefixOf xs ys

-- | Extract UTF8String at position
extractUTF8String :: [ASN1] -> Int -> Maybe B.ByteString
extractUTF8String asn1List pos =
  let strings = [bs | ASN1String (ASN1CharacterString _ bs) <- asn1List]
  in if pos < length strings then Just (strings !! pos) else Nothing

-- | Extract tagged UTF8String [tag] IMPLICIT
extractTaggedUTF8 :: [ASN1] -> Int -> Maybe B.ByteString
extractTaggedUTF8 asn1List tag = go asn1List
  where
    go [] = Nothing
    go (Other _ t bs : _) | t == fromIntegral tag = Just bs
    go (_ : rest) = go rest

-- | Extract component addresses
extractComponentAddresses :: [ASN1] -> [([Integer], B.ByteString)]
extractComponentAddresses asn1List = go asn1List
  where
    go [] = []
    go (Start (Container _ 4) : rest) = extractAddrs rest
    go (_ : rest) = go rest

    extractAddrs [] = []
    extractAddrs (End (Container _ _) : _) = []
    extractAddrs (Start Sequence : OID oid : ASN1String (ASN1CharacterString _ bs) : End Sequence : rest) =
      (oid, bs) : extractAddrs rest
    extractAddrs (_ : rest) = extractAddrs rest

-- | Extract component status field [7] IMPLICIT AttributeStatus
-- AttributeStatus ::= ENUMERATED { added(0), modified(1), removed(2) }
extractComponentStatus :: [ASN1] -> Maybe Int
extractComponentStatus asn1List = go asn1List
  where
    go [] = Nothing
    go (Other _ 7 bs : _) = case B.unpack bs of
      [v] -> Just (fromIntegral v)
      _ -> Nothing
    go (_ : rest) = go rest

-- | AttributeStatus name for Delta Platform Certificate
-- Values: added(0), modified(1), removed(2)
attributeStatusName :: Int -> String
attributeStatusName n = case n of
  0 -> "ADDED"
  1 -> "MODIFIED"
  2 -> "REMOVED"
  _ -> "unknown (" ++ show n ++ ")"

-- | Show Platform Configuration V1 attribute
showPlatformConfigurationV1 :: String -> [[ASN1]] -> IO ()
showPlatformConfigurationV1 indent values = do
  putStrLn $ indent ++ "Platform Configuration V1:"
  showRawAttributeValues (indent ++ "  ") values

-- | Helper: convert 4 bytes to Word32
bytesToWord32 :: B.ByteString -> Word32
bytesToWord32 bs
  | B.length bs >= 4 =
      let b0 = fromIntegral (B.index bs 0) :: Word32
          b1 = fromIntegral (B.index bs 1) :: Word32
          b2 = fromIntegral (B.index bs 2) :: Word32
          b3 = fromIntegral (B.index bs 3) :: Word32
      in (b0 `shiftL` 24) .|. (b1 `shiftL` 16) .|. (b2 `shiftL` 8) .|. b3
  | otherwise = 0

-- | Helper: pad hex string to specified length with leading zeros
padHex :: Int -> String -> String
padHex n s = replicate (n - length s) '0' ++ s

-- | EAL level name
ealName :: Int -> String
ealName n = case n of
  1 -> "EAL1"
  2 -> "EAL2"
  3 -> "EAL3"
  4 -> "EAL4"
  5 -> "EAL5"
  6 -> "EAL6"
  7 -> "EAL7"
  _ -> "EAL" ++ show n

-- | Evaluation status name
evalStatusName :: Int -> String
evalStatusName n = case n of
  0 -> "designedToMeet"
  1 -> "evaluationInProgress"
  2 -> "evaluationCompleted"
  _ -> "unknown (" ++ show n ++ ")"

-- | FIPS level name
fipsLevelName :: Int -> String
fipsLevelName n = case n of
  1 -> "Level 1"
  2 -> "Level 2"
  3 -> "Level 3"
  4 -> "Level 4"
  _ -> "Level " ++ show n

-- | Measurement root type name
measurementRootTypeName :: Int -> String
measurementRootTypeName n = case n of
  0 -> "static"
  1 -> "dynamic"
  2 -> "nonHost"
  3 -> "hybrid"
  4 -> "physical"
  5 -> "virtual"
  _ -> "unknown (" ++ show n ++ ")"

-- | Show issuer information
showIssuer :: AttCertIssuer -> IO ()
showIssuer (AttCertIssuerV1 names) =
  putStrLn $ "  Issuer: " ++ formatAltNames names
showIssuer (AttCertIssuerV2 v2form) = do
  let names = v2formIssuerName v2form
  case names of
    [] -> putStrLn "  Issuer: (empty)"
    _ -> putStrLn $ "  Issuer: " ++ formatIssuerNames names
  where
    formatIssuerNames :: [AltName] -> String
    formatIssuerNames altNames =
      case [dn | AltDirectoryName dn <- altNames] of
        (dn : _) -> formatDN dn
        [] -> formatAltNames altNames

-- | Show holder information (EK Certificate)
showHolder :: Holder -> IO ()
showHolder holder = do
  putStrLn "  Holder:"
  case holderBaseCertificateID holder of
    Just issuerSerial -> do
      putStrLn $ "    EK Certificate Issuer: " ++ extractDNFromAltNames (issuer issuerSerial)
      putStrLn $ "    EK Certificate Serial: " ++ show (serial issuerSerial)
    Nothing -> putStrLn "    (No BaseCertificateID)"
  case holderEntityName holder of
    Just names -> putStrLn $ "    Entity Name: " ++ formatAltNames names
    Nothing -> return ()

-- | Extract DistinguishedName from AltNames list, or format all alt names if no DN found
extractDNFromAltNames :: [AltName] -> String
extractDNFromAltNames altNames =
  case [dn | AltDirectoryName dn <- altNames] of
    (dn : _) -> formatDN dn
    [] -> formatAltNames altNames

-- | Show validity period in improved format
showValidityPeriod :: AttCertValidityPeriod -> IO ()
showValidityPeriod (AttCertValidityPeriod start end) = do
  putStrLn $ "    Not Before: " ++ timePrint ("YYYY-MM-DD H:MI:S" :: String) start ++ " UTC"
  putStrLn $ "    Not After:  " ++ timePrint ("YYYY-MM-DD H:MI:S" :: String) end ++ " UTC"

-- | Show a component in improved format with class value
_showComponentImproved :: Int -> ComponentIdentifier -> IO ()
_showComponentImproved i comp = do
  putStrLn $ "    [" ++ show i ++ "] Component"
  putStrLn $ "        Manufacturer: " ++ formatBS (ciManufacturer comp)
  putStrLn $ "        Model: " ++ formatBS (ciModel comp)
  case ciSerial comp of
    Just ser -> putStrLn $ "        Serial: " ++ formatBS ser
    Nothing -> return ()

-- | Show a component v2 in improved format with class value
_showComponentV2Improved :: Int -> ComponentIdentifierV2 -> IO ()
_showComponentV2Improved i comp = do
  putStrLn $ "    [" ++ show i ++ "] " ++ componentClassName (ci2ComponentClass comp)
        ++ " (" ++ formatComponentClassHex (ci2ComponentClass comp) ++ ")"
  putStrLn $ "        Manufacturer: " ++ formatBS (ci2Manufacturer comp)
  putStrLn $ "        Model: " ++ formatBS (ci2Model comp)
  case ci2Serial comp of
    Just ser -> putStrLn $ "        Serial: " ++ formatBS ser
    Nothing -> return ()

-- | Format component class as hex value
formatComponentClassHex :: ComponentClass -> String
formatComponentClassHex cls = case cls of
  ComponentMotherboard -> "0x00030003"
  ComponentCPU -> "0x00010002"
  ComponentMemory -> "0x00060004"
  ComponentHardDrive -> "0x00070002"
  ComponentNetworkInterface -> "0x00090002"
  ComponentGraphicsCard -> "0x00050002"
  ComponentSoundCard -> "0x00050006"
  ComponentOpticalDrive -> "0x00080004"
  ComponentKeyboard -> "0x000C0002"
  ComponentMouse -> "0x000C0003"
  ComponentDisplay -> "0x000D0003"
  ComponentSpeaker -> "0x000C0007"
  ComponentMicrophone -> "0x000C0008"
  ComponentCamera -> "0x000C0009"
  ComponentTouchscreen -> "0x000D0007"
  ComponentFingerprint -> "0x000C000A"
  ComponentBluetooth -> "0x0005000F"
  ComponentWifi -> "0x0005000D"
  ComponentEthernet -> "0x00050004"
  ComponentUSB -> "0x0005000B"
  ComponentFireWire -> "0x0005000C"
  ComponentSCSI -> "0x00050003"
  ComponentIDE -> "0x00050007"
  ComponentOther _ -> "0x00000000"

-- | Show TCG attributes in improved format with OID names
_showTCGAttributesImproved :: [TCGAttribute] -> IO ()
_showTCGAttributesImproved attrs = do
  putStrLn "  TCG Attributes:"
  forM_ attrs $ \attr -> case attr of
    TCGPlatformConfiguration _ ->
      putStrLn $ "    - " ++ formatOIDWithName [2, 23, 133, 5, 1, 7, 1]
    TCGPlatformConfigurationV2 _ ->
      putStrLn $ "    - " ++ formatOIDWithName [2, 23, 133, 5, 1, 7, 2]
    TCGPlatformManufacturer _ ->
      putStrLn $ "    - " ++ formatOIDWithName [2, 23, 133, 5, 1, 1]
    TCGPlatformModel _ ->
      putStrLn $ "    - " ++ formatOIDWithName [2, 23, 133, 5, 1, 4]
    TCGPlatformSerial _ ->
      putStrLn $ "    - " ++ formatOIDWithName [2, 23, 133, 5, 1, 6]
    TCGPlatformVersion _ ->
      putStrLn $ "    - " ++ formatOIDWithName [2, 23, 133, 5, 1, 5]
    TCGTPMModel _ ->
      putStrLn $ "    - " ++ formatOIDWithName [2, 23, 133, 2, 2]
    TCGTPMVersion _ ->
      putStrLn $ "    - " ++ formatOIDWithName [2, 23, 133, 2, 3]
    TCGTPMSpecification _ ->
      putStrLn $ "    - " ++ formatOIDWithName [2, 23, 133, 2, 16]
    TCGComponentIdentifier _ ->
      putStrLn "    - tcg-at-componentIdentifier"
    TCGComponentIdentifierV2 _ ->
      putStrLn "    - tcg-at-componentIdentifier-v2"
    TCGRootOfTrust _ ->
      putStrLn "    - tcg-at-rootOfTrust"
    TCGCertificationLevel _ ->
      putStrLn "    - tcg-at-certificationLevel"
    TCGOtherAttribute oid _ ->
      putStrLn $ "    - " ++ formatOIDWithName oid
    _ -> putStrLn $ "    - " ++ show attr
  putStrLn ""

-- | Show extensions in improved format with OID names
showExtensionsImproved :: Extensions -> IO ()
showExtensionsImproved (Extensions Nothing) = return ()
showExtensionsImproved (Extensions (Just exts)) = do
  putStrLn "  Extensions:"
  forM_ exts $ \ext ->
    putStrLn $ "    - " ++ formatOIDWithName (extRawOID ext)
      ++ if extRawCritical ext then " (critical)" else ""

-- | Show platform certificate information in a compact format
showPlatformCertSmall :: SignedPlatformCertificate -> IO ()
showPlatformCertSmall signedCert = do
  let certInfo = getPlatformCertificate signedCert
      validity = pciValidity certInfo
  putStrLn $ "Serial: " ++ show (pciSerialNumber certInfo)
  putStrLn $ "Version: v" ++ show (pciVersion certInfo)
  putStrLn $ "Valid: " ++ formatValidityPeriod validity
  case getPlatformInfo signedCert of
    Just info -> do
      putStrLn $ "Manufacturer: " ++ formatBS (piManufacturer info)
      putStrLn $ "Model: " ++ formatBS (piModel info)
      putStrLn $ "Serial: " ++ formatBS (piSerial info)
    Nothing -> putStrLn "No platform info found"
  where
    formatValidityPeriod (AttCertValidityPeriod start end) =
      timePrint ("YYYY-MM-DD H:MI:S" :: String) start
        ++ " to "
        ++ timePrint ("YYYY-MM-DD H:MI:S" :: String) end

-- | Show component information from a parsed Platform Certificate
showComponentInformation :: SignedPlatformCertificate -> Bool -> IO ()
showComponentInformation signedCert _verbose = do
  putStrLn "Platform Certificate Components:"
  putStrLn ""

  let certInfo = getPlatformCertificate signedCert
      Attributes rawAttrs = pciAttributes certInfo

  -- Extract basic platform information
  putStrLn "=== Platform Information ==="
  case getPlatformInfo signedCert of
    Just info -> do
      putStrLn $ "Manufacturer: " ++ formatBS (piManufacturer info)
      putStrLn $ "Model: " ++ formatBS (piModel info)
      putStrLn $ "Version: " ++ formatBS (piVersion info)
      putStrLn $ "Serial Number: " ++ formatBS (piSerial info)
    Nothing -> putStrLn "No platform information found"

  putStrLn ""

  -- Extract TPM information
  putStrLn "=== TPM Information ==="
  case getTPMInfo signedCert of
    Just tpmInfo -> do
      putStrLn $ "Model: " ++ formatBS (tpmModel tpmInfo)
      putStrLn $ "Version: " ++ show (tpmVersion tpmInfo)
      putStrLn $ "Specification: " ++ show (tpmSpecification tpmInfo)
    Nothing -> putStrLn "No TPM information found"

  putStrLn ""

  -- Extract component identifiers (check V2 attribute first, then V1)
  putStrLn "=== Component Identifiers ==="
  let v2Attr = findAttributeByOID [2, 23, 133, 5, 1, 7, 2] rawAttrs  -- tcg-at-platformConfiguration-v2
      v1Attr = findAttributeByOID [2, 23, 133, 5, 1, 7, 1] rawAttrs  -- tcg-at-platformConfiguration
  case (v2Attr, v1Attr) of
    (Just attr, _) -> showComponentsFromAttribute attr
    (Nothing, Just attr) -> showComponentsFromAttribute attr
    (Nothing, Nothing) ->
      -- Fallback to getComponentIdentifiers for older format
      let components = getComponentIdentifiers signedCert
      in if null components
        then putStrLn "No component identifiers found"
        else do
          putStrLn $ "Found " ++ show (length components) ++ " component(s):"
          forM_ (zip [1 ..] components) $ \(idx, comp) -> do
            putStrLn $ "  [" ++ show (idx :: Int) ++ "] Component:"
            putStrLn $ "      Manufacturer: " ++ formatBS (ciManufacturer comp)
            putStrLn $ "      Model: " ++ formatBS (ciModel comp)
            case ciSerial comp of
              Just ser -> putStrLn $ "      Serial: " ++ formatBS ser
              Nothing -> return ()
            case ciRevision comp of
              Just rev -> putStrLn $ "      Revision: " ++ formatBS rev
              Nothing -> return ()

  putStrLn ""

  -- Extract additional attributes
  putStrLn "=== Additional TCG Attributes ==="
  let tcgAttrs = extractTCGAttributes signedCert
  if null tcgAttrs
    then putStrLn "No additional TCG attributes found"
    else do
      putStrLn $ "Found " ++ show (length tcgAttrs) ++ " attribute(s):"
      mapM_
        (\(i, attr) -> putStrLn $ "  [" ++ show (i :: Int) ++ "] " ++ show attr)
        (zip [1 ..] tcgAttrs)

-- | Find an attribute by OID
findAttributeByOID :: [Integer] -> [Attribute] -> Maybe Attribute
findAttributeByOID targetOid attrs =
  case filter (\a -> attrType a == targetOid) attrs of
    (a:_) -> Just a
    [] -> Nothing

-- | Show components from a Platform Configuration attribute
showComponentsFromAttribute :: Attribute -> IO ()
showComponentsFromAttribute attr = do
  let allASN1 = concat (attrValues attr)
  parsePlatformConfigComponents "  " allASN1

-- | Parse and display components from Platform Configuration ASN.1
parsePlatformConfigComponents :: String -> [ASN1] -> IO ()
parsePlatformConfigComponents indent asn1List = go asn1List 1
  where
    go [] _ = return ()
    go (Start Sequence : rest) n = go rest n
    go (End Sequence : rest) n = go rest n
    -- componentIdentifiers [0]
    go (Start (Container _ 0) : rest) n = do
      let (compContent, remaining) = spanUntilEndContainerComp rest
      parseCompList indent compContent n
      go remaining n
    go (_ : rest) n = go rest n

    spanUntilEndContainerComp :: [ASN1] -> ([ASN1], [ASN1])
    spanUntilEndContainerComp xs = spanNested (0 :: Int) xs []
      where
        spanNested :: Int -> [ASN1] -> [ASN1] -> ([ASN1], [ASN1])
        spanNested _ [] acc = (reverse acc, [])
        spanNested depth (End (Container _ _) : rest) acc
          | depth == 0 = (reverse acc, rest)
          | otherwise = spanNested (depth - 1) rest (End (Container Context 0) : acc)
        spanNested depth (Start c@(Container _ _) : rest) acc =
          spanNested (depth + 1) rest (Start c : acc)
        spanNested depth (x : rest) acc = spanNested depth rest (x : acc)

-- | Parse component list for components command
parseCompList :: String -> [ASN1] -> Int -> IO ()
parseCompList indent asn1List startIdx = go asn1List startIdx
  where
    go [] _ = return ()
    go (Start Sequence : rest) n = do
      let (compContent, remaining) = spanUntilEndSeqComp rest
      parseCompIdentifier indent compContent n
      go remaining (n + 1)
    go (_ : rest) n = go rest n

    spanUntilEndSeqComp :: [ASN1] -> ([ASN1], [ASN1])
    spanUntilEndSeqComp xs = spanNested (0 :: Int) xs []
      where
        spanNested :: Int -> [ASN1] -> [ASN1] -> ([ASN1], [ASN1])
        spanNested _ [] acc = (reverse acc, [])
        spanNested depth (End Sequence : rest) acc
          | depth == 0 = (reverse acc, rest)
          | otherwise = spanNested (depth - 1) rest (End Sequence : acc)
        spanNested depth (Start Sequence : rest) acc =
          spanNested (depth + 1) rest (Start Sequence : acc)
        spanNested depth (x : rest) acc = spanNested depth rest (x : acc)

-- | Parse a single ComponentIdentifier for components command
parseCompIdentifier :: String -> [ASN1] -> Int -> IO ()
parseCompIdentifier indent asn1List idx = do
  let (classOid, classValue) = extractComponentClass asn1List
      mfg = extractUTF8String asn1List 0
      model = extractUTF8String asn1List 1
      serialNum = extractTaggedUTF8 asn1List 0
      revision = extractTaggedUTF8 asn1List 1
      addresses = extractComponentAddresses asn1List
      status = extractComponentStatus asn1List
  -- Display component info
  let classDisplay = case (classOid, classValue) of
        (Just oid, Just val) ->
          let w32 = bytesToWord32 val
              hexVal = "0x" ++ padHex 8 (showHex w32 "")
              mnemonic = case lookupComponentClassName w32 of
                Just name -> name
                Nothing -> "Unknown"
          in formatOIDWithName oid ++ " / Mnemonic Name: " ++ mnemonic ++ " (Component Class Value: " ++ hexVal ++ ")"
        (Just oid, Nothing) -> formatOIDWithName oid
        (Nothing, Just val) ->
          let w32 = bytesToWord32 val
              hexVal = "0x" ++ padHex 8 (showHex w32 "")
              mnemonic = case lookupComponentClassName w32 of
                Just name -> name
                Nothing -> "Unknown"
          in "Mnemonic Name: " ++ mnemonic ++ " (Component Class Value: " ++ hexVal ++ ")"
        _ -> "Unknown"
  -- Show status for Delta certificate components
  let statusStr = case status of
        Just s -> " [" ++ attributeStatusName s ++ "]"
        Nothing -> ""
  putStrLn $ indent ++ "[" ++ show idx ++ "] Component:" ++ statusStr
  putStrLn $ indent ++ "    Class: " ++ classDisplay
  case mfg of
    Just m -> putStrLn $ indent ++ "    Manufacturer: " ++ BC.unpack m
    Nothing -> return ()
  case model of
    Just m -> putStrLn $ indent ++ "    Model: " ++ BC.unpack m
    Nothing -> return ()
  case serialNum of
    Just s -> putStrLn $ indent ++ "    Serial: " ++ BC.unpack s
    Nothing -> return ()
  case revision of
    Just r -> putStrLn $ indent ++ "    Revision: " ++ BC.unpack r
    Nothing -> return ()
  unless (null addresses) $ do
    putStrLn $ indent ++ "    Addresses:"
    forM_ addresses $ \(addrOid, addrVal) ->
      putStrLn $ indent ++ "      " ++ formatOIDWithName addrOid ++ ": " ++ BC.unpack addrVal

-- | Show a single component with details
showSingleComponent :: Bool -> (Int, ComponentIdentifier) -> IO ()
showSingleComponent _verbose (index, comp) = do
  putStrLn $ "  [" ++ show index ++ "] Component:"
  putStrLn $ "      Manufacturer: " ++ formatBS (ciManufacturer comp)
  putStrLn $ "      Model: " ++ formatBS (ciModel comp)
  case ciSerial comp of
    Just ser -> putStrLn $ "      Serial: " ++ formatBS ser
    Nothing -> return ()
  case ciRevision comp of
    Just rev -> putStrLn $ "      Revision: " ++ formatBS rev
    Nothing -> return ()

-- | Show detailed information for TCG attributes
showTCGAttribute :: TCGAttribute -> IO ()
showTCGAttribute attr = case attr of
  TCGPlatformManufacturer (PlatformManufacturerAttr mfg) ->
    putStrLn $ "  Platform Manufacturer: " ++ formatBS mfg
  TCGPlatformModel (PlatformModelAttr model) ->
    putStrLn $ "  Platform Model: " ++ formatBS model
  TCGPlatformSerial (PlatformSerialAttr serialNum) ->
    putStrLn $ "  Platform Serial: " ++ formatBS serialNum
  TCGPlatformVersion (PlatformVersionAttr version) ->
    putStrLn $ "  Platform Version: " ++ formatBS version
  TCGTPMModel (TPMModelAttr model) ->
    putStrLn $ "  TPM Model: " ++ formatBS model
  TCGComponentIdentifier (ComponentIdentifierAttr comp _) ->
    putStrLn $ "  Component: " ++ formatBS (ciManufacturer comp) ++ " " ++ formatBS (ciModel comp)
  TCGComponentIdentifierV2 (ComponentIdentifierV2Attr comp _ _) -> do
    putStrLn $ "  Component v2: " ++ formatBS (ci2Manufacturer comp) ++ " " ++ formatBS (ci2Model comp)
    putStrLn $ "      Class: " ++ componentClassName (ci2ComponentClass comp)
  -- Extended platform attributes with detailed display
  TCGPlatformConfigUri (PlatformConfigUriAttr uri desc) -> do
    putStrLn $ "  Platform Configuration URI: " ++ show uri
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGPlatformClass (PlatformClassAttr cls desc) -> do
    putStrLn $ "  Platform Class: " ++ show cls
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGCertificationLevel (CertificationLevelAttr lvl desc) -> do
    putStrLn $ "  Certification Level: " ++ show lvl ++ " (" ++ certificationLevelName lvl ++ ")"
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGPlatformQualifiers (PlatformQualifiersAttr quals desc) -> do
    putStrLn $ "  Platform Qualifiers (" ++ show (length quals) ++ "):"
    forM_ quals $ \qual -> putStrLn $ "    - " ++ show qual
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGRootOfTrust (RootOfTrustAttr measure alg desc) -> do
    putStrLn $ "  Root of Trust:"
    putStrLn $ "    Measurement: " ++ hexdump measure
    putStrLn $ "    Algorithm: " ++ show alg
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGRTMType (RTMTypeAttr typ desc) -> do
    putStrLn $ "  RTM Type: " ++ show typ ++ " (" ++ rtmTypeName typ ++ ")"
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGBootMode (BootModeAttr mode desc) -> do
    putStrLn $ "  Boot Mode: " ++ show mode
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGFirmwareVersion (FirmwareVersionAttr ver desc) -> do
    putStrLn $ "  Firmware Version: " ++ show ver
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  TCGPolicyReference (PolicyReferenceAttr uri desc) -> do
    putStrLn $ "  Policy Reference URI: " ++ show uri
    maybe (return ()) (\d -> putStrLn $ "    Description: " ++ show d) desc
  other -> putStrLn $ "  " ++ show other

-- | Show extended platform attributes summary
showExtendedPlatformAttributes :: [TCGAttribute] -> IO ()
showExtendedPlatformAttributes attrs = do
  let extendedAttrs = filter isExtendedAttribute attrs
  unless (null extendedAttrs) $ do
    putStrLn ""
    putStrLn "Extended Platform Attributes Summary:"
    forM_ extendedAttrs $ \attr -> case attr of
      TCGPlatformConfigUri (PlatformConfigUriAttr uri _) ->
        putStrLn $ "  ✓ Platform Configuration URI: " ++ show uri
      TCGPlatformClass (PlatformClassAttr cls _) ->
        putStrLn $ "  ✓ Platform Class: " ++ show cls
      TCGCertificationLevel (CertificationLevelAttr lvl _) ->
        putStrLn $ "  ✓ Certification Level: " ++ show lvl ++ " (" ++ certificationLevelName lvl ++ ")"
      TCGRootOfTrust (RootOfTrustAttr _ alg _) ->
        putStrLn $ "  ✓ Root of Trust (Algorithm: " ++ show alg ++ ")"
      TCGRTMType (RTMTypeAttr typ _) ->
        putStrLn $ "  ✓ RTM Type: " ++ rtmTypeName typ
      TCGBootMode (BootModeAttr mode _) ->
        putStrLn $ "  ✓ Boot Mode: " ++ show mode
      TCGFirmwareVersion (FirmwareVersionAttr ver _) ->
        putStrLn $ "  ✓ Firmware Version: " ++ show ver
      TCGPolicyReference (PolicyReferenceAttr uri _) ->
        putStrLn $ "  ✓ Policy Reference: " ++ show uri
      _ -> return ()

-- | Check if attribute is an extended platform attribute
isExtendedAttribute :: TCGAttribute -> Bool
isExtendedAttribute attr = case attr of
  TCGPlatformConfigUri _ -> True
  TCGPlatformClass _ -> True
  TCGCertificationLevel _ -> True
  TCGPlatformQualifiers _ -> True
  TCGRootOfTrust _ -> True
  TCGRTMType _ -> True
  TCGBootMode _ -> True
  TCGFirmwareVersion _ -> True
  TCGPolicyReference _ -> True
  _ -> False

-- | Get certification level name
certificationLevelName :: Int -> String
certificationLevelName lvl = case lvl of
  1 -> "Basic"
  2 -> "Standard"
  3 -> "Enhanced"
  4 -> "High"
  5 -> "Very High"
  6 -> "Critical"
  7 -> "Ultra"
  _ -> "Unknown"

-- | Get RTM type name
rtmTypeName :: Int -> String
rtmTypeName typ = case typ of
  1 -> "BIOS"
  2 -> "UEFI"
  3 -> "Other"
  _ -> "Unknown"

-- | Get component class name with OID display
componentClassName :: ComponentClass -> String
componentClassName cls = case cls of
  ComponentMotherboard -> "Motherboard"
  ComponentCPU -> "CPU"
  ComponentMemory -> "Memory"
  ComponentHardDrive -> "Hard Drive"
  ComponentNetworkInterface -> "Network Interface"
  ComponentGraphicsCard -> "Graphics Card"
  ComponentSoundCard -> "Sound Card"
  ComponentOpticalDrive -> "Optical Drive"
  ComponentKeyboard -> "Keyboard"
  ComponentMouse -> "Mouse"
  ComponentDisplay -> "Display"
  ComponentSpeaker -> "Speaker"
  ComponentMicrophone -> "Microphone"
  ComponentCamera -> "Camera"
  ComponentTouchscreen -> "Touchscreen"
  ComponentFingerprint -> "Fingerprint Reader"
  ComponentBluetooth -> "Bluetooth"
  ComponentWifi -> "WiFi"
  ComponentEthernet -> "Ethernet"
  ComponentUSB -> "USB"
  ComponentFireWire -> "FireWire"
  ComponentSCSI -> "SCSI"
  ComponentIDE -> "IDE"
  ComponentOther oid -> "Other (" ++ formatOIDWithName oid ++ ")"

-- | Extract ComponentIdentifiers from TCGAttributes
_extractComponentsFromTCGAttrs :: [TCGAttribute] -> [ComponentIdentifier]
_extractComponentsFromTCGAttrs = concatMap extractComp
  where
    extractComp (TCGComponentIdentifier (ComponentIdentifierAttr comp _)) = [comp]
    extractComp _ = []

-- | Extract ComponentIdentifierV2 from TCGAttributes
_extractComponentsV2FromTCGAttrs :: [TCGAttribute] -> [ComponentIdentifierV2]
_extractComponentsV2FromTCGAttrs = concatMap extractComp
  where
    extractComp (TCGComponentIdentifierV2 (ComponentIdentifierV2Attr comp _ _)) = [comp]
    extractComp _ = []

-- * Delta Certificate Display Functions

-- | Show detailed Delta Platform Certificate information
--
-- Displays certificate in an improved format with:
-- - Certificate type indicator (Delta Platform Certificate)
-- - Version and serial number
-- - Base certificate reference
-- - Component changes with status indicators
-- - Delta-specific attributes
showDeltaPlatformCert :: SignedDeltaPlatformCertificate -> IO ()
showDeltaPlatformCert signedCert = do
  let certInfo = getDeltaPlatformCertificate signedCert
      validity = dpciValidity certInfo
      baseRef = getBaseCertificateReference signedCert

  -- Header with certificate type
  putStrLn "Delta Platform Certificate Information:"
  putStrLn $ "  Version: v" ++ show (dpciVersion certInfo)
  putStrLn $ "  Serial Number: 0x" ++ showHex (dpciSerialNumber certInfo) ""
  putStrLn ""

  -- Issuer
  showIssuer (dpciIssuer certInfo)
  putStrLn ""

  -- Holder (EK Certificate)
  showHolder (dpciHolder certInfo)
  putStrLn ""

  -- Validity
  putStrLn "  Validity:"
  showValidityPeriod validity
  putStrLn ""

  -- Base Certificate Reference (Delta-specific)
  putStrLn "  Base Certificate Reference:"
  showBaseCertificateRef baseRef
  putStrLn ""

  -- Component Changes (Delta-specific)
  let componentDeltas = getComponentDeltas signedCert
  if null componentDeltas
    then putStrLn "  Component Changes: (none)"
    else do
      putStrLn $ "  Component Changes (" ++ show (length componentDeltas) ++ "):"
      forM_ (zip [1 ..] componentDeltas) $ \(i, delta) ->
        showComponentDelta i delta
  putStrLn ""

  -- Extensions with OID names
  showExtensionsImproved (dpciExtensions certInfo)

-- | Show base certificate reference information
showBaseCertificateRef :: BasePlatformCertificateRef -> IO ()
showBaseCertificateRef baseRef = do
  putStrLn $ "    Issuer: " ++ formatDN (bpcrIssuer baseRef)
  putStrLn $ "    Serial: 0x" ++ showHex (bpcrSerialNumber baseRef) ""
  case bpcrCertificateHash baseRef of
    Just hash -> putStrLn $ "    Certificate Hash: " ++ hexdump hash
    Nothing -> return ()
  case bpcrValidityPeriod baseRef of
    Just validity -> do
      putStr "    Validity: "
      case validity of
        AttCertValidityPeriod start end ->
          putStrLn $
            timePrint ("YYYY-MM-DD" :: String) start
              ++ " to "
              ++ timePrint ("YYYY-MM-DD" :: String) end
    Nothing -> return ()

-- | Show a single component delta with operation indicator
showComponentDelta :: Int -> ComponentDelta -> IO ()
showComponentDelta i delta = do
  let op = cdOperation delta
      comp = cdComponent delta
      statusLabel = formatDeltaOperation op
  putStrLn $ "    [" ++ show i ++ "] " ++ statusLabel ++ " " ++ componentClassName (ci2ComponentClass comp)
        ++ " (" ++ formatComponentClassHex (ci2ComponentClass comp) ++ ")"
  putStrLn $ "        Manufacturer: " ++ formatBS (ci2Manufacturer comp)
  putStrLn $ "        Model: " ++ formatBS (ci2Model comp)
  case ci2Serial comp of
    Just ser -> putStrLn $ "        Serial: " ++ formatBS ser
    Nothing -> return ()
  -- Show previous component for replace/modify operations
  case (op, cdPreviousComponent delta) of
    (DeltaReplace, Just prev) -> do
      putStrLn "        (Replaced)"
      putStrLn $ "          Previous: " ++ formatBS (ci2Manufacturer prev) ++ " / " ++ formatBS (ci2Model prev)
    (DeltaModify, Just prev) -> do
      putStrLn "        (Modified)"
      putStrLn $ "          Previous: " ++ formatBS (ci2Manufacturer prev) ++ " / " ++ formatBS (ci2Model prev)
    _ -> return ()

-- | Show delta operation in human-readable format
showDeltaOperation :: DeltaOperation -> IO ()
showDeltaOperation op = putStrLn $ "Operation: " ++ formatDeltaOperation op

-- | Format a DeltaOperation as a status label
formatDeltaOperation :: DeltaOperation -> String
formatDeltaOperation op = case op of
  DeltaAdd -> "[ADDED]"
  DeltaRemove -> "[REMOVED]"
  DeltaModify -> "[MODIFIED]"
  DeltaReplace -> "[REPLACED]"
  DeltaUpdate -> "[UPDATED]"