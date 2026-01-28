{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Data.X509.TCG.Platform
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Platform Certificate data structures and processing.
--
-- This module implements Platform Certificates as defined in the IWG Platform
-- Certificate Profile v1.1. Platform Certificates are attribute certificates
-- that bind platform configuration information to a platform identity.
module Data.X509.TCG.Platform
  ( -- * Platform Certificate Types
    PlatformCertificateInfo (..),
    SignedPlatformCertificate,

    -- * Platform Configuration
    PlatformConfiguration (..),
    ExtendedPlatformConfiguration (..),
    PlatformConfigurationV2 (..),
    ComponentStatus (..),

    -- * Platform Information
    PlatformInfo (..),
    TPMInfo (..),
    TPMSpecification (..),
    TPMVersion (..),

    -- * Marshalling Operations
    encodeSignedPlatformCertificate,
    decodeSignedPlatformCertificate,

    -- * Accessor Functions
    getPlatformCertificate,
    getPlatformConfiguration,
    getPlatformInfo,
    getTPMInfo,
    getComponentStatus,

    -- * Parsing Functions  
    parsePlatformConfiguration,
    parsePlatformConfigurationV2,
    parseTPMVersion,
    parseTPMSpecification,
  )
where

import Data.ASN1.Types
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.BinaryEncoding (DER(..))
import qualified Data.ByteString as B
import Data.List (find)
import Data.X509 (Extensions(..), SignatureALG, SignedExact, decodeSignedObject, encodeSignedObject, getSigned, signedObject)
import Data.X509.AttCert (AttCertIssuer, AttCertValidityPeriod, Holder, UniqueID)
import Data.X509.Attribute (AttributeValue, Attributes(..), Attribute(..), attrType, attrValues)
import Data.X509.TCG.Component (ComponentIdentifier, ComponentIdentifierV2)

-- | Platform Certificate Information structure
--
-- This is similar to AttributeCertificateInfo but specifically for Platform Certificates
-- as defined in the IWG specification.
data PlatformCertificateInfo = PlatformCertificateInfo
  { pciVersion :: Int, -- Must be 2 (v2)
    pciHolder :: Holder,
    pciIssuer :: AttCertIssuer,
    pciSignature :: SignatureALG,
    pciSerialNumber :: Integer,
    pciValidity :: AttCertValidityPeriod,
    pciAttributes :: Attributes,
    pciIssuerUniqueID :: Maybe UniqueID,
    pciExtensions :: Extensions
  }
  deriving (Show, Eq)

-- | ASN1Object instance for PlatformCertificateInfo
instance ASN1Object PlatformCertificateInfo where
  toASN1 (PlatformCertificateInfo pciVer pciHolder' pciIssuer' pciSig pciSn pciValid pciAttrs pciUid pciExts) xs =
    ( [Start Sequence]
        ++ [IntVal $ fromIntegral pciVer]
        ++ toASN1 pciHolder' []
        ++ toASN1 pciIssuer' []
        ++ toASN1 pciSig []
        ++ [IntVal pciSn]
        ++ toASN1 pciValid []
        ++ toASN1 pciAttrs []
        ++ maybe [] (\u -> [BitString u]) pciUid
        ++ toASN1 pciExts []
        ++ [End Sequence]
    )
      ++ xs
  -- Note: decodeSignedObject strips the outer SEQUENCE before calling fromASN1.
  -- For direct fromASN1 calls (e.g., property tests), the SEQUENCE is present.
  -- We handle both cases by checking the first element.
  fromASN1 [] = Left "PlatformCertificateInfo: empty input"
  fromASN1 (Start Sequence : IntVal ver : rest) = parsePCIContent ver rest True
  fromASN1 (IntVal ver : rest) = parsePCIContent ver rest False
  fromASN1 _ = Left "PlatformCertificateInfo: Invalid ASN1 structure"

-- | Parse PlatformCertificateInfo content after version
-- @hasOuterSequence@ indicates whether to expect End Sequence at the end
parsePCIContent :: Integer -> [ASN1] -> Bool -> Either String (PlatformCertificateInfo, [ASN1])
parsePCIContent ver rest hasOuterSequence = do
  (holder, rest1) <- fromASN1 rest
  (issuer, rest2) <- fromASN1 rest1
  (signature, rest3) <- fromASN1 rest2
  case rest3 of
    (IntVal serialNum : rest4) -> do
      (validity, rest5) <- fromASN1 rest4
      (attributes, rest6) <- fromASN1 rest5
      let (uid, rest7) = extractUID rest6
          (extensions, rest8) = extractExtensions rest7
      if hasOuterSequence
        then case rest8 of
          (End Sequence : remaining) ->
            Right (PlatformCertificateInfo (fromIntegral ver) holder issuer signature serialNum validity attributes uid extensions, remaining)
          _ -> Left "PlatformCertificateInfo: Invalid ASN1 sequence termination"
        else
          Right (PlatformCertificateInfo (fromIntegral ver) holder issuer signature serialNum validity attributes uid extensions, rest8)
    _ -> Left "PlatformCertificateInfo: Missing serial number"

-- Helper functions for ASN.1 parsing
extractUID :: [ASN1] -> (Maybe UniqueID, [ASN1])
extractUID (BitString uid : rest) = (Just uid, rest)
extractUID rest = (Nothing, rest)

extractExtensions :: [ASN1] -> (Extensions, [ASN1])
extractExtensions asn1 = case fromASN1 asn1 of
  Right (exts, rest) -> (exts, rest)
  Left _ -> (Extensions Nothing, asn1)  -- No extensions present

-- | A Signed Platform Certificate
type SignedPlatformCertificate = SignedExact PlatformCertificateInfo

-- | Platform Configuration structure (v1)
--
-- Contains basic platform configuration information without status tracking.
data PlatformConfiguration = PlatformConfiguration
  { pcManufacturer :: B.ByteString,
    pcModel :: B.ByteString,
    pcVersion :: B.ByteString,
    pcSerial :: B.ByteString,
    pcComponents :: [ComponentIdentifier]
  }
  deriving (Show, Eq)

-- | Extended Platform Configuration structure  
--
-- Enhanced version with additional platform metadata fields as defined in
-- IWG Platform Certificate Profile v1.1.
data ExtendedPlatformConfiguration = ExtendedPlatformConfiguration
  { epcManufacturer :: B.ByteString,
    epcModel :: B.ByteString,
    epcVersion :: B.ByteString,
    epcSerial :: B.ByteString,
    epcComponents :: [ComponentIdentifier],
    -- Extended fields from IWG Platform Certificate Profile v1.1
    epcPlatformConfigUri :: Maybe B.ByteString,      -- Platform Configuration URI
    epcPlatformClass :: Maybe B.ByteString,          -- Platform Class identifier
    epcSpecificationVersion :: Maybe B.ByteString,   -- TCG specification version
    epcMajorVersion :: Maybe Int,                    -- Major version number
    epcMinorVersion :: Maybe Int,                    -- Minor version number
    epcPatchVersion :: Maybe Int,                    -- Patch version number
    epcPlatformQualifier :: Maybe B.ByteString,      -- Platform qualifier (Enterprise, Consumer, etc.)
    -- TCG Credential Specification (2.23.133.2.23) fields
    epcCredentialSpecMajor :: Maybe Int,             -- Credential spec major version (e.g., 1)
    epcCredentialSpecMinor :: Maybe Int,             -- Credential spec minor version (e.g., 1)
    epcCredentialSpecRevision :: Maybe Int,          -- Credential spec revision (e.g., 13)
    -- TCG Platform Specification (2.23.133.2.17) fields
    epcPlatformSpecMajor :: Maybe Int,               -- Platform spec major version (e.g., 2 for TPM 2.0)
    epcPlatformSpecMinor :: Maybe Int,               -- Platform spec minor version (e.g., 0)
    epcPlatformSpecRevision :: Maybe Int,            -- Platform spec revision (e.g., 164)
    -- Additional platform fields
    epcCertificationLevel :: Maybe Int,              -- Certification level (1-7)
    epcPlatformQualifiers :: Maybe [B.ByteString],   -- List of platform qualifiers
    epcRootOfTrust :: Maybe B.ByteString,            -- Root of Trust information
    epcRTMType :: Maybe Int,                         -- RTM Type (1=BIOS, 2=UEFI, 3=Other)
    epcBootMode :: Maybe B.ByteString,               -- Boot mode information
    epcFirmwareVersion :: Maybe B.ByteString,        -- Firmware version
    epcPolicyReference :: Maybe B.ByteString         -- Policy reference URI
  }
  deriving (Show, Eq)

-- | Platform Configuration structure (v2)
--
-- Enhanced version with component status tracking for Delta Platform Certificates.
data PlatformConfigurationV2 = PlatformConfigurationV2
  { pcv2Manufacturer :: B.ByteString,
    pcv2Model :: B.ByteString,
    pcv2Version :: B.ByteString,
    pcv2Serial :: B.ByteString,
    pcv2Components :: [(ComponentIdentifierV2, ComponentStatus)]
  }
  deriving (Show, Eq)

-- | Component Status enumeration
--
-- Tracks the status of components in Platform Configuration v2.
data ComponentStatus
  = -- | Component was added to the platform
    ComponentAdded
  | -- | Component was removed from the platform
    ComponentRemoved
  | -- | Component was modified on the platform
    ComponentModified
  | -- | Component remains unchanged
    ComponentUnchanged
  deriving (Show, Eq, Enum)

-- | Platform Information structure
--
-- High-level platform identification and characteristics.
data PlatformInfo = PlatformInfo
  { piManufacturer :: B.ByteString,
    piModel :: B.ByteString,
    piSerial :: B.ByteString,
    piVersion :: B.ByteString
  }
  deriving (Show, Eq)

-- | TPM Information structure
--
-- Contains TPM-specific identification and specification information.
data TPMInfo = TPMInfo
  { tpmModel :: B.ByteString,
    tpmVersion :: TPMVersion,
    tpmSpecification :: TPMSpecification
  }
  deriving (Show, Eq)

-- | TPM Version information
data TPMVersion = TPMVersion
  { tpmVersionMajor :: Int,
    tpmVersionMinor :: Int,
    tpmVersionRevMajor :: Int,
    tpmVersionRevMinor :: Int
  }
  deriving (Show, Eq)

-- | TPM Specification information
data TPMSpecification = TPMSpecification
  { tpmSpecFamily :: B.ByteString,
    tpmSpecLevel :: Int,
    tpmSpecRevision :: Int
  }
  deriving (Show, Eq)

-- | Encode a SignedPlatformCertificate to a DER-encoded bytestring
encodeSignedPlatformCertificate :: SignedPlatformCertificate -> B.ByteString
encodeSignedPlatformCertificate = encodeSignedObject

-- | Decode a DER-encoded bytestring to a SignedPlatformCertificate
decodeSignedPlatformCertificate :: B.ByteString -> Either String SignedPlatformCertificate
decodeSignedPlatformCertificate = decodeSignedObject

-- | Extract the PlatformCertificateInfo from a SignedPlatformCertificate
getPlatformCertificate :: SignedPlatformCertificate -> PlatformCertificateInfo
getPlatformCertificate = signedObject . getSigned

-- | Extract Platform Configuration from a Platform Certificate
--
-- This function searches for the tcg-at-platformConfiguration attribute
-- (OID 2.23.133.2.1) and parses it into a structured PlatformConfiguration.
--
-- The platform configuration provides detailed information about:
-- * Platform manufacturer, model, version, and serial number
-- * Complete list of platform components with their identifiers
-- * Component hierarchy and relationships
--
-- Example usage:
-- @
-- case getPlatformConfiguration cert of
--   Just config -> do
--     putStrLn $ "Platform: " ++ B.unpack (pcManufacturer config)
--     putStrLn $ "Components: " ++ show (length $ pcComponents config)
--   Nothing -> putStrLn "No platform configuration found in certificate"
-- @
getPlatformConfiguration :: SignedPlatformCertificate -> Maybe PlatformConfiguration
getPlatformConfiguration cert =
  case lookupAttribute "2.23.133.2.1" (pciAttributes $ getPlatformCertificate cert) of
    Just attrVal -> parsePlatformConfiguration attrVal
    Nothing -> Nothing

-- | Extract Platform Information from a Platform Certificate
--
-- Extracts basic platform identification attributes.
getPlatformInfo :: SignedPlatformCertificate -> Maybe PlatformInfo
getPlatformInfo cert = do
  let attrs = pciAttributes $ getPlatformCertificate cert
  manufacturer <- lookupAttributeValue "2.23.133.2.4" attrs -- tcg-at-platformManufacturer
  model <- lookupAttributeValue "2.23.133.2.5" attrs -- tcg-at-platformModel
  serial <- lookupAttributeValue "2.23.133.2.6" attrs -- tcg-at-platformSerial
  version <- lookupAttributeValue "2.23.133.2.7" attrs -- tcg-at-platformVersion
  return $ PlatformInfo manufacturer model serial version

-- | Extract TPM Information from a Platform Certificate
--
-- Extracts TPM-specific identification and specification attributes.
getTPMInfo :: SignedPlatformCertificate -> Maybe TPMInfo
getTPMInfo cert = do
  let attrs = pciAttributes $ getPlatformCertificate cert
  model <- lookupAttributeValue "2.23.133.2.16" attrs -- tcg-at-tpmModel
  versionData <- lookupAttributeValue "2.23.133.2.17" attrs -- tcg-at-tpmVersion
  specData <- lookupAttributeValue "2.23.133.2.18" attrs -- tcg-at-tpmSpecification
  version <- parseTPMVersion versionData
  spec <- parseTPMSpecification specData
  return $ TPMInfo model version spec

-- | Extract Component Status information for Delta Platform Certificates
getComponentStatus :: SignedPlatformCertificate -> Maybe [(ComponentIdentifierV2, ComponentStatus)]
getComponentStatus cert = do
  config <- getPlatformConfigurationV2 cert
  return $ pcv2Components config

-- * Helper Functions

-- | Lookup an attribute value by OID string
--
-- This function searches through the attributes list to find an attribute
-- with the specified OID and returns its value if found.
--
-- Example:
-- @
-- case lookupAttribute "2.23.133.2.1" platformAttrs of
--   Just value -> processPlatformConfig value
--   Nothing -> handleMissingConfig
-- @
lookupAttribute :: String -> Attributes -> Maybe AttributeValue
lookupAttribute oidStr (Attributes attrs) = 
  case parseOIDString oidStr of
    Just targetOid -> 
      case find (\attr -> attrType attr == targetOid) attrs of
        Just attr -> case attrValues attr of
          [[value]] -> Just value  -- Expecting single value
          (values:_) -> case values of
            (value:_) -> Just value  -- Take first value from first set
            [] -> Nothing
          _ -> Nothing
        Nothing -> Nothing
    Nothing -> Nothing
  where
    -- Parse OID string like "2.23.133.2.1" into OID list
    parseOIDString :: String -> Maybe OID
    parseOIDString str = 
      let parts = words $ map (\c -> if c == '.' then ' ' else c) str
      in traverse readMaybe parts
    
    readMaybe :: String -> Maybe Integer
    readMaybe s = case reads s of
      [(x, "")] -> Just x
      _ -> Nothing

-- | Extract attribute value as ByteString by OID
--
-- This function combines attribute lookup with ByteString extraction,
-- providing a convenient way to access string-based attribute values.
--
-- Parameters:
-- * @oid@ - The OID string to search for
-- * @attrs@ - The attributes list to search in
--
-- Returns:
-- * @Just ByteString@ if the attribute is found and contains a valid string
-- * @Nothing@ if the attribute is missing or has invalid format
--
-- Example:
-- @
-- manufacturerName <- lookupAttributeValue "2.23.133.2.2" attrs
-- @
lookupAttributeValue :: String -> Attributes -> Maybe B.ByteString
lookupAttributeValue oid attrs = do
  attrVal <- lookupAttribute oid attrs
  case attrVal of
    OctetString str -> Just str
    _ -> Nothing

-- | Parse Platform Configuration from AttributeValue
--
-- According to section 3.1.6 of the specification, the PlatformConfiguration
-- structure is defined as:
--
-- PlatformConfiguration ::= SEQUENCE {
--   platformManufacturer    UTF8String OPTIONAL,
--   platformModel          UTF8String OPTIONAL, 
--   platformVersion        UTF8String OPTIONAL,
--   platformSerial         UTF8String OPTIONAL,
--   components             SEQUENCE OF ComponentIdentifier OPTIONAL
-- }
parsePlatformConfiguration :: AttributeValue -> Maybe PlatformConfiguration
parsePlatformConfiguration (OctetString bytes) = 
  case decodeASN1' DER bytes of
    Right asn1 -> case fromASN1 asn1 of
      Right (config, []) -> Just config
      _ -> Nothing
    Left _ -> Nothing
parsePlatformConfiguration _ = Nothing

-- | Extract Platform Configuration v2 from a Platform Certificate
getPlatformConfigurationV2 :: SignedPlatformCertificate -> Maybe PlatformConfigurationV2
getPlatformConfigurationV2 cert =
  case lookupAttribute "2.23.133.2.23" (pciAttributes $ getPlatformCertificate cert) of
    Just attrVal -> parsePlatformConfigurationV2 attrVal
    Nothing -> Nothing

-- | Parse Platform Configuration v2 from AttributeValue
--
-- According to section 3.1.7 of the specification, the PlatformConfigurationV2
-- structure is defined as:
--
-- PlatformConfigurationV2 ::= SEQUENCE {
--   platformManufacturer    UTF8String OPTIONAL,
--   platformModel          UTF8String OPTIONAL, 
--   platformVersion        UTF8String OPTIONAL,
--   platformSerial         UTF8String OPTIONAL,
--   components             SEQUENCE OF ComponentIdentifierV2 OPTIONAL
-- }
parsePlatformConfigurationV2 :: AttributeValue -> Maybe PlatformConfigurationV2
parsePlatformConfigurationV2 (OctetString bytes) = 
  case decodeASN1' DER bytes of
    Right asn1 -> case fromASN1 asn1 of
      Right (config, []) -> Just config
      _ -> Nothing
    Left _ -> Nothing
parsePlatformConfigurationV2 _ = Nothing

-- | Parse TPM Version from ByteString
--
-- According to section 3.1.11 of the specification, the TPMVersion
-- structure is defined as:
--
-- TPMVersion ::= SEQUENCE {
--   major         INTEGER,
--   minor         INTEGER,
--   revMajor      INTEGER,
--   revMinor      INTEGER
-- }
parseTPMVersion :: B.ByteString -> Maybe TPMVersion
parseTPMVersion bytes = 
  case decodeASN1' DER bytes of
    Right asn1 -> case fromASN1 asn1 of
      Right (version, []) -> Just version
      _ -> Nothing
    Left _ -> Nothing

-- | Parse TPM Specification from ByteString
--
-- According to section 3.1.12 of the specification, the TPMSpecification
-- structure is defined as:
--
-- TPMSpecification ::= SEQUENCE {
--   family        UTF8String,
--   level         INTEGER,
--   revision      INTEGER
-- }
parseTPMSpecification :: B.ByteString -> Maybe TPMSpecification
parseTPMSpecification bytes = 
  case decodeASN1' DER bytes of
    Right asn1 -> case fromASN1 asn1 of
      Right (spec, []) -> Just spec
      _ -> Nothing
    Left _ -> Nothing

-- ASN.1 instances for basic types

instance ASN1Object PlatformConfiguration where
  toASN1 (PlatformConfiguration manufacturer model version serial components) xs =
    [Start Sequence, OctetString manufacturer, OctetString model, OctetString version, OctetString serial] 
    ++ [Start Sequence] ++ concatMap (`toASN1` []) components ++ [End Sequence, End Sequence] ++ xs
  fromASN1 (Start Sequence : OctetString manufacturer : OctetString model : OctetString version : OctetString serial : Start Sequence : rest) =
    case parseComponentList rest of
      Right (components, End Sequence : End Sequence : remaining) -> 
        Right (PlatformConfiguration manufacturer model version serial components, remaining)
      _ -> Left "PlatformConfiguration: Invalid component sequence"
  fromASN1 _ = Left "PlatformConfiguration: Invalid ASN1 structure"

-- Helper function to parse component list
parseComponentList :: [ASN1] -> Either String ([ComponentIdentifier], [ASN1])
parseComponentList asn1 = parseComponents asn1 []
  where
    parseComponents [] acc = Right (reverse acc, [])
    parseComponents (End Sequence : rest) acc = Right (reverse acc, End Sequence : rest)
    parseComponents remaining acc = 
      case fromASN1 remaining of
        Right (component, rest') -> parseComponents rest' (component : acc)
        Left err -> Left err

instance ASN1Object PlatformConfigurationV2 where
  toASN1 (PlatformConfigurationV2 manufacturer model version serial components) xs =
    [Start Sequence, OctetString manufacturer, OctetString model, OctetString version, OctetString serial] 
    ++ [Start Sequence] ++ concatMap (\(comp, status) -> toASN1 comp [] ++ toASN1 status []) components ++ [End Sequence, End Sequence] ++ xs
  fromASN1 (Start Sequence : OctetString manufacturer : OctetString model : OctetString version : OctetString serial : Start Sequence : rest) =
    case parseComponentListV2 rest of
      Right (components, End Sequence : End Sequence : remaining) -> 
        Right (PlatformConfigurationV2 manufacturer model version serial components, remaining)
      _ -> Left "PlatformConfigurationV2: Invalid component sequence"
  fromASN1 _ = Left "PlatformConfigurationV2: Invalid ASN1 structure"

-- Helper function to parse component list with status
parseComponentListV2 :: [ASN1] -> Either String ([(ComponentIdentifierV2, ComponentStatus)], [ASN1])
parseComponentListV2 asn1 = parseComponentsV2 asn1 []
  where
    parseComponentsV2 [] acc = Right (reverse acc, [])
    parseComponentsV2 (End Sequence : rest) acc = Right (reverse acc, End Sequence : rest)
    parseComponentsV2 remaining acc = 
      case fromASN1 remaining of
        Right (component, rest') -> 
          case fromASN1 rest' of
            Right (status, rest'') -> parseComponentsV2 rest'' ((component, status) : acc)
            Left err -> Left err
        Left err -> Left err

instance ASN1Object TPMVersion where
  toASN1 (TPMVersion major minor revMajor revMinor) xs =
    [Start Sequence, IntVal (fromIntegral major), IntVal (fromIntegral minor), 
     IntVal (fromIntegral revMajor), IntVal (fromIntegral revMinor), End Sequence] ++ xs
  fromASN1 (Start Sequence : IntVal major : IntVal minor : IntVal revMajor : IntVal revMinor : End Sequence : xs) =
    Right (TPMVersion (fromIntegral major) (fromIntegral minor) (fromIntegral revMajor) (fromIntegral revMinor), xs)
  fromASN1 _ = Left "TPMVersion: Invalid ASN1 structure"

instance ASN1Object TPMSpecification where  
  toASN1 (TPMSpecification family level revision) xs =
    [Start Sequence, OctetString family, IntVal (fromIntegral level), IntVal (fromIntegral revision), End Sequence] ++ xs
  fromASN1 (Start Sequence : OctetString family : IntVal level : IntVal revision : End Sequence : xs) =
    Right (TPMSpecification family (fromIntegral level) (fromIntegral revision), xs)
  fromASN1 _ = Left "TPMSpecification: Invalid ASN1 structure"

instance ASN1Object ComponentStatus where
  toASN1 status xs = [IntVal (fromIntegral $ fromEnum status)] ++ xs
  fromASN1 (IntVal n : xs) 
    | n >= 0 && n <= 3 = Right (toEnum (fromIntegral n), xs)
    | otherwise = Left "ComponentStatus: Invalid enum value"
  fromASN1 _ = Left "ComponentStatus: Invalid ASN1 structure"

instance ASN1Object ExtendedPlatformConfiguration where
  toASN1 (ExtendedPlatformConfiguration mfg model ver serial comps configUri platClass specVer
          majVer minVer patchVer platQual credSpecMaj credSpecMin credSpecRev
          platSpecMaj platSpecMin platSpecRev certLvl quals rot rtmType bootMode fwVer polRef) xs =
    [Start Sequence]
    ++ [OctetString mfg, OctetString model, OctetString ver, OctetString serial]
    ++ [Start Sequence] ++ concatMap (\comp -> toASN1 comp []) comps ++ [End Sequence]
    -- Optional extended fields
    ++ maybe [] (\uri -> [OctetString uri]) configUri
    ++ maybe [] (\cls -> [OctetString cls]) platClass
    ++ maybe [] (\spec -> [OctetString spec]) specVer
    ++ maybe [] (\maj -> [IntVal (fromIntegral maj)]) majVer
    ++ maybe [] (\min' -> [IntVal (fromIntegral min')]) minVer
    ++ maybe [] (\patch -> [IntVal (fromIntegral patch)]) patchVer
    ++ maybe [] (\qual -> [OctetString qual]) platQual
    ++ maybe [] (\maj -> [IntVal (fromIntegral maj)]) credSpecMaj
    ++ maybe [] (\min' -> [IntVal (fromIntegral min')]) credSpecMin
    ++ maybe [] (\rev -> [IntVal (fromIntegral rev)]) credSpecRev
    ++ maybe [] (\maj -> [IntVal (fromIntegral maj)]) platSpecMaj
    ++ maybe [] (\min' -> [IntVal (fromIntegral min')]) platSpecMin
    ++ maybe [] (\rev -> [IntVal (fromIntegral rev)]) platSpecRev
    ++ maybe [] (\lvl -> [IntVal (fromIntegral lvl)]) certLvl
    ++ maybe [] (\qs -> [Start Sequence] ++ concatMap (\q -> [OctetString q]) qs ++ [End Sequence]) quals
    ++ maybe [] (\r -> [OctetString r]) rot
    ++ maybe [] (\rt -> [IntVal (fromIntegral rt)]) rtmType
    ++ maybe [] (\bm -> [OctetString bm]) bootMode
    ++ maybe [] (\fw -> [OctetString fw]) fwVer
    ++ maybe [] (\pol -> [OctetString pol]) polRef
    ++ [End Sequence]
    ++ xs
    
  fromASN1 (Start Sequence : OctetString mfg : OctetString model : OctetString ver : OctetString serial : Start Sequence : rest) = do
    (comps, rest') <- parseExtendedComponentList rest []
    -- Parse optional fields (simplified implementation)
    parseExtendedFields rest' mfg model ver serial comps Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing
    where
      parseExtendedComponentList (End Sequence : remaining) acc = Right (reverse acc, remaining)
      parseExtendedComponentList remaining acc = do
        (comp, rest'') <- fromASN1 remaining
        parseExtendedComponentList rest'' (comp : acc)
      parseExtendedFields (End Sequence : xs) mfg' model' ver' serial' comps' configUri' platClass' specVer' majVer' minVer' patchVer' platQual' credSpecMaj' credSpecMin' credSpecRev' platSpecMaj' platSpecMin' platSpecRev' certLvl' quals' rot' rtmType' bootMode' fwVer' polRef' =
        Right (ExtendedPlatformConfiguration mfg' model' ver' serial' comps' configUri' platClass' specVer' majVer' minVer' patchVer' platQual' credSpecMaj' credSpecMin' credSpecRev' platSpecMaj' platSpecMin' platSpecRev' certLvl' quals' rot' rtmType' bootMode' fwVer' polRef', xs)
      parseExtendedFields (OctetString val : rest'') mfg' model' ver' serial' comps' Nothing platClass' specVer' majVer' minVer' patchVer' platQual' credSpecMaj' credSpecMin' credSpecRev' platSpecMaj' platSpecMin' platSpecRev' certLvl' quals' rot' rtmType' bootMode' fwVer' polRef' =
        parseExtendedFields rest'' mfg' model' ver' serial' comps' (Just val) platClass' specVer' majVer' minVer' patchVer' platQual' credSpecMaj' credSpecMin' credSpecRev' platSpecMaj' platSpecMin' platSpecRev' certLvl' quals' rot' rtmType' bootMode' fwVer' polRef'
      parseExtendedFields _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ =
        Left "ExtendedPlatformConfiguration: Could not parse extended fields"
  fromASN1 _ = Left "ExtendedPlatformConfiguration: Expected Start Sequence"