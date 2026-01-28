{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Data.X509.TCG.Attributes
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Platform Certificate attributes and attribute processing.
--
-- This module implements the specific attributes defined in the IWG Platform
-- Certificate Profile v1.1, including Platform Configuration, Component
-- Identification, and TPM-related attributes.
module Data.X509.TCG.Attributes
  ( -- * TCG Attribute Types
    TCGAttribute (..),
    TCGAttributeValue (..),

    -- * Platform Configuration Attributes
    PlatformConfigurationAttr (..),
    PlatformConfigurationV2Attr (..),

    -- * Component Attributes
    ComponentIdentifierAttr (..),
    ComponentIdentifierV2Attr (..),
    ComponentClassAttr (..),

    -- * Platform Information Attributes
    PlatformManufacturerAttr (..),
    PlatformModelAttr (..),
    PlatformSerialAttr (..),
    PlatformVersionAttr (..),

    -- * TPM Attributes
    TPMModelAttr (..),
    TPMVersionAttr (..),
    TPMSpecificationAttr (..),

    -- * Certificate Extension Attributes
    RelevantCredentialsAttr (..),
    RelevantManifestsAttr (..),
    VirtualPlatformAttr (..),
    MultiTenantAttr (..),
    
    -- * Extended Platform Attributes (IWG v1.1)
    PlatformConfigUriAttr (..),
    PlatformClassAttr (..),
    CertificationLevelAttr (..),
    PlatformQualifiersAttr (..),
    RootOfTrustAttr (..),
    RTMTypeAttr (..),
    BootModeAttr (..),
    FirmwareVersionAttr (..),
    PolicyReferenceAttr (..),

    -- * Attribute Parsing and Encoding
    parseTCGAttribute,
    encodeTCGAttribute,
    lookupTCGAttribute,
    validateTCGAttributes,
    parsePlatformConfigAttr,
    parsePlatformConfigV2Attr,
    parseComponentIdAttr,
    parseComponentIdV2Attr,
    parseTPMVersionAttr,
    parseTPMSpecAttr,
    parseRelevantCredAttr,

    -- * Attribute Utilities
    attributeOIDToType,
    attributeTypeToOID,
    isRequiredAttribute,
    isCriticalAttribute,
  )
where

import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.Encoding (decodeASN1', encodeASN1)
import Data.ASN1.Types
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.Map.Strict as Map
import Data.X509.Attribute (Attribute (..), AttributeValue)
import Data.X509.TCG.Component (ComponentClass, ComponentIdentifier, ComponentIdentifierV2)
import Data.X509.TCG.OID
import Data.X509.TCG.Platform (PlatformConfiguration, PlatformConfigurationV2, TPMSpecification, TPMVersion)

-- | TCG Attribute enumeration
--
-- Represents all types of attributes defined in the TCG specifications.
data TCGAttribute
  = TCGPlatformConfiguration PlatformConfigurationAttr
  | TCGPlatformConfigurationV2 PlatformConfigurationV2Attr
  | TCGComponentIdentifier ComponentIdentifierAttr
  | TCGComponentIdentifierV2 ComponentIdentifierV2Attr
  | TCGComponentClass ComponentClassAttr
  | TCGPlatformManufacturer PlatformManufacturerAttr
  | TCGPlatformModel PlatformModelAttr
  | TCGPlatformSerial PlatformSerialAttr
  | TCGPlatformVersion PlatformVersionAttr
  | TCGTPMModel TPMModelAttr
  | TCGTPMVersion TPMVersionAttr
  | TCGTPMSpecification TPMSpecificationAttr
  | TCGRelevantCredentials RelevantCredentialsAttr
  | TCGRelevantManifests RelevantManifestsAttr
  | TCGVirtualPlatform VirtualPlatformAttr
  | TCGMultiTenant MultiTenantAttr
  -- | Extended platform attributes (IWG v1.1)
  | TCGPlatformConfigUri PlatformConfigUriAttr
  | TCGPlatformClass PlatformClassAttr
  | TCGCertificationLevel CertificationLevelAttr
  | TCGPlatformQualifiers PlatformQualifiersAttr
  | TCGRootOfTrust RootOfTrustAttr
  | TCGRTMType RTMTypeAttr
  | TCGBootMode BootModeAttr
  | TCGFirmwareVersion FirmwareVersionAttr
  | TCGPolicyReference PolicyReferenceAttr
  | -- | For unknown/custom attributes
    TCGOtherAttribute OID B.ByteString
  deriving (Show, Eq)

-- | TCG Attribute Value wrapper
data TCGAttributeValue = TCGAttributeValue
  { tcgAttrOID :: OID,
    tcgAttrValue :: B.ByteString,
    tcgAttrCritical :: Bool
  }
  deriving (Show, Eq)

-- * Platform Configuration Attributes

-- | Platform Configuration attribute (v1)
data PlatformConfigurationAttr = PlatformConfigurationAttr
  { pcaConfiguration :: PlatformConfiguration,
    pcaTimestamp :: Maybe B.ByteString,
    pcaCertificationLevel :: Maybe Int
  }
  deriving (Show, Eq)

-- | Platform Configuration attribute (v2) with status tracking
data PlatformConfigurationV2Attr = PlatformConfigurationV2Attr
  { pcv2aConfiguration :: PlatformConfigurationV2,
    pcv2aTimestamp :: Maybe B.ByteString,
    pcv2aCertificationLevel :: Maybe Int,
    pcv2aChangeSequence :: Maybe Integer
  }
  deriving (Show, Eq)

-- * Component Attributes

-- | Component Identifier attribute (v1)
data ComponentIdentifierAttr = ComponentIdentifierAttr
  { ciaIdentifier :: ComponentIdentifier,
    ciaTimestamp :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Component Identifier attribute (v2)
data ComponentIdentifierV2Attr = ComponentIdentifierV2Attr
  { ci2aIdentifier :: ComponentIdentifierV2,
    ci2aTimestamp :: Maybe B.ByteString,
    ci2aCertificationInfo :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Component Class attribute
data ComponentClassAttr = ComponentClassAttr
  { ccaClass :: ComponentClass,
    ccaDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- * Platform Information Attributes

-- | Platform Manufacturer attribute
newtype PlatformManufacturerAttr = PlatformManufacturerAttr
  { pmaManufacturer :: B.ByteString
  }
  deriving (Show, Eq)

-- | Platform Model attribute
newtype PlatformModelAttr = PlatformModelAttr
  { pmdaModel :: B.ByteString
  }
  deriving (Show, Eq)

-- | Platform Serial attribute
newtype PlatformSerialAttr = PlatformSerialAttr
  { psaSerial :: B.ByteString
  }
  deriving (Show, Eq)

-- | Platform Version attribute
newtype PlatformVersionAttr = PlatformVersionAttr
  { pvaVersion :: B.ByteString
  }
  deriving (Show, Eq)

-- * TPM Attributes

-- | TPM Model attribute
newtype TPMModelAttr = TPMModelAttr
  { tmaModel :: B.ByteString
  }
  deriving (Show, Eq)

-- | TPM Version attribute
newtype TPMVersionAttr = TPMVersionAttr
  { tvaVersion :: TPMVersion
  }
  deriving (Show, Eq)

-- | TPM Specification attribute
newtype TPMSpecificationAttr = TPMSpecificationAttr
  { tsaSpecification :: TPMSpecification
  }
  deriving (Show, Eq)

-- * Certificate Extension Attributes

-- | Relevant Credentials attribute
data RelevantCredentialsAttr = RelevantCredentialsAttr
  { rcaCredentials :: [B.ByteString],
    rcaCritical :: Bool
  }
  deriving (Show, Eq)

-- | Relevant Manifests attribute
data RelevantManifestsAttr = RelevantManifestsAttr
  { rmaManifests :: [B.ByteString],
    rmaCritical :: Bool
  }
  deriving (Show, Eq)

-- | Virtual Platform attribute
data VirtualPlatformAttr = VirtualPlatformAttr
  { vpaIsVirtual :: Bool,
    vpaHypervisorInfo :: Maybe B.ByteString,
    vpaCritical :: Bool
  }
  deriving (Show, Eq)

-- | Multi-Tenant attribute
data MultiTenantAttr = MultiTenantAttr
  { mtaIsMultiTenant :: Bool,
    mtaTenantInfo :: Maybe [B.ByteString],
    mtaCritical :: Bool
  }
  deriving (Show, Eq)

-- * Registry-based Attribute Parsing

-- | Type alias for attribute parser functions
type AttributeParser = [[AttributeValue]] -> Either String TCGAttribute

-- | Registry mapping OIDs to their corresponding parser functions
--
-- This registry-based approach replaces the long conditional chain
-- with a more maintainable and extensible lookup table.
attributeParserRegistry :: Map.Map OID AttributeParser
attributeParserRegistry =
  Map.fromList
    [ (tcg_at_platformConfiguration, parsePlatformConfigAttr),
      (tcg_at_platformConfiguration_v2, parsePlatformConfigV2Attr),
      (tcg_at_componentIdentifier, parseComponentIdAttr),
      (tcg_at_componentIdentifier_v2, parseComponentIdV2Attr),
      (tcg_at_componentClass, parseComponentClassAttr),
      (tcg_at_platformManufacturer, parsePlatformMfgAttr),
      (tcg_at_platformModel, parsePlatformModelAttr),
      (tcg_at_platformSerial, parsePlatformSerialAttr),
      (tcg_at_platformVersion, parsePlatformVersionAttr),
      (tcg_at_tpmModel, parseTPMModelAttr),
      (tcg_at_tpmVersion, parseTPMVersionAttr),
      (tcg_at_tpmSpecification, parseTPMSpecAttr),
      (tcg_ce_relevantCredentials, parseRelevantCredAttr),
      (tcg_ce_relevantManifests, parseRelevantManiAttr),
      (tcg_ce_virtualPlatform, parseVirtualPlatAttr),
      (tcg_ce_multiTenant, parseMultiTenantAttr)
    ]

-- | Parse a TCG attribute from an ASN.1 Attribute using registry lookup
--
-- This function uses the registry pattern to dispatch parsing based on OID,
-- making it easy to add new attribute types by simply adding entries to the registry.
parseTCGAttribute :: Attribute -> Either String TCGAttribute
parseTCGAttribute attr =
  let oid = attrType attr
      values = attrValues attr
   in case Map.lookup oid attributeParserRegistry of
        Just parser -> parser values
        Nothing -> parseOtherAttr oid values -- Fallback for unknown attributes

-- | Encode a TCG attribute to an ASN.1 Attribute
encodeTCGAttribute :: TCGAttribute -> Attribute
encodeTCGAttribute tcgAttr =
  case tcgAttr of
    TCGPlatformConfiguration attr -> encodeAttribute tcg_at_platformConfiguration [encodePlatformConfigAttr attr]
    TCGPlatformConfigurationV2 attr -> encodeAttribute tcg_at_platformConfiguration_v2 [encodePlatformConfigV2Attr attr]
    TCGComponentIdentifier attr -> encodeAttribute tcg_at_componentIdentifier [encodeComponentIdAttr attr]
    TCGComponentIdentifierV2 attr -> encodeAttribute tcg_at_componentIdentifier_v2 [encodeComponentIdV2Attr attr]
    TCGComponentClass attr -> encodeAttribute tcg_at_componentClass [encodeComponentClassAttr attr]
    TCGPlatformManufacturer attr -> encodeAttribute tcg_at_platformManufacturer [encodePlatformMfgAttr attr]
    TCGPlatformModel attr -> encodeAttribute tcg_at_platformModel [encodePlatformModelAttr attr]
    TCGPlatformSerial attr -> encodeAttribute tcg_at_platformSerial [encodePlatformSerialAttr attr]
    TCGPlatformVersion attr -> encodeAttribute tcg_at_platformVersion [encodePlatformVersionAttr attr]
    TCGTPMModel attr -> encodeAttribute tcg_at_tpmModel [encodeTPMModelAttr attr]
    TCGTPMVersion attr -> encodeAttribute tcg_at_tpmVersion [encodeTPMVersionAttr attr]
    TCGTPMSpecification attr -> encodeAttribute tcg_at_tpmSpecification [encodeTPMSpecAttr attr]
    TCGRelevantCredentials attr -> encodeAttribute tcg_ce_relevantCredentials [encodeRelevantCredAttr attr]
    TCGRelevantManifests attr -> encodeAttribute tcg_ce_relevantManifests [encodeRelevantManiAttr attr]
    TCGVirtualPlatform attr -> encodeAttribute tcg_ce_virtualPlatform [encodeVirtualPlatAttr attr]
    TCGMultiTenant attr -> encodeAttribute tcg_ce_multiTenant [encodeMultiTenantAttr attr]
    -- Extended platform attributes
    TCGPlatformConfigUri attr -> encodeAttribute tcg_at_platformConfigUri [encodePlatformConfigUriAttr attr]
    TCGPlatformClass attr -> encodeAttribute tcg_at_platformClass [encodePlatformClassAttr attr]
    TCGCertificationLevel attr -> encodeAttribute tcg_at_certificationLevel [encodeCertificationLevelAttr attr]
    TCGPlatformQualifiers attr -> encodeAttribute tcg_at_platformQualifiers [encodePlatformQualifiersAttr attr]
    TCGRootOfTrust attr -> encodeAttribute tcg_at_rootOfTrust [encodeRootOfTrustAttr attr]
    TCGRTMType attr -> encodeAttribute tcg_at_rtmType [encodeRTMTypeAttr attr]
    TCGBootMode attr -> encodeAttribute tcg_at_bootMode [encodeBootModeAttr attr]
    TCGFirmwareVersion attr -> encodeAttribute tcg_at_firmwareVersion [encodeFirmwareVersionAttr attr]
    TCGPolicyReference attr -> encodeAttribute tcg_at_policyReference [encodePolicyReferenceAttr attr]
    TCGOtherAttribute oid value -> encodeAttribute oid [[OctetString value]]

-- | Lookup a TCG attribute by OID in a list of attributes
lookupTCGAttribute :: OID -> [Attribute] -> Maybe TCGAttribute
lookupTCGAttribute targetOID attrs =
  case filter (matchesOID targetOID) attrs of
    [] -> Nothing
    (attr : _) -> case parseTCGAttribute attr of
      Right tcgAttr -> Just tcgAttr
      Left _ -> Nothing
  where
    matchesOID :: OID -> Attribute -> Bool
    matchesOID oid attr = attrType attr == oid

-- | Validate a list of TCG attributes for compliance
validateTCGAttributes :: [TCGAttribute] -> [String]
validateTCGAttributes attrs =
  checkRequiredAttributes attrs
    ++ concatMap validateSingleAttribute attrs

-- * Attribute Utilities

-- | Convert attribute OID to TCG attribute type identifier
attributeOIDToType :: OID -> String
attributeOIDToType oid
  | oid == tcg_at_platformConfiguration = "platformConfiguration"
  | oid == tcg_at_platformConfiguration_v2 = "platformConfiguration_v2"
  | oid == tcg_at_componentIdentifier = "componentIdentifier"
  | oid == tcg_at_componentIdentifier_v2 = "componentIdentifier_v2"
  | oid == tcg_at_componentClass = "componentClass"
  | oid == tcg_at_platformManufacturer = "platformManufacturer"
  | oid == tcg_at_platformModel = "platformModel"
  | oid == tcg_at_platformSerial = "platformSerial"
  | oid == tcg_at_platformVersion = "platformVersion"
  | oid == tcg_at_tpmModel = "tpmModel"
  | oid == tcg_at_tpmVersion = "tpmVersion"
  | oid == tcg_at_tpmSpecification = "tpmSpecification"
  | otherwise = "unknown"

-- | Convert TCG attribute type to OID
attributeTypeToOID :: String -> Maybe OID
attributeTypeToOID typeName =
  case typeName of
    "platformConfiguration" -> Just tcg_at_platformConfiguration
    "platformConfiguration_v2" -> Just tcg_at_platformConfiguration_v2
    "componentIdentifier" -> Just tcg_at_componentIdentifier
    "componentIdentifier_v2" -> Just tcg_at_componentIdentifier_v2
    "componentClass" -> Just tcg_at_componentClass
    "platformManufacturer" -> Just tcg_at_platformManufacturer
    "platformModel" -> Just tcg_at_platformModel
    "platformSerial" -> Just tcg_at_platformSerial
    "platformVersion" -> Just tcg_at_platformVersion
    "tpmModel" -> Just tcg_at_tpmModel
    "tpmVersion" -> Just tcg_at_tpmVersion
    "tpmSpecification" -> Just tcg_at_tpmSpecification
    _ -> Nothing

-- | Check if an attribute is required in Platform Certificates
isRequiredAttribute :: OID -> Bool
isRequiredAttribute oid = oid `elem` requiredAttributes
  where
    requiredAttributes =
      [ tcg_at_platformConfiguration_v2,
        tcg_at_componentIdentifier_v2
      ]

-- | Check if an attribute is marked as critical
isCriticalAttribute :: OID -> Bool
isCriticalAttribute oid = oid `elem` criticalAttributes
  where
    criticalAttributes =
      [ tcg_ce_relevantCredentials,
        tcg_ce_relevantManifests
      ]

-- Helper functions for parsing individual attribute types

parsePlatformConfigAttr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformConfigAttr [[OctetString bs]] = do
  -- Parse ASN.1 DER encoded Platform Configuration
  case decodeASN1' DER bs of
    Left err -> Left $ "Failed to decode Platform Configuration ASN.1: " ++ show err
    Right asn1 ->
      case fromASN1 asn1 of
        Left err -> Left $ "Failed to parse Platform Configuration: " ++ err
        Right (config, _) ->
          Right $ TCGPlatformConfiguration (PlatformConfigurationAttr config Nothing Nothing)
parsePlatformConfigAttr _ = Left "Invalid Platform Configuration attribute format - expected single OctetString"

parsePlatformConfigV2Attr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformConfigV2Attr [[OctetString bs]] = case decodeASN1' DER bs of
  Left err -> Left $ "Failed to decode Platform Configuration v2 ASN.1: " ++ show err
  Right asn1 ->
    case fromASN1 asn1 of
      Left err -> Left $ "Failed to parse Platform Configuration v2: " ++ err
      Right (config, _) ->
        Right $ TCGPlatformConfigurationV2 (PlatformConfigurationV2Attr config Nothing Nothing Nothing)
parsePlatformConfigV2Attr _ = Left "Invalid Platform Configuration v2 attribute format - expected single OctetString"

parseComponentIdAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseComponentIdAttr [[OctetString bs]] = case decodeASN1' DER bs of
  Left err -> Left $ "Failed to decode Component Identifier ASN.1: " ++ show err
  Right asn1 ->
    case fromASN1 asn1 of
      Left err -> Left $ "Failed to parse Component Identifier: " ++ err
      Right (identifier, _) ->
        Right $ TCGComponentIdentifier (ComponentIdentifierAttr identifier Nothing)
parseComponentIdAttr _ = Left "Invalid Component Identifier attribute format - expected single OctetString"

parseComponentIdV2Attr :: [[AttributeValue]] -> Either String TCGAttribute
parseComponentIdV2Attr [[OctetString bs]] = case decodeASN1' DER bs of
  Left err -> Left $ "Failed to decode Component Identifier v2 ASN.1: " ++ show err
  Right asn1 ->
    case fromASN1 asn1 of
      Left err -> Left $ "Failed to parse Component Identifier v2: " ++ err
      Right (identifier, _) ->
        Right $ TCGComponentIdentifierV2 (ComponentIdentifierV2Attr identifier Nothing Nothing)
parseComponentIdV2Attr _ = Left "Invalid Component Identifier v2 attribute format - expected single OctetString"

parseComponentClassAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseComponentClassAttr [[OctetString bs]] = case decodeASN1' DER bs of
  Left err -> Left $ "Failed to decode Component Class ASN.1: " ++ show err
  Right asn1 ->
    case fromASN1 asn1 of
      Left err -> Left $ "Failed to parse Component Class: " ++ err
      Right (componentClass, _) ->
        Right $ TCGComponentClass (ComponentClassAttr componentClass Nothing)
parseComponentClassAttr _ = Left "Invalid Component Class attribute format - expected single OctetString"

parsePlatformMfgAttr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformMfgAttr [[OctetString bs]] = Right $ TCGPlatformManufacturer (PlatformManufacturerAttr bs)
parsePlatformMfgAttr _ = Left "Invalid Platform Manufacturer attribute"

parsePlatformModelAttr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformModelAttr [[OctetString bs]] = Right $ TCGPlatformModel (PlatformModelAttr bs)
parsePlatformModelAttr _ = Left "Invalid Platform Model attribute"

parsePlatformSerialAttr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformSerialAttr [[OctetString bs]] = Right $ TCGPlatformSerial (PlatformSerialAttr bs)
parsePlatformSerialAttr _ = Left "Invalid Platform Serial attribute"

parsePlatformVersionAttr :: [[AttributeValue]] -> Either String TCGAttribute
parsePlatformVersionAttr [[OctetString bs]] = Right $ TCGPlatformVersion (PlatformVersionAttr bs)
parsePlatformVersionAttr _ = Left "Invalid Platform Version attribute"

parseTPMModelAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseTPMModelAttr [[OctetString bs]] = Right $ TCGTPMModel (TPMModelAttr bs)
parseTPMModelAttr _ = Left "Invalid TPM Model attribute"

parseTPMVersionAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseTPMVersionAttr [[OctetString bs]] = case decodeASN1' DER bs of
  Left err -> Left $ "Failed to decode TPM Version ASN.1: " ++ show err
  Right asn1 ->
    case fromASN1 asn1 of
      Left err -> Left $ "Failed to parse TPM Version: " ++ err
      Right (version, _) ->
        Right $ TCGTPMVersion (TPMVersionAttr version)
parseTPMVersionAttr _ = Left "Invalid TPM Version attribute format - expected single OctetString"

parseTPMSpecAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseTPMSpecAttr [[OctetString bs]] = case decodeASN1' DER bs of
  Left err -> Left $ "Failed to decode TPM Specification ASN.1: " ++ show err
  Right asn1 ->
    case fromASN1 asn1 of
      Left err -> Left $ "Failed to parse TPM Specification: " ++ err
      Right (spec, _) ->
        Right $ TCGTPMSpecification (TPMSpecificationAttr spec)
parseTPMSpecAttr _ = Left "Invalid TPM Specification attribute format - expected single OctetString"

parseRelevantCredAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseRelevantCredAttr [[OctetString bs]] = case decodeASN1' DER bs of
  Left err -> Left $ "Failed to decode Relevant Credentials ASN.1: " ++ show err
  Right asn1 ->
    case parseRelevantCredentialsASN1 asn1 of
      Left err -> Left $ "Failed to parse Relevant Credentials: " ++ err
      Right attr ->
        Right $ TCGRelevantCredentials attr
parseRelevantCredAttr _ = Left "Invalid Relevant Credentials attribute format - expected single OctetString"

-- Helper function to parse RelevantCredentialsAttr from ASN.1
parseRelevantCredentialsASN1 :: [ASN1] -> Either String RelevantCredentialsAttr
parseRelevantCredentialsASN1 (Start Sequence : inner) =
  parseRelevantCredentialsInner inner []
parseRelevantCredentialsASN1 _ = Left "Expected Sequence for RelevantCredentials"

parseRelevantCredentialsInner :: [ASN1] -> [B.ByteString] -> Either String RelevantCredentialsAttr
parseRelevantCredentialsInner (Start Sequence : rest) credentials = do
  -- Parse the sequence of credential OctetStrings
  (credList, remaining) <- parseCredentialSequence rest []
  case remaining of
    Boolean critical : End Sequence : _ ->
      Right $ RelevantCredentialsAttr (credentials ++ credList) critical
    End Sequence : _ ->
      Right $ RelevantCredentialsAttr (credentials ++ credList) False -- Default to non-critical
    _ -> Left "Invalid RelevantCredentials structure after credentials sequence"
parseRelevantCredentialsInner (OctetString cred : rest) credentials =
  parseRelevantCredentialsInner rest (credentials ++ [cred])
parseRelevantCredentialsInner (Boolean critical : End Sequence : _) credentials =
  Right $ RelevantCredentialsAttr credentials critical
parseRelevantCredentialsInner (End Sequence : _) credentials =
  Right $ RelevantCredentialsAttr credentials False -- Default to non-critical
parseRelevantCredentialsInner _ _ = Left "Unexpected ASN.1 in RelevantCredentials"

parseCredentialSequence :: [ASN1] -> [B.ByteString] -> Either String ([B.ByteString], [ASN1])
parseCredentialSequence (OctetString cred : rest) acc =
  parseCredentialSequence rest (acc ++ [cred])
parseCredentialSequence (End Sequence : rest) acc =
  Right (acc, rest)
parseCredentialSequence _ _ = Left "Invalid credential sequence"

parseRelevantManiAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseRelevantManiAttr [[OctetString bs]] = case decodeASN1' DER bs of
  Left err -> Left $ "Failed to decode Relevant Manifests ASN.1: " ++ show err
  Right asn1 ->
    case parseRelevantManifestsASN1 asn1 of
      Left err -> Left $ "Failed to parse Relevant Manifests: " ++ err
      Right attr ->
        Right $ TCGRelevantManifests attr
parseRelevantManiAttr _ = Left "Invalid Relevant Manifests attribute format - expected single OctetString"

-- Helper function to parse RelevantManifestsAttr from ASN.1
parseRelevantManifestsASN1 :: [ASN1] -> Either String RelevantManifestsAttr
parseRelevantManifestsASN1 (Start Sequence : inner) =
  parseRelevantManifestsInner inner []
parseRelevantManifestsASN1 _ = Left "Expected Sequence for RelevantManifests"

parseRelevantManifestsInner :: [ASN1] -> [B.ByteString] -> Either String RelevantManifestsAttr
parseRelevantManifestsInner (Start Sequence : rest) manifests = do
  -- Parse the sequence of manifest OctetStrings
  (manifList, remaining) <- parseManifestSequence rest []
  case remaining of
    Boolean critical : End Sequence : _ ->
      Right $ RelevantManifestsAttr (manifests ++ manifList) critical
    End Sequence : _ ->
      Right $ RelevantManifestsAttr (manifests ++ manifList) False -- Default to non-critical
    _ -> Left "Invalid RelevantManifests structure after manifests sequence"
parseRelevantManifestsInner (OctetString manifest : rest) manifests =
  parseRelevantManifestsInner rest (manifests ++ [manifest])
parseRelevantManifestsInner (Boolean critical : End Sequence : _) manifests =
  Right $ RelevantManifestsAttr manifests critical
parseRelevantManifestsInner (End Sequence : _) manifests =
  Right $ RelevantManifestsAttr manifests False -- Default to non-critical
parseRelevantManifestsInner _ _ = Left "Unexpected ASN.1 in RelevantManifests"

parseManifestSequence :: [ASN1] -> [B.ByteString] -> Either String ([B.ByteString], [ASN1])
parseManifestSequence (OctetString manifest : rest) acc =
  parseManifestSequence rest (acc ++ [manifest])
parseManifestSequence (End Sequence : rest) acc =
  Right (acc, rest)
parseManifestSequence _ _ = Left "Invalid manifest sequence"

parseVirtualPlatAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseVirtualPlatAttr [[OctetString encoded]] = do
  asn1List <- case decodeASN1' DER encoded of
    Left err -> Left $ "Failed to decode VirtualPlatform ASN.1: " ++ show err
    Right asn1 -> Right asn1
  case asn1List of
    [Start Sequence, Boolean isVirtual, Boolean critical, End Sequence] ->
      Right $ TCGVirtualPlatform (VirtualPlatformAttr isVirtual Nothing critical)
    [Start Sequence, Boolean isVirtual, OctetString hypervisorInfo, Boolean critical, End Sequence] ->
      Right $ TCGVirtualPlatform (VirtualPlatformAttr isVirtual (Just hypervisorInfo) critical)
    _ -> Left "Invalid VirtualPlatform attribute format"
parseVirtualPlatAttr _ = Left "Invalid Virtual Platform attribute format - expected single OctetString"

parseMultiTenantAttr :: [[AttributeValue]] -> Either String TCGAttribute
parseMultiTenantAttr [[OctetString encoded]] = do
  asn1List <- case decodeASN1' DER encoded of
    Left err -> Left $ "Failed to decode MultiTenant ASN.1: " ++ show err
    Right asn1 -> Right asn1
  case asn1List of
    [Start Sequence, Boolean isMultiTenant, Boolean critical, End Sequence] ->
      Right $ TCGMultiTenant (MultiTenantAttr isMultiTenant Nothing critical)
    (Start Sequence : Boolean isMultiTenant : tenantInfoStart) ->
      case parseTenantInfoSequence tenantInfoStart of
        Right (tenantInfo, [Boolean critical, End Sequence]) ->
          Right $ TCGMultiTenant (MultiTenantAttr isMultiTenant (Just tenantInfo) critical)
        _ -> Left "Invalid MultiTenant attribute format"
    _ -> Left "Invalid MultiTenant attribute format"
  where
    parseTenantInfoSequence :: [ASN1] -> Either String ([B.ByteString], [ASN1])
    parseTenantInfoSequence (Start Sequence : rest) =
      parseTenantList rest []
    parseTenantInfoSequence other = Right ([], other)

    parseTenantList :: [ASN1] -> [B.ByteString] -> Either String ([B.ByteString], [ASN1])
    parseTenantList (End Sequence : rest) acc = Right (reverse acc, rest)
    parseTenantList (OctetString tenantInfo : rest) acc =
      parseTenantList rest (tenantInfo : acc)
    parseTenantList _ _ = Left "Invalid tenant info sequence"
parseMultiTenantAttr _ = Left "Invalid Multi-Tenant attribute format - expected single OctetString"

parseOtherAttr :: OID -> [[AttributeValue]] -> Either String TCGAttribute
parseOtherAttr oid [[OctetString bs]] = Right $ TCGOtherAttribute oid bs
parseOtherAttr oid _ = Left $ "Invalid other attribute with OID: " ++ show oid

-- Helper functions for encoding individual attribute types

encodeAttribute :: OID -> [[AttributeValue]] -> Attribute
encodeAttribute = Attribute

encodePlatformConfigAttr :: PlatformConfigurationAttr -> [AttributeValue]
encodePlatformConfigAttr (PlatformConfigurationAttr config mTimestamp mCertLevel) =
  let configASN1 = toASN1 config []
      timestampASN1 = maybe [] (\ts -> [OctetString ts]) mTimestamp
      certLevelASN1 = maybe [] (\cl -> [IntVal (fromIntegral cl)]) mCertLevel
      fullASN1 = [Start Sequence] ++ configASN1 ++ timestampASN1 ++ certLevelASN1 ++ [End Sequence]
      encoded = L.toStrict $ encodeASN1 DER fullASN1
   in [OctetString encoded]

encodePlatformConfigV2Attr :: PlatformConfigurationV2Attr -> [AttributeValue]
encodePlatformConfigV2Attr (PlatformConfigurationV2Attr config mTimestamp mCertLevel mChangeSeq) =
  let configASN1 = toASN1 config []
      timestampASN1 = maybe [] (\ts -> [OctetString ts]) mTimestamp
      certLevelASN1 = maybe [] (\cl -> [IntVal (fromIntegral cl)]) mCertLevel
      changeSeqASN1 = maybe [] (\cs -> [IntVal cs]) mChangeSeq
      fullASN1 = [Start Sequence] ++ configASN1 ++ timestampASN1 ++ certLevelASN1 ++ changeSeqASN1 ++ [End Sequence]
      encoded = L.toStrict $ encodeASN1 DER fullASN1
   in [OctetString encoded]

encodeComponentIdAttr :: ComponentIdentifierAttr -> [AttributeValue]
encodeComponentIdAttr (ComponentIdentifierAttr identifier mTimestamp) =
  let idASN1 = toASN1 identifier []
      timestampASN1 = maybe [] (\ts -> [OctetString ts]) mTimestamp
      fullASN1 = [Start Sequence] ++ idASN1 ++ timestampASN1 ++ [End Sequence]
      encoded = L.toStrict $ encodeASN1 DER fullASN1
   in [OctetString encoded]

encodeComponentIdV2Attr :: ComponentIdentifierV2Attr -> [AttributeValue]
encodeComponentIdV2Attr (ComponentIdentifierV2Attr identifier mTimestamp mCertInfo) =
  let idASN1 = toASN1 identifier []
      timestampASN1 = maybe [] (\ts -> [OctetString ts]) mTimestamp
      certInfoASN1 = maybe [] (\ci -> [OctetString ci]) mCertInfo
      fullASN1 = [Start Sequence] ++ idASN1 ++ timestampASN1 ++ certInfoASN1 ++ [End Sequence]
      encoded = L.toStrict $ encodeASN1 DER fullASN1
   in [OctetString encoded]

encodeComponentClassAttr :: ComponentClassAttr -> [AttributeValue]
encodeComponentClassAttr (ComponentClassAttr compClass mDescription) =
  let classASN1 = toASN1 compClass []
      descASN1 = maybe [] (\desc -> [OctetString desc]) mDescription
      fullASN1 = [Start Sequence] ++ classASN1 ++ descASN1 ++ [End Sequence]
      encoded = L.toStrict $ encodeASN1 DER fullASN1
   in [OctetString encoded]

encodePlatformMfgAttr :: PlatformManufacturerAttr -> [AttributeValue]
encodePlatformMfgAttr (PlatformManufacturerAttr bs) = [OctetString bs]

encodePlatformModelAttr :: PlatformModelAttr -> [AttributeValue]
encodePlatformModelAttr (PlatformModelAttr bs) = [OctetString bs]

encodePlatformSerialAttr :: PlatformSerialAttr -> [AttributeValue]
encodePlatformSerialAttr (PlatformSerialAttr bs) = [OctetString bs]

encodePlatformVersionAttr :: PlatformVersionAttr -> [AttributeValue]
encodePlatformVersionAttr (PlatformVersionAttr bs) = [OctetString bs]

encodeTPMModelAttr :: TPMModelAttr -> [AttributeValue]
encodeTPMModelAttr (TPMModelAttr bs) = [OctetString bs]

encodeTPMVersionAttr :: TPMVersionAttr -> [AttributeValue]
encodeTPMVersionAttr (TPMVersionAttr version) =
  let versionASN1 = toASN1 version []
      encoded = L.toStrict $ encodeASN1 DER versionASN1
   in [OctetString encoded]

encodeTPMSpecAttr :: TPMSpecificationAttr -> [AttributeValue]
encodeTPMSpecAttr (TPMSpecificationAttr spec) =
  let specASN1 = toASN1 spec []
      encoded = L.toStrict $ encodeASN1 DER specASN1
   in [OctetString encoded]

encodeRelevantCredAttr :: RelevantCredentialsAttr -> [AttributeValue]
encodeRelevantCredAttr (RelevantCredentialsAttr credentials critical) =
  let credASN1 = [Start Sequence] ++ map OctetString credentials ++ [End Sequence]
      criticalASN1 = [Boolean critical]
      fullASN1 = [Start Sequence] ++ credASN1 ++ criticalASN1 ++ [End Sequence]
      encoded = L.toStrict $ encodeASN1 DER fullASN1
   in [OctetString encoded]

encodeRelevantManiAttr :: RelevantManifestsAttr -> [AttributeValue]
encodeRelevantManiAttr (RelevantManifestsAttr manifests critical) =
  let manifASN1 = [Start Sequence] ++ map OctetString manifests ++ [End Sequence]
      criticalASN1 = [Boolean critical]
      fullASN1 = [Start Sequence] ++ manifASN1 ++ criticalASN1 ++ [End Sequence]
      encoded = L.toStrict $ encodeASN1 DER fullASN1
   in [OctetString encoded]

encodeVirtualPlatAttr :: VirtualPlatformAttr -> [AttributeValue]
encodeVirtualPlatAttr (VirtualPlatformAttr isVirtual mHypervisorInfo critical) =
  let virtualASN1 = [Boolean isVirtual]
      hypervisorASN1 = maybe [] (\info -> [OctetString info]) mHypervisorInfo
      criticalASN1 = [Boolean critical]
      fullASN1 = [Start Sequence] ++ virtualASN1 ++ hypervisorASN1 ++ criticalASN1 ++ [End Sequence]
      encoded = L.toStrict $ encodeASN1 DER fullASN1
   in [OctetString encoded]

encodeMultiTenantAttr :: MultiTenantAttr -> [AttributeValue]
encodeMultiTenantAttr (MultiTenantAttr isMultiTenant mTenantInfo critical) =
  let multiTenantASN1 = [Boolean isMultiTenant]
      tenantInfoASN1 = maybe [] (\infos -> [Start Sequence] ++ map OctetString infos ++ [End Sequence]) mTenantInfo
      criticalASN1 = [Boolean critical]
      fullASN1 = [Start Sequence] ++ multiTenantASN1 ++ tenantInfoASN1 ++ criticalASN1 ++ [End Sequence]
      encoded = L.toStrict $ encodeASN1 DER fullASN1
   in [OctetString encoded]

-- Helper functions for validation

checkRequiredAttributes :: [TCGAttribute] -> [String]
checkRequiredAttributes attrs =
  let presentOIDs = map getAttributeOID attrs
      missingRequired = filter (`notElem` presentOIDs) requiredAttributeOIDs
   in map (\oid -> "Missing required attribute: " ++ attributeOIDToType oid) missingRequired
  where
    requiredAttributeOIDs =
      [ tcg_at_platformConfiguration_v2,
        tcg_at_componentIdentifier_v2
      ]

    getAttributeOID :: TCGAttribute -> OID
    getAttributeOID attr = case attr of
      TCGPlatformConfiguration _ -> tcg_at_platformConfiguration
      TCGPlatformConfigurationV2 _ -> tcg_at_platformConfiguration_v2
      TCGComponentIdentifier _ -> tcg_at_componentIdentifier
      TCGComponentIdentifierV2 _ -> tcg_at_componentIdentifier_v2
      TCGComponentClass _ -> tcg_at_componentClass
      TCGPlatformManufacturer _ -> tcg_at_platformManufacturer
      TCGPlatformModel _ -> tcg_at_platformModel
      TCGPlatformSerial _ -> tcg_at_platformSerial
      TCGPlatformVersion _ -> tcg_at_platformVersion
      TCGTPMModel _ -> tcg_at_tpmModel
      TCGTPMVersion _ -> tcg_at_tpmVersion
      TCGTPMSpecification _ -> tcg_at_tpmSpecification
      TCGRelevantCredentials _ -> tcg_ce_relevantCredentials
      TCGRelevantManifests _ -> tcg_ce_relevantManifests
      TCGVirtualPlatform _ -> tcg_ce_virtualPlatform
      TCGMultiTenant _ -> tcg_ce_multiTenant
      -- Extended platform attributes
      TCGPlatformConfigUri _ -> tcg_at_platformConfigUri
      TCGPlatformClass _ -> tcg_at_platformClass
      TCGCertificationLevel _ -> tcg_at_certificationLevel
      TCGPlatformQualifiers _ -> tcg_at_platformQualifiers
      TCGRootOfTrust _ -> tcg_at_rootOfTrust
      TCGRTMType _ -> tcg_at_rtmType
      TCGBootMode _ -> tcg_at_bootMode
      TCGFirmwareVersion _ -> tcg_at_firmwareVersion
      TCGPolicyReference _ -> tcg_at_policyReference
      TCGOtherAttribute oid _ -> oid

validateSingleAttribute :: TCGAttribute -> [String]
validateSingleAttribute attr =
  case attr of
    TCGPlatformManufacturer (PlatformManufacturerAttr bs) ->
      (["Platform Manufacturer cannot be empty" | B.null bs])
    TCGPlatformModel (PlatformModelAttr bs) ->
      (["Platform Model cannot be empty" | B.null bs])
    TCGPlatformSerial (PlatformSerialAttr bs) ->
      (["Platform Serial cannot be empty" | B.null bs])
    TCGPlatformVersion (PlatformVersionAttr bs) ->
      (["Platform Version cannot be empty" | B.null bs])
    TCGTPMModel (TPMModelAttr bs) ->
      (["TPM Model cannot be empty" | B.null bs])
    TCGComponentIdentifier _ -> [] -- Component identifier validation would need detailed implementation
    TCGComponentIdentifierV2 _ -> [] -- Component identifier V2 validation would need detailed implementation
    TCGPlatformConfiguration _ -> [] -- Platform configuration validation would need detailed implementation
    TCGPlatformConfigurationV2 _ -> [] -- Platform configuration V2 validation would need detailed implementation
    TCGTPMVersion _ -> [] -- TPM version validation would need detailed implementation
    TCGTPMSpecification _ -> [] -- TPM specification validation would need detailed implementation
    TCGRelevantCredentials _ -> [] -- Relevant credentials validation would need detailed implementation
    TCGRelevantManifests _ -> [] -- Relevant manifests validation would need detailed implementation
    TCGVirtualPlatform _ -> [] -- Virtual platform attributes are always valid
    TCGMultiTenant _ -> [] -- Multi-tenant attributes are always valid
    TCGComponentClass _ -> [] -- Component class attributes are always valid
    -- Extended platform attributes validation
    TCGPlatformConfigUri (PlatformConfigUriAttr uri _) ->
      (["Platform Configuration URI cannot be empty" | B.null uri])
    TCGPlatformClass (PlatformClassAttr cls _) ->
      (["Platform Class cannot be empty" | B.null cls])
    TCGCertificationLevel (CertificationLevelAttr lvl _) ->
      (["Certification Level must be between 1-7" | lvl < 1 || lvl > 7])
    TCGPlatformQualifiers (PlatformQualifiersAttr quals _) ->
      (["Platform Qualifiers list cannot be empty" | null quals])
    TCGRootOfTrust (RootOfTrustAttr measure _ _) ->
      (["Root of Trust measurement cannot be empty" | B.null measure])
    TCGRTMType (RTMTypeAttr typ _) ->
      (["RTM Type must be 1 (BIOS), 2 (UEFI), or 3 (Other)" | typ < 1 || typ > 3])
    TCGBootMode (BootModeAttr mode _) ->
      (["Boot Mode cannot be empty" | B.null mode])
    TCGFirmwareVersion (FirmwareVersionAttr ver _) ->
      (["Firmware Version cannot be empty" | B.null ver])
    TCGPolicyReference (PolicyReferenceAttr uri _) ->
      (["Policy Reference URI cannot be empty" | B.null uri])
    TCGOtherAttribute _ bs ->
      (["Custom attribute value cannot be empty" | B.null bs])

-- * Extended Platform Attributes (IWG v1.1)

-- | Platform Configuration URI attribute
data PlatformConfigUriAttr = PlatformConfigUriAttr
  { pcuUri :: B.ByteString,
    pcuDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Platform Class attribute
data PlatformClassAttr = PlatformClassAttr
  { pcaClass :: B.ByteString,
    pcaDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Certification Level attribute (1-7)
data CertificationLevelAttr = CertificationLevelAttr
  { claLevel :: Int,
    claDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Platform Qualifiers attribute
data PlatformQualifiersAttr = PlatformQualifiersAttr
  { pqaQualifiers :: [B.ByteString],
    pqaDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Root of Trust attribute
data RootOfTrustAttr = RootOfTrustAttr
  { rotMeasurement :: B.ByteString,
    rotAlgorithm :: OID,
    rotDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | RTM Type attribute (1=BIOS, 2=UEFI, 3=Other)
data RTMTypeAttr = RTMTypeAttr
  { rtmType :: Int,
    rtmDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Boot Mode attribute
data BootModeAttr = BootModeAttr
  { bmMode :: B.ByteString,
    bmDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Firmware Version attribute
data FirmwareVersionAttr = FirmwareVersionAttr
  { fvVersion :: B.ByteString,
    fvDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Policy Reference attribute
data PolicyReferenceAttr = PolicyReferenceAttr
  { prUri :: B.ByteString,
    prDescription :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- * ASN.1 Encoding/Decoding Instances for Extended Attributes

instance ASN1Object PlatformConfigUriAttr where
  toASN1 (PlatformConfigUriAttr uri desc) xs =
    [Start Sequence, OctetString uri]
    ++ maybe [] (\d -> [OctetString d]) desc
    ++ [End Sequence]
    ++ xs
  fromASN1 (Start Sequence : OctetString uri : rest) = do
    case rest of
      (End Sequence : xs) -> Right (PlatformConfigUriAttr uri Nothing, xs)
      (OctetString desc : End Sequence : xs) -> Right (PlatformConfigUriAttr uri (Just desc), xs)
      _ -> Left "PlatformConfigUriAttr: Invalid ASN1 structure"
  fromASN1 _ = Left "PlatformConfigUriAttr: Expected Start Sequence"

instance ASN1Object PlatformClassAttr where
  toASN1 (PlatformClassAttr cls desc) xs =
    [Start Sequence, OctetString cls]
    ++ maybe [] (\d -> [OctetString d]) desc
    ++ [End Sequence]
    ++ xs
  fromASN1 (Start Sequence : OctetString cls : rest) = do
    case rest of
      (End Sequence : xs) -> Right (PlatformClassAttr cls Nothing, xs)
      (OctetString desc : End Sequence : xs) -> Right (PlatformClassAttr cls (Just desc), xs)
      _ -> Left "PlatformClassAttr: Invalid ASN1 structure"
  fromASN1 _ = Left "PlatformClassAttr: Expected Start Sequence"

instance ASN1Object CertificationLevelAttr where
  toASN1 (CertificationLevelAttr lvl desc) xs =
    [Start Sequence, IntVal (fromIntegral lvl)]
    ++ maybe [] (\d -> [OctetString d]) desc
    ++ [End Sequence]
    ++ xs
  fromASN1 (Start Sequence : IntVal lvl : rest) = do
    case rest of
      (End Sequence : xs) -> Right (CertificationLevelAttr (fromIntegral lvl) Nothing, xs)
      (OctetString desc : End Sequence : xs) -> Right (CertificationLevelAttr (fromIntegral lvl) (Just desc), xs)
      _ -> Left "CertificationLevelAttr: Invalid ASN1 structure"
  fromASN1 _ = Left "CertificationLevelAttr: Expected Start Sequence"

instance ASN1Object PlatformQualifiersAttr where
  toASN1 (PlatformQualifiersAttr quals desc) xs =
    [Start Sequence]
    ++ [Start Sequence] ++ concatMap (\q -> [OctetString q]) quals ++ [End Sequence]
    ++ maybe [] (\d -> [OctetString d]) desc
    ++ [End Sequence]
    ++ xs
  fromASN1 (Start Sequence : Start Sequence : rest) = do
    let (qualifiers, remaining) = parseQualifiers rest
    case remaining of
      (End Sequence : End Sequence : xs) -> Right (PlatformQualifiersAttr qualifiers Nothing, xs)
      (End Sequence : OctetString desc : End Sequence : xs) -> Right (PlatformQualifiersAttr qualifiers (Just desc), xs)
      _ -> Left "PlatformQualifiersAttr: Invalid ASN1 structure"
    where
      parseQualifiers (OctetString q : rest') = 
        let (quals, remaining) = parseQualifiers rest'
        in (q : quals, remaining)
      parseQualifiers rest' = ([], rest')
  fromASN1 _ = Left "PlatformQualifiersAttr: Expected Start Sequence"

instance ASN1Object RootOfTrustAttr where
  toASN1 (RootOfTrustAttr measure alg desc) xs =
    [Start Sequence, OctetString measure, OID alg]
    ++ maybe [] (\d -> [OctetString d]) desc
    ++ [End Sequence]
    ++ xs
  fromASN1 (Start Sequence : OctetString measure : OID alg : rest) = do
    case rest of
      (End Sequence : xs) -> Right (RootOfTrustAttr measure alg Nothing, xs)
      (OctetString desc : End Sequence : xs) -> Right (RootOfTrustAttr measure alg (Just desc), xs)
      _ -> Left "RootOfTrustAttr: Invalid ASN1 structure"
  fromASN1 _ = Left "RootOfTrustAttr: Expected Start Sequence"

instance ASN1Object RTMTypeAttr where
  toASN1 (RTMTypeAttr typ desc) xs =
    [Start Sequence, IntVal (fromIntegral typ)]
    ++ maybe [] (\d -> [OctetString d]) desc
    ++ [End Sequence]
    ++ xs
  fromASN1 (Start Sequence : IntVal typ : rest) = do
    case rest of
      (End Sequence : xs) -> Right (RTMTypeAttr (fromIntegral typ) Nothing, xs)
      (OctetString desc : End Sequence : xs) -> Right (RTMTypeAttr (fromIntegral typ) (Just desc), xs)
      _ -> Left "RTMTypeAttr: Invalid ASN1 structure"
  fromASN1 _ = Left "RTMTypeAttr: Expected Start Sequence"

instance ASN1Object BootModeAttr where
  toASN1 (BootModeAttr mode desc) xs =
    [Start Sequence, OctetString mode]
    ++ maybe [] (\d -> [OctetString d]) desc
    ++ [End Sequence]
    ++ xs
  fromASN1 (Start Sequence : OctetString mode : rest) = do
    case rest of
      (End Sequence : xs) -> Right (BootModeAttr mode Nothing, xs)
      (OctetString desc : End Sequence : xs) -> Right (BootModeAttr mode (Just desc), xs)
      _ -> Left "BootModeAttr: Invalid ASN1 structure"
  fromASN1 _ = Left "BootModeAttr: Expected Start Sequence"

instance ASN1Object FirmwareVersionAttr where
  toASN1 (FirmwareVersionAttr ver desc) xs =
    [Start Sequence, OctetString ver]
    ++ maybe [] (\d -> [OctetString d]) desc
    ++ [End Sequence]
    ++ xs
  fromASN1 (Start Sequence : OctetString ver : rest) = do
    case rest of
      (End Sequence : xs) -> Right (FirmwareVersionAttr ver Nothing, xs)
      (OctetString desc : End Sequence : xs) -> Right (FirmwareVersionAttr ver (Just desc), xs)
      _ -> Left "FirmwareVersionAttr: Invalid ASN1 structure"
  fromASN1 _ = Left "FirmwareVersionAttr: Expected Start Sequence"

instance ASN1Object PolicyReferenceAttr where
  toASN1 (PolicyReferenceAttr uri desc) xs =
    [Start Sequence, OctetString uri]
    ++ maybe [] (\d -> [OctetString d]) desc
    ++ [End Sequence]
    ++ xs
  fromASN1 (Start Sequence : OctetString uri : rest) = do
    case rest of
      (End Sequence : xs) -> Right (PolicyReferenceAttr uri Nothing, xs)
      (OctetString desc : End Sequence : xs) -> Right (PolicyReferenceAttr uri (Just desc), xs)
      _ -> Left "PolicyReferenceAttr: Invalid ASN1 structure"
  fromASN1 _ = Left "PolicyReferenceAttr: Expected Start Sequence"

-- * Extended Attribute Encoders

encodePlatformConfigUriAttr :: PlatformConfigUriAttr -> [AttributeValue]
encodePlatformConfigUriAttr attr =
  let encoded = L.toStrict $ encodeASN1 DER (toASN1 attr [])
  in [OctetString encoded]

encodePlatformClassAttr :: PlatformClassAttr -> [AttributeValue]
encodePlatformClassAttr attr =
  let encoded = L.toStrict $ encodeASN1 DER (toASN1 attr [])
  in [OctetString encoded]

encodeCertificationLevelAttr :: CertificationLevelAttr -> [AttributeValue]
encodeCertificationLevelAttr attr =
  let encoded = L.toStrict $ encodeASN1 DER (toASN1 attr [])
  in [OctetString encoded]

encodePlatformQualifiersAttr :: PlatformQualifiersAttr -> [AttributeValue]
encodePlatformQualifiersAttr attr =
  let encoded = L.toStrict $ encodeASN1 DER (toASN1 attr [])
  in [OctetString encoded]

encodeRootOfTrustAttr :: RootOfTrustAttr -> [AttributeValue]
encodeRootOfTrustAttr attr =
  let encoded = L.toStrict $ encodeASN1 DER (toASN1 attr [])
  in [OctetString encoded]

encodeRTMTypeAttr :: RTMTypeAttr -> [AttributeValue]
encodeRTMTypeAttr attr =
  let encoded = L.toStrict $ encodeASN1 DER (toASN1 attr [])
  in [OctetString encoded]

encodeBootModeAttr :: BootModeAttr -> [AttributeValue]
encodeBootModeAttr attr =
  let encoded = L.toStrict $ encodeASN1 DER (toASN1 attr [])
  in [OctetString encoded]

encodeFirmwareVersionAttr :: FirmwareVersionAttr -> [AttributeValue]
encodeFirmwareVersionAttr attr =
  let encoded = L.toStrict $ encodeASN1 DER (toASN1 attr [])
  in [OctetString encoded]

encodePolicyReferenceAttr :: PolicyReferenceAttr -> [AttributeValue]
encodePolicyReferenceAttr attr =
  let encoded = L.toStrict $ encodeASN1 DER (toASN1 attr [])
  in [OctetString encoded]
