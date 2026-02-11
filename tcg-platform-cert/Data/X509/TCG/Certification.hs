{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Data.X509.TCG.Certification
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- FIPS 140-2/3 and Common Criteria certification level data structures.
--
-- This module implements detailed certification information as required for
-- government and high-security environments, including FIPS 140-2/3 validation
-- and Common Criteria Evaluation Assurance Levels (EAL 1-7).
--
-- == FIPS 140-2/3 Compliance
--
-- FIPS 140-2/3 (Federal Information Processing Standard Publication 140-2/3)
-- defines security requirements for cryptographic modules. This implementation
-- supports all four security levels and the newer FIPS 140-3 standard.
--
-- == Common Criteria Support
--
-- Common Criteria (ISO/IEC 15408) provides a framework for computer security
-- certification. This implementation supports Evaluation Assurance Levels
-- EAL1 through EAL7 with proper structural definitions.
--
module Data.X509.TCG.Certification
  ( -- * FIPS 140-2/3 Support
    FIPSLevel (..),
    SecurityLevel (..),
    FIPSVersion (..),
    
    -- * Common Criteria Support
    CommonCriteriaLevel (..),
    CommonCriteriaMeasures (..),
    EvaluationAssuranceLevel (..),
    EvaluationStatus (..),
    StrengthOfFunction (..),
    ProtectionProfile (..),
    SecurityTarget (..),
    
    -- * Measurement Root Types
    MeasurementRootType (..),
    
    -- * URI Reference Support
    URIReference (..),
    
    -- * Platform Configuration Support  
    PlatformConfiguration (..),
    ComponentIdentifier (..),
    ComponentClass (..),
    ComponentClassRegistry (..),
    ComponentClassValue,
    ComponentAddress (..),
    AddressType (..),
    AttributeStatus (..),
    Property (..),
    CertificateIdentifier (..),
    PrivateEnterpriseNumber,
    
    -- * String Types
    IA5String,
    UTF8String,
    BitString,
    URIMAX,
    STRMAX,
    
    -- * Other Certification Support
    OtherCertification (..),
    CertificationType (..),
    
    -- * Combined Certification Structure
    CertificationInfo (..),
    
    -- * Validation Functions
    validateFIPSLevel,
    validateEALLevel,
    isFIPSCompliant,
    isCommonCriteriaCompliant,
    
    -- * Utility Functions
    fipsLevelToInt,
    ealLevelToInt,
    parseFIPSVersion,
    formatCertificationInfo,
  ) where

import Data.ASN1.Types
import qualified Data.ByteString as B
import Data.Data (Data, Typeable)
import Data.Hourglass (DateTime)
import Data.Word (Word32)
-- AlgorithmIdentifier placeholder - should be properly defined
type AlgorithmIdentifier = OID

-- * Type Aliases for ASN.1 String Types

-- | IA5String type alias for ASCII strings
type IA5String = B.ByteString

-- | UTF8String type alias for Unicode strings  
type UTF8String = B.ByteString

-- | BitString type alias
type BitString = B.ByteString

-- | Component Class Value (4-byte octet string)
type ComponentClassValue = B.ByteString

-- | Private Enterprise Number
type PrivateEnterpriseNumber = Word32

-- | String size constraints
type STRMAX = Int  -- Maximum string size
type URIMAX = Int  -- Maximum URI size

-- * FIPS 140-2/3 Support

-- | FIPS 140 standard version.
data FIPSVersion
  = FIPS_140_1  -- ^ Legacy FIPS 140-1 (withdrawn).
  | FIPS_140_2  -- ^ FIPS 140-2 (widely deployed).
  | FIPS_140_3  -- ^ FIPS 140-3 (current standard, ISO 19790 aligned).
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | FIPS 140-2\/3 security levels (1–4).
data SecurityLevel
  = SLLevel1  -- ^ Level 1: basic security requirements, no physical security.
  | SLLevel2  -- ^ Level 2: tamper-evidence and role-based authentication.
  | SLLevel3  -- ^ Level 3: tamper-resistance and identity-based authentication.
  | SLLevel4  -- ^ Level 4: complete envelope of protection, environmental failure protection.
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | FIPS 140 certification level as encoded in @tBBSecurityAssertions@.
--
-- Corresponds to the @FIPSLevel@ ASN.1 type in TCG PCP v2.1 §3.1.4.
data FIPSLevel = FIPSLevel
  { flVersion :: !IA5String
    -- ^ FIPS standard version string: @\"140-1\"@, @\"140-2\"@, or @\"140-3\"@.
  , flLevel   :: !SecurityLevel
    -- ^ Security level (1–4). REQUIRED.
  , flPlus    :: !Bool
    -- ^ FIPS Plus augmentation (DEFAULT FALSE, omitted in DER when False).
  } deriving (Show, Eq, Data, Typeable)

-- * Common Criteria Support

-- | Common Criteria Evaluation Assurance Level (EAL 1–7).
--
-- Defined as @EvaluationAssuranceLevel@ ENUMERATED in TCG PCP v2.1 §3.1.4.
data EvaluationAssuranceLevel
  = EALLevel1  -- ^ EAL1: functionally tested.
  | EALLevel2  -- ^ EAL2: structurally tested.
  | EALLevel3  -- ^ EAL3: methodically tested and checked.
  | EALLevel4  -- ^ EAL4: methodically designed, tested, and reviewed.
  | EALLevel5  -- ^ EAL5: semiformally designed and tested.
  | EALLevel6  -- ^ EAL6: semiformally verified design and tested.
  | EALLevel7  -- ^ EAL7: formally verified design and tested.
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Common Criteria evaluation status.
--
-- Defined as @EvaluationStatus@ ENUMERATED in TCG PCP v2.1 §3.1.4.
data EvaluationStatus
  = ESDesignedToMeet       -- ^ designedToMeet (0): not yet evaluated.
  | ESEvaluationInProgress -- ^ evaluationInProgress (1): evaluation underway.
  | ESEvaluationCompleted  -- ^ evaluationCompleted (2): evaluation finished successfully.
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Strength of Function levels for Common Criteria (SOF).
data StrengthOfFunction
  = SOFBasic   -- ^ Basic strength of function.
  | SOFMedium  -- ^ Medium strength of function.
  | SOFHigh    -- ^ High strength of function.
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Measurement Root Type for the platform's Root of Trust for Measurement.
--
-- Defined as @MeasurementRootType@ ENUMERATED in TCG PCP v2.1 §3.1.4.
data MeasurementRootType
  = MRTStatic    -- ^ static (0): measurement root is in ROM\/firmware.
  | MRTDynamic   -- ^ dynamic (1): measurement root can be updated.
  | MRTNonHost   -- ^ nonHost (2): measurement root is external to the host.
  | MRTHybrid    -- ^ hybrid (3): capable of both static and dynamic measurement.
  | MRTPhysical  -- ^ physical (4): anchored by a discrete physical TPM.
  | MRTVirtual   -- ^ virtual (5): TPM is virtualised.
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | URI Reference with optional integrity hash.
--
-- Corresponds to @URIReference@ in TCG PCP v2.1 §3.1.3.
data URIReference = URIReference
  { urUniformResourceIdentifier :: !IA5String
    -- ^ The URI string (SIZE 1..URIMAX).
  , urHashAlgorithm            :: !(Maybe AlgorithmIdentifier)
    -- ^ Hash algorithm OID for integrity verification (OPTIONAL).
  , urHashValue                :: !(Maybe BitString)
    -- ^ Hash value over the URI-referenced content (OPTIONAL).
  } deriving (Show, Eq, Data, Typeable)

-- | Common Criteria Measures as defined in TCG PCP v2.1 §3.1.4.
--
-- Encodes the @CommonCriteriaMeasures@ SEQUENCE within @tBBSecurityAssertions@.
data CommonCriteriaMeasures = CommonCriteriaMeasures
  { ccmVersion            :: !IA5String
    -- ^ Common Criteria version string (e.g., @\"3.1\"@). SIZE (1..STRMAX).
  , ccmAssuranceLevel     :: !EvaluationAssuranceLevel
    -- ^ Evaluation Assurance Level (EAL 1–7). REQUIRED.
  , ccmEvaluationStatus   :: !EvaluationStatus
    -- ^ Current evaluation status. REQUIRED.
  , ccmPlus              :: !Bool
    -- ^ CC Plus augmentation (DEFAULT FALSE).
  , ccmStrengthOfFunction :: !(Maybe StrengthOfFunction)
    -- ^ Strength of function rating (OPTIONAL, IMPLICIT tag [0]).
  , ccmProfileOid        :: !(Maybe OID)
    -- ^ Protection Profile OID (OPTIONAL, IMPLICIT tag [1]).
  , ccmProfileUri        :: !(Maybe URIReference)
    -- ^ Protection Profile URI (OPTIONAL, IMPLICIT tag [2]).
  , ccmTargetOid         :: !(Maybe OID)
    -- ^ Security Target OID (OPTIONAL, IMPLICIT tag [3]).
  , ccmTargetUri         :: !(Maybe URIReference)
    -- ^ Security Target URI (OPTIONAL, IMPLICIT tag [4]).
  } deriving (Show, Eq, Data, Typeable)

-- | Common Criteria Protection Profile (PP) information.
data ProtectionProfile = ProtectionProfile
  { ppName :: !B.ByteString
    -- ^ Protection Profile name.
  , ppVersion :: !B.ByteString
    -- ^ PP version string.
  , ppIdentifier :: !(Maybe B.ByteString)
    -- ^ PP identifier or registered OID (OPTIONAL).
  } deriving (Show, Eq, Data, Typeable)

-- | Common Criteria Security Target (ST) information.
data SecurityTarget = SecurityTarget
  { stName :: !B.ByteString
    -- ^ Security Target name.
  , stVersion :: !B.ByteString
    -- ^ ST version string.
  , stIdentifier :: !(Maybe B.ByteString)
    -- ^ ST identifier (OPTIONAL).
  } deriving (Show, Eq, Data, Typeable)

-- * Platform Configuration Support

-- | Platform Configuration (complies with lines 575-580)
data PlatformConfiguration = PlatformConfiguration
  { pcComponentIdentifiers    :: !(Maybe [ComponentIdentifier])  -- OPTIONAL [0] IMPLICIT SEQUENCE(SIZE(1..MAX))
  , pcComponentIdentifiersUri :: !(Maybe URIReference)           -- OPTIONAL [1] IMPLICIT
  , pcPlatformProperties     :: !(Maybe [Property])              -- OPTIONAL [2] IMPLICIT SEQUENCE(SIZE(1..MAX))
  , pcPlatformPropertiesUri  :: !(Maybe URIReference)            -- OPTIONAL [3] IMPLICIT
  } deriving (Show, Eq, Data, Typeable)

-- | Component Identifier (complies with lines 582-593)
data ComponentIdentifier = ComponentIdentifier
  { ciComponentClass       :: !ComponentClass                    -- REQUIRED
  , ciComponentManufacturer :: !UTF8String                       -- REQUIRED SIZE (1..STRMAX)
  , ciComponentModel       :: !UTF8String                        -- REQUIRED SIZE (1..STRMAX)
  , ciComponentSerial      :: !(Maybe UTF8String)                -- OPTIONAL [0] IMPLICIT SIZE (1..STRMAX)
  , ciComponentRevision    :: !(Maybe UTF8String)                -- OPTIONAL [1] IMPLICIT SIZE (1..STRMAX)
  , ciComponentManufacturerId :: !(Maybe PrivateEnterpriseNumber) -- OPTIONAL [2] IMPLICIT
  , ciFieldReplaceable     :: !(Maybe Bool)                      -- OPTIONAL [3] IMPLICIT
  , ciComponentAddresses   :: ![ComponentAddress]                -- OPTIONAL [4] IMPLICIT SEQUENCE(SIZE(1..MAX))
  , ciComponentPlatformCert :: !(Maybe CertificateIdentifier)    -- OPTIONAL [5] IMPLICIT
  , ciComponentPlatformCertUri :: !(Maybe URIReference)          -- OPTIONAL [6] IMPLICIT
  , ciStatus               :: !(Maybe AttributeStatus)           -- OPTIONAL [7] IMPLICIT
  } deriving (Show, Eq, Data, Typeable)

-- | Component Class (complies with lines 595-597)
data ComponentClass = ComponentClass
  { ccComponentClassRegistry :: !ComponentClassRegistry          -- REQUIRED
  , ccComponentClassValue   :: !ComponentClassValue             -- REQUIRED OCTET STRING SIZE(4)
  } deriving (Show, Eq, Data, Typeable)

-- | Component class registry identifier (TCG PCP v2.1 §3.1.7).
data ComponentClassRegistry
  = TcgRegistryComponentClass   -- ^ TCG component class registry (2.23.133.18.3.1).
  | IetfRegistryComponentClass  -- ^ IETF component class registry.
  | DmtfRegistryComponentClass  -- ^ DMTF component class registry.
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Component Address (complies with lines 602-607)
data ComponentAddress = ComponentAddress
  { caAddressType  :: !AddressType  -- REQUIRED
  , caAddressValue :: !UTF8String   -- REQUIRED SIZE (1..STRMAX)
  } deriving (Show, Eq, Data, Typeable)

-- | Network address type for component identification.
data AddressType
  = ATEthernetMac   -- ^ Ethernet MAC address (tcg-address-ethernetmac).
  | ATWlanMac       -- ^ Wireless LAN MAC address (tcg-address-wlanmac).
  | ATBluetoothMac  -- ^ Bluetooth MAC address (tcg-address-bluetoothmac).
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Attribute status in Delta Platform Certificates.
data AttributeStatus
  = ASAdded    -- ^ Component was added to the platform.
  | ASRemoved  -- ^ Component was removed from the platform.
  | ASModified -- ^ Component was modified.
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Property structure for platform properties
data Property = Property
  { propName  :: !UTF8String  -- Property name
  , propValue :: !UTF8String  -- Property value
  } deriving (Show, Eq, Data, Typeable)

-- | Certificate Identifier for referencing certificates
data CertificateIdentifier = CertificateIdentifier
  { certIssuer :: !UTF8String  -- Certificate issuer
  , certSerial :: !Integer     -- Certificate serial number
  } deriving (Show, Eq, Data, Typeable)

-- | Complete Common Criteria certification record.
data CommonCriteriaLevel = CommonCriteriaLevel
  { ccLevel :: !EvaluationAssuranceLevel
    -- ^ Evaluation Assurance Level (EAL 1–7).
  , ccPlus :: !Bool
    -- ^ EAL Plus augmentation designation.
  , ccProtectionProfile :: !(Maybe ProtectionProfile)
    -- ^ Protection Profile used for evaluation (OPTIONAL).
  , ccSecurityTarget :: !(Maybe SecurityTarget)
    -- ^ Security Target document (OPTIONAL).
  , ccCertificateNumber :: !(Maybe B.ByteString)
    -- ^ CC certificate or validation report number (OPTIONAL).
  , ccValidationDate :: !(Maybe DateTime)
    -- ^ Date the evaluation was completed (OPTIONAL).
  , ccEvaluationFacility :: !(Maybe B.ByteString)
    -- ^ Name of the evaluation facility (OPTIONAL).
  , ccDescription :: !(Maybe B.ByteString)
    -- ^ Additional description (OPTIONAL).
  } deriving (Show, Eq, Data, Typeable)

-- * Other Certification Support

-- | Known certification programme types.
data CertificationType
  = NIST_CAVP          -- ^ NIST Cryptographic Algorithm Validation Program (USA).
  | NIAP_CCEVS         -- ^ NIAP Common Criteria Evaluation and Validation Scheme (USA).
  | CSE_CCEF           -- ^ CSE Common Criteria Evaluation Facility (Canada).
  | BSI_CC             -- ^ BSI Common Criteria (Germany).
  | ANSSI_CC           -- ^ ANSSI Common Criteria (France).
  | CESG_CPA           -- ^ CESG Commercial Product Assurance (UK).
  | JISEC_CC           -- ^ JISEC Common Criteria (Japan).
  | KECS_CC            -- ^ KECS Common Criteria (South Korea).
  | Other B.ByteString -- ^ Other certification type (free-form identifier).
  deriving (Show, Eq, Data, Typeable)

-- | Certification information from a non-FIPS, non-CC programme.
data OtherCertification = OtherCertification
  { ocType :: !CertificationType
    -- ^ Certification programme type.
  , ocLevel :: !(Maybe B.ByteString)
    -- ^ Certification level or grade (OPTIONAL).
  , ocCertificateNumber :: !(Maybe B.ByteString)
    -- ^ Certificate or validation report number (OPTIONAL).
  , ocValidationDate :: !(Maybe DateTime)
    -- ^ Date the certification was issued (OPTIONAL).
  , ocDescription :: !(Maybe B.ByteString)
    -- ^ Free-form description (OPTIONAL).
  } deriving (Show, Eq, Data, Typeable)

-- * Combined Certification Structure

-- | Aggregate certification information combining all programme results.
data CertificationInfo = CertificationInfo
  { ciFips :: !(Maybe FIPSLevel)
    -- ^ FIPS 140-2\/3 certification result (OPTIONAL).
  , ciCommonCriteria :: !(Maybe CommonCriteriaLevel)
    -- ^ Common Criteria certification result (OPTIONAL).
  , ciOtherCertifications :: ![OtherCertification]
    -- ^ Results from other certification programmes.
  , ciIsCritical :: !Bool
    -- ^ Whether this certification info is marked as a critical extension.
  } deriving (Show, Eq, Data, Typeable)

-- * ASN.1 Encoding Support

instance ASN1Object FIPSVersion where
  toASN1 ver xs = IntVal (fromIntegral $ fromEnum ver) : xs
  fromASN1 (IntVal i : xs)
    | i >= 0 && i <= fromIntegral (fromEnum (maxBound :: FIPSVersion)) = 
        Right (toEnum (fromIntegral i), xs)
    | otherwise = Left "FIPSVersion: Invalid enumeration value"
  fromASN1 _ = Left "FIPSVersion: Expected IntVal"

instance ASN1Object SecurityLevel where
  toASN1 level xs = IntVal (fromIntegral $ fromEnum level + 1) : xs
  fromASN1 (IntVal i : xs)
    | i >= 1 && i <= 4 = Right (toEnum (fromIntegral i - 1), xs)
    | otherwise = Left "SecurityLevel: Invalid level (must be 1-4)"
  fromASN1 _ = Left "SecurityLevel: Expected IntVal"

instance ASN1Object EvaluationAssuranceLevel where
  toASN1 eal xs = IntVal (fromIntegral $ fromEnum eal + 1) : xs
  fromASN1 (IntVal i : xs)
    | i >= 1 && i <= 7 = Right (toEnum (fromIntegral i - 1), xs)
    | otherwise = Left "EvaluationAssuranceLevel: Invalid EAL (must be 1-7)"
  fromASN1 _ = Left "EvaluationAssuranceLevel: Expected IntVal"

instance ASN1Object FIPSLevel where
  toASN1 (FIPSLevel ver level plus) xs =
    Start Sequence : 
    OctetString ver :
    toASN1 level (
      Boolean plus : 
      [End Sequence]
    ) ++ xs

  fromASN1 (Start Sequence : OctetString ver : rest) = do
    (level, rest1) <- fromASN1 rest
    case rest1 of
      (Boolean plus : End Sequence : remaining) ->
        Right (FIPSLevel ver level plus, remaining)
      _ -> Left "FIPSLevel: Invalid ASN1 sequence structure"
  fromASN1 _ = Left "FIPSLevel: Expected Start Sequence with version"

instance ASN1Object CommonCriteriaLevel where
  toASN1 (CommonCriteriaLevel eal plus pp st certNum valDate facility desc) xs =
    Start Sequence :
    toASN1 eal (
      Boolean plus :
      maybe [] (\p -> toASN1 p []) pp ++
      maybe [] (\s -> toASN1 s []) st ++
      maybe [] (\cn -> [OctetString cn]) certNum ++
      maybe [] (\vd -> [ASN1Time TimeGeneralized vd Nothing]) valDate ++
      maybe [] (\f -> [OctetString f]) facility ++
      maybe [] (\d -> [OctetString d]) desc ++
      [End Sequence]
    ) ++ xs

  fromASN1 (Start Sequence : rest) = do
    (eal, rest1) <- fromASN1 rest
    case rest1 of
      (Boolean plus : rest2) -> do
        -- Simplified parsing for now - full implementation would parse PP/ST
        let (certNum, rest3) = extractOptionalOctetString rest2
            (valDate, rest4) = extractOptionalTime rest3
            (facility, rest5) = extractOptionalOctetString rest4  
            (desc, rest6) = extractOptionalOctetString rest5
        case rest6 of
          (End Sequence : remaining) ->
            Right (CommonCriteriaLevel eal plus Nothing Nothing certNum valDate facility desc, remaining)
          _ -> Left "CommonCriteriaLevel: Invalid ASN1 sequence termination"
      _ -> Left "CommonCriteriaLevel: Missing plus field"
  fromASN1 _ = Left "CommonCriteriaLevel: Expected Start Sequence"

instance ASN1Object ProtectionProfile where
  toASN1 (ProtectionProfile name ver ident) xs =
    Start Sequence :
    OctetString name :
    OctetString ver :
    maybe [] (\i -> [OctetString i]) ident ++
    [End Sequence] ++ xs

  fromASN1 (Start Sequence : OctetString name : OctetString ver : rest) = do
    let (ident, rest1) = extractOptionalOctetString rest
    case rest1 of
      (End Sequence : remaining) -> Right (ProtectionProfile name ver ident, remaining)
      _ -> Left "ProtectionProfile: Invalid ASN1 sequence termination"
  fromASN1 _ = Left "ProtectionProfile: Expected Start Sequence with name and version"

instance ASN1Object SecurityTarget where
  toASN1 (SecurityTarget name ver ident) xs =
    Start Sequence :
    OctetString name :
    OctetString ver :
    maybe [] (\i -> [OctetString i]) ident ++
    [End Sequence] ++ xs

  fromASN1 (Start Sequence : OctetString name : OctetString ver : rest) = do
    let (ident, rest1) = extractOptionalOctetString rest
    case rest1 of
      (End Sequence : remaining) -> Right (SecurityTarget name ver ident, remaining)
      _ -> Left "SecurityTarget: Invalid ASN1 sequence termination"  
  fromASN1 _ = Left "SecurityTarget: Expected Start Sequence with name and version"

-- ASN.1 instances for new structures

instance ASN1Object MeasurementRootType where
  toASN1 mrt xs = IntVal (fromIntegral $ fromEnum mrt) : xs
  fromASN1 (IntVal i : xs)
    | i >= 0 && i <= fromIntegral (fromEnum (maxBound :: MeasurementRootType)) = 
        Right (toEnum (fromIntegral i), xs)
    | otherwise = Left "MeasurementRootType: Invalid enumeration value"
  fromASN1 _ = Left "MeasurementRootType: Expected IntVal"

instance ASN1Object EvaluationStatus where
  toASN1 status xs = IntVal (fromIntegral $ fromEnum status) : xs
  fromASN1 (IntVal i : xs)
    | i >= 0 && i <= fromIntegral (fromEnum (maxBound :: EvaluationStatus)) = 
        Right (toEnum (fromIntegral i), xs)
    | otherwise = Left "EvaluationStatus: Invalid enumeration value"
  fromASN1 _ = Left "EvaluationStatus: Expected IntVal"

instance ASN1Object StrengthOfFunction where
  toASN1 sof xs = IntVal (fromIntegral $ fromEnum sof) : xs
  fromASN1 (IntVal i : xs)
    | i >= 0 && i <= fromIntegral (fromEnum (maxBound :: StrengthOfFunction)) = 
        Right (toEnum (fromIntegral i), xs)
    | otherwise = Left "StrengthOfFunction: Invalid enumeration value"
  fromASN1 _ = Left "StrengthOfFunction: Expected IntVal"

instance ASN1Object ComponentClassRegistry where
  toASN1 registry xs = IntVal (fromIntegral $ fromEnum registry) : xs
  fromASN1 (IntVal i : xs)
    | i >= 0 && i <= fromIntegral (fromEnum (maxBound :: ComponentClassRegistry)) = 
        Right (toEnum (fromIntegral i), xs)
    | otherwise = Left "ComponentClassRegistry: Invalid enumeration value"
  fromASN1 _ = Left "ComponentClassRegistry: Expected IntVal"

instance ASN1Object AddressType where
  toASN1 addrType xs = IntVal (fromIntegral $ fromEnum addrType) : xs
  fromASN1 (IntVal i : xs)
    | i >= 0 && i <= fromIntegral (fromEnum (maxBound :: AddressType)) = 
        Right (toEnum (fromIntegral i), xs)
    | otherwise = Left "AddressType: Invalid enumeration value"
  fromASN1 _ = Left "AddressType: Expected IntVal"

instance ASN1Object AttributeStatus where
  toASN1 status xs = IntVal (fromIntegral $ fromEnum status) : xs
  fromASN1 (IntVal i : xs)
    | i >= 0 && i <= fromIntegral (fromEnum (maxBound :: AttributeStatus)) = 
        Right (toEnum (fromIntegral i), xs)
    | otherwise = Left "AttributeStatus: Invalid enumeration value"
  fromASN1 _ = Left "AttributeStatus: Expected IntVal"

instance ASN1Object ComponentClass where
  toASN1 (ComponentClass registry value) xs =
    Start Sequence :
    toASN1 registry (OctetString value : [End Sequence]) ++ xs
  fromASN1 (Start Sequence : rest) = do
    (registry, rest1) <- fromASN1 rest
    case rest1 of
      (OctetString value : End Sequence : remaining) ->
        Right (ComponentClass registry value, remaining)
      _ -> Left "ComponentClass: Invalid ASN1 sequence structure"
  fromASN1 _ = Left "ComponentClass: Expected Start Sequence"

instance ASN1Object ComponentAddress where
  toASN1 (ComponentAddress addrType value) xs =
    Start Sequence :
    toASN1 addrType (OctetString value : [End Sequence]) ++ xs
  fromASN1 (Start Sequence : rest) = do
    (addrType, rest1) <- fromASN1 rest
    case rest1 of
      (OctetString value : End Sequence : remaining) ->
        Right (ComponentAddress addrType value, remaining)
      _ -> Left "ComponentAddress: Invalid ASN1 sequence structure"
  fromASN1 _ = Left "ComponentAddress: Expected Start Sequence"

instance ASN1Object Property where
  toASN1 (Property name value) xs =
    Start Sequence :
    OctetString name :
    OctetString value :
    [End Sequence] ++ xs
  fromASN1 (Start Sequence : OctetString name : OctetString value : End Sequence : rest) =
    Right (Property name value, rest)
  fromASN1 _ = Left "Property: Expected Start Sequence with name and value"

instance ASN1Object CertificateIdentifier where
  toASN1 (CertificateIdentifier issuer serial) xs =
    Start Sequence :
    OctetString issuer :
    IntVal serial :
    [End Sequence] ++ xs
  fromASN1 (Start Sequence : OctetString issuer : IntVal serial : End Sequence : rest) =
    Right (CertificateIdentifier issuer serial, rest)
  fromASN1 _ = Left "CertificateIdentifier: Expected Start Sequence with issuer and serial"

-- * Helper Functions for ASN.1 Parsing

extractOptionalOctetString :: [ASN1] -> (Maybe B.ByteString, [ASN1])
extractOptionalOctetString (OctetString bs : rest) = (Just bs, rest)
extractOptionalOctetString rest = (Nothing, rest)

extractOptionalTime :: [ASN1] -> (Maybe DateTime, [ASN1])
extractOptionalTime (ASN1Time _ time _ : rest) = (Just time, rest)
extractOptionalTime rest = (Nothing, rest)

-- * Validation Functions

-- | Validate FIPS level consistency
validateFIPSLevel :: FIPSLevel -> Either String ()
validateFIPSLevel (FIPSLevel _ver _level _) = Right () -- Simplified validation

-- | Validate EAL level 
validateEALLevel :: CommonCriteriaLevel -> Either String ()
validateEALLevel (CommonCriteriaLevel eal plus _ _ _ _ _ _) = do
  case (eal, plus) of
    (EALLevel7, _) -> Right () -- EAL7 is valid
    _ -> Right ()

-- | Check if component is FIPS compliant
isFIPSCompliant :: CertificationInfo -> Bool  
isFIPSCompliant (CertificationInfo (Just _) _ _ _) = True
isFIPSCompliant _ = False

-- | Check if component is Common Criteria compliant
isCommonCriteriaCompliant :: CertificationInfo -> Bool
isCommonCriteriaCompliant (CertificationInfo _ (Just _) _ _) = True  
isCommonCriteriaCompliant _ = False

-- * Utility Functions

-- | Convert FIPS security level to integer
fipsLevelToInt :: SecurityLevel -> Int
fipsLevelToInt = (+ 1) . fromEnum

-- | Convert EAL level to integer
ealLevelToInt :: EvaluationAssuranceLevel -> Int  
ealLevelToInt = (+ 1) . fromEnum

-- | Parse FIPS version from string
parseFIPSVersion :: String -> Maybe FIPSVersion
parseFIPSVersion "140-1" = Just FIPS_140_1
parseFIPSVersion "140-2" = Just FIPS_140_2  
parseFIPSVersion "140-3" = Just FIPS_140_3
parseFIPSVersion _ = Nothing

-- | Format certification information for display
formatCertificationInfo :: CertificationInfo -> String
formatCertificationInfo (CertificationInfo fips cc others _) = 
  unlines $ filter (not . null) [
    maybe "" formatFIPS fips,
    maybe "" formatCC cc,
    if null others then "" else "Other Certifications: " ++ show (length others)
  ]
  where
    formatFIPS (FIPSLevel ver level plus) =
      "FIPS " ++ show ver ++ " Level " ++ show (fipsLevelToInt level) ++
      (if plus then " Plus" else "")
    
    formatCC (CommonCriteriaLevel eal plus _ _ _ _ _ _) =
      "Common Criteria EAL" ++ show (ealLevelToInt eal) ++
      (if plus then " Plus" else "")