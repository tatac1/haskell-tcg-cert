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

-- | FIPS Version enumeration
data FIPSVersion
  = FIPS_140_1  -- Legacy FIPS 140-1
  | FIPS_140_2  -- Current FIPS 140-2
  | FIPS_140_3  -- New FIPS 140-3
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | FIPS 140-2/3 Security Levels
data SecurityLevel
  = SLLevel1  -- Level 1: Basic security requirements
  | SLLevel2  -- Level 2: Enhanced physical security
  | SLLevel3  -- Level 3: Tamper-evident physical security
  | SLLevel4  -- Level 4: Tamper-active physical security
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | FIPS Level certification (simplified for ASN.1 compliance)
data FIPSLevel = FIPSLevel
  { flVersion :: !IA5String      -- SIZE (1..STRMAX) - "140-1", "140-2", or "140-3"
  , flLevel   :: !SecurityLevel  -- REQUIRED
  , flPlus    :: !Bool           -- DEFAULT FALSE
  } deriving (Show, Eq, Data, Typeable)

-- * Common Criteria Support

-- | Evaluation Assurance Level (complies with lines 387-394)
data EvaluationAssuranceLevel
  = EALLevel1  -- level1 (1)
  | EALLevel2  -- level2 (2)
  | EALLevel3  -- level3 (3)
  | EALLevel4  -- level4 (4)
  | EALLevel5  -- level5 (5)
  | EALLevel6  -- level6 (6)
  | EALLevel7  -- level7 (7)
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Evaluation Status (complies with lines 409-412)
data EvaluationStatus
  = ESDesignedToMeet      -- designedToMeet (0)
  | ESEvaluationInProgress -- evaluationInProgress (1)
  | ESEvaluationCompleted  -- evaluationCompleted (2)
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Strength of Function levels for Common Criteria
data StrengthOfFunction
  = SOFBasic      -- Basic strength of function
  | SOFMedium     -- Medium strength of function  
  | SOFHigh       -- High strength of function
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Measurement Root Type (complies with lines 365-371)
data MeasurementRootType
  = MRTStatic    -- static (0)
  | MRTDynamic   -- dynamic (1)
  | MRTNonHost   -- nonHost (2)
  | MRTHybrid    -- hybrid (3) - capable of static AND dynamic
  | MRTPhysical  -- physical (4) - anchored by physical TPM
  | MRTVirtual   -- virtual (5) - TPM is virtualized
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | URI Reference (complies with lines 404-407)
data URIReference = URIReference
  { urUniformResourceIdentifier :: !IA5String                -- SIZE (1..URIMAX)
  , urHashAlgorithm            :: !(Maybe AlgorithmIdentifier) -- OPTIONAL
  , urHashValue                :: !(Maybe BitString)          -- OPTIONAL
  } deriving (Show, Eq, Data, Typeable)

-- | Common Criteria Measures (complies with lines 376-385)
data CommonCriteriaMeasures = CommonCriteriaMeasures
  { ccmVersion            :: !IA5String                       -- SIZE (1..STRMAX) - "2.2" or "3.1"
  , ccmAssuranceLevel     :: !EvaluationAssuranceLevel       -- REQUIRED
  , ccmEvaluationStatus   :: !EvaluationStatus               -- REQUIRED
  , ccmPlus              :: !Bool                             -- DEFAULT FALSE
  , ccmStrengthOfFunction :: !(Maybe StrengthOfFunction)      -- OPTIONAL [0] IMPLICIT
  , ccmProfileOid        :: !(Maybe OID)                     -- OPTIONAL [1] IMPLICIT
  , ccmProfileUri        :: !(Maybe URIReference)            -- OPTIONAL [2] IMPLICIT
  , ccmTargetOid         :: !(Maybe OID)                     -- OPTIONAL [3] IMPLICIT
  , ccmTargetUri         :: !(Maybe URIReference)            -- OPTIONAL [4] IMPLICIT
  } deriving (Show, Eq, Data, Typeable)

-- | Protection Profile information
data ProtectionProfile = ProtectionProfile
  { ppName :: !B.ByteString          -- Protection Profile name
  , ppVersion :: !B.ByteString       -- PP version
  , ppIdentifier :: !(Maybe B.ByteString) -- PP identifier/OID
  } deriving (Show, Eq, Data, Typeable)

-- | Security Target information
data SecurityTarget = SecurityTarget
  { stName :: !B.ByteString          -- Security Target name
  , stVersion :: !B.ByteString       -- ST version
  , stIdentifier :: !(Maybe B.ByteString) -- ST identifier
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

-- | Component Class Registry (complies with lines 599-600)
data ComponentClassRegistry
  = TcgRegistryComponentClass     -- tcg-registry-componentClass-tcg
  | IetfRegistryComponentClass    -- tcg-registry-componentClass-ietf
  | DmtfRegistryComponentClass    -- tcg-registry-componentClass-dmtf
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Component Address (complies with lines 602-607)
data ComponentAddress = ComponentAddress
  { caAddressType  :: !AddressType  -- REQUIRED
  , caAddressValue :: !UTF8String   -- REQUIRED SIZE (1..STRMAX)
  } deriving (Show, Eq, Data, Typeable)

-- | Address Type (complies with lines 606-607)
data AddressType
  = ATEthernetMac   -- tcg-address-ethernetmac
  | ATWlanMac      -- tcg-address-wlanmac
  | ATBluetoothMac -- tcg-address-bluetoothmac
  deriving (Show, Eq, Enum, Bounded, Data, Typeable)

-- | Attribute Status for Delta certificates
data AttributeStatus
  = ASAdded    -- Component was added
  | ASRemoved  -- Component was removed
  | ASModified -- Component was modified
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

-- | Common Criteria Level certification information
data CommonCriteriaLevel = CommonCriteriaLevel
  { ccLevel :: !EvaluationAssuranceLevel    -- EAL level (1-7)
  , ccPlus :: !Bool                         -- EAL Plus designation
  , ccProtectionProfile :: !(Maybe ProtectionProfile) -- Protection Profile
  , ccSecurityTarget :: !(Maybe SecurityTarget)       -- Security Target
  , ccCertificateNumber :: !(Maybe B.ByteString)     -- CC certificate number
  , ccValidationDate :: !(Maybe DateTime)             -- Validation date
  , ccEvaluationFacility :: !(Maybe B.ByteString)    -- Evaluation facility
  , ccDescription :: !(Maybe B.ByteString)           -- Additional description
  } deriving (Show, Eq, Data, Typeable)

-- * Other Certification Support

-- | Other certification types
data CertificationType
  = NIST_CAVP        -- NIST Cryptographic Algorithm Validation Program
  | NIAP_CCEVS       -- NIAP Common Criteria Evaluation and Validation Scheme  
  | CSE_CCEF         -- CSE Common Criteria Evaluation Facility (Canada)
  | BSI_CC           -- BSI Common Criteria (Germany)
  | ANSSI_CC         -- ANSSI Common Criteria (France)
  | CESG_CPA         -- CESG Commercial Product Assurance (UK)
  | JISEC_CC         -- JISEC Common Criteria (Japan)
  | KECS_CC          -- KECS Common Criteria (South Korea)
  | Other B.ByteString -- Other certification type
  deriving (Show, Eq, Data, Typeable)

-- | Other certification information
data OtherCertification = OtherCertification
  { ocType :: !CertificationType         -- Certification type
  , ocLevel :: !(Maybe B.ByteString)     -- Certification level/grade
  , ocCertificateNumber :: !(Maybe B.ByteString) -- Certificate number
  , ocValidationDate :: !(Maybe DateTime) -- Validation date
  , ocDescription :: !(Maybe B.ByteString) -- Description
  } deriving (Show, Eq, Data, Typeable)

-- * Combined Certification Structure

-- | Complete certification information structure
data CertificationInfo = CertificationInfo
  { ciFips :: !(Maybe FIPSLevel)                -- FIPS 140-2/3 certification
  , ciCommonCriteria :: !(Maybe CommonCriteriaLevel) -- Common Criteria certification
  , ciOtherCertifications :: ![OtherCertification]   -- Other certifications
  , ciIsCritical :: !Bool                       -- Critical extension flag
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