{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Reference
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Specification reference database for compliance testing.
--
-- This module provides a comprehensive database of IWG specification
-- references for all compliance checks, enabling traceability.
--
-- Line numbers reference extracted text files in docs/extracted_text/

module Data.X509.TCG.Compliance.Reference
  ( -- * Specification Reference
    SpecReference (..)
  , SpecDocument (..)

    -- * Reference Database
  , ReferenceDB
  , defaultReferenceDB
  , lookupReference

    -- * Reference Formatting
  , formatReference
  , formatReferenceShort
  , documentName
  , documentShortName
  ) where

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T

import Data.X509.TCG.Compliance.Types

-- | Helper function for showing values as Text
tshow :: Show a => a -> Text
tshow = T.pack . show

-- | Specification document identifiers
data SpecDocument
  = IWGProfile           -- ^ IWG Platform Certificate Profile v1.1
  | IWGErrata            -- ^ Platform Certificate Profile Errata v3
  | TCGRegistry          -- ^ TCG Component Class Registry v1.0
  | PCIeRegistry         -- ^ PCIe Component Class Registry v1
  | SMBIOSRegistry       -- ^ SMBIOS Component Class Registry v1.01
  | StorageRegistry      -- ^ Storage Component Class Registry v1.0
  | RFC5755              -- ^ RFC 5755 - Attribute Certificate Profile
  deriving (Show, Eq, Ord, Enum, Bounded)

-- | Complete specification reference with line numbers
data SpecReference = SpecReference
  { srDocument    :: !SpecDocument     -- ^ Source document
  , srSection     :: !Text             -- ^ Section number (e.g., "3.7.1")
  , srTitle       :: !Text             -- ^ Section title
  , srLine        :: !(Maybe Int)      -- ^ Line number in extracted text
  , srLevel       :: !RequirementLevel -- ^ MUST/SHOULD/MAY
  , srQuote       :: !(Maybe Text)     -- ^ Relevant quote from spec
  } deriving (Show, Eq)

-- | Format reference for human-readable output
formatReference :: SpecReference -> Text
formatReference ref = mconcat
  [ documentName (srDocument ref)
  , " §", srSection ref
  , maybe "" (\l -> " (line " <> tshow l <> ")") (srLine ref)
  , " [", tshow (srLevel ref), "]"
  ]

-- | Format reference in short form
formatReferenceShort :: SpecReference -> Text
formatReferenceShort ref = mconcat
  [ documentShortName (srDocument ref)
  , " §", srSection ref
  ]

-- | Get full document name
documentName :: SpecDocument -> Text
documentName = \case
  IWGProfile      -> "IWG Platform Certificate Profile v1.1"
  IWGErrata       -> "Platform Certificate Profile Errata v3"
  TCGRegistry     -> "TCG Component Class Registry v1.0"
  PCIeRegistry    -> "PCIe Component Class Registry v1"
  SMBIOSRegistry  -> "SMBIOS Component Class Registry v1.01"
  StorageRegistry -> "Storage Component Class Registry v1.0"
  RFC5755         -> "RFC 5755"

-- | Get short document name
documentShortName :: SpecDocument -> Text
documentShortName = \case
  IWGProfile      -> "IWG Profile"
  IWGErrata       -> "Errata"
  TCGRegistry     -> "TCG Registry"
  PCIeRegistry    -> "PCIe Registry"
  SMBIOSRegistry  -> "SMBIOS Registry"
  StorageRegistry -> "Storage Registry"
  RFC5755         -> "RFC 5755"

-- | Reference database type
type ReferenceDB = Map CheckId SpecReference

-- | Lookup a reference by CheckId
lookupReference :: CheckId -> ReferenceDB -> Maybe SpecReference
lookupReference = Map.lookup

-- | Default reference database with all compliance checks
-- Line numbers reference IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.txt
defaultReferenceDB :: ReferenceDB
defaultReferenceDB = Map.fromList
  --
  -- ============================================================================
  -- Structural checks (STR-001 to STR-013)
  -- ============================================================================
  --
  [ (CheckId Structural 1, SpecReference IWGProfile "3.2.1" "Version"
      (Just 1152) Must (Just "version number MUST be set to 2 (encoded as value 1)"))
  , (CheckId Structural 2, SpecReference IWGProfile "3.2.4" "Holder"
      (Just 1168) Must (Just "BaseCertificateID choice MUST be used"))
  , (CheckId Structural 3, SpecReference IWGProfile "3.2.5" "Issuer"
      (Just 1175) Must (Just "distinguished name of the entity that issued this Platform Certificate"))
  , (CheckId Structural 4, SpecReference IWGProfile "3.2.3" "Signature Algorithm"
      (Just 1164) Must (Just "Algorithm used by the platform certificate issuer to sign"))
  , (CheckId Structural 5, SpecReference IWGProfile "3.2.2" "Serial Number"
      (Just 1159) Must (Just "serial number MUST be a positive integer"))
  , (CheckId Structural 6, SpecReference IWGProfile "3.2.6" "Validity Period"
      (Just 1179) Must (Just "notBefore and notAfter MUST use appropriate time format"))
  , (CheckId Structural 7, SpecReference IWGProfile "3.2.10" "Attributes"
      (Just 1213) Should (Just "Attributes SHOULD be included"))
  , (CheckId Structural 8, SpecReference RFC5755 "4.2" "Extension OID Uniqueness"
      Nothing Must (Just "Extension OIDs MUST be unique within certificate"))
  , (CheckId Structural 9, SpecReference RFC5755 "4.2" "Critical Extension Processing"
      Nothing Must (Just "Unknown critical extensions MUST cause rejection"))
  , (CheckId Structural 10, SpecReference IWGProfile "3.1.7" "Platform Config URI"
      (Just 1044) May (Just "PlatformConfigUri attribute MAY be included"))
  , (CheckId Structural 11, SpecReference IWGProfile "3.2.10" "TCG Platform Specification attribute"
      (Just 740) Should (Just "Base: SHOULD include; Delta: MUST NOT include"))
  , (CheckId Structural 12, SpecReference IWGProfile "3.2.10" "TCG Credential Type attribute"
      (Just 743) Should (Just "Base: SHOULD include; Delta: MUST include"))
  , (CheckId Structural 13, SpecReference IWGProfile "3.2.10" "TCG Credential Specification attribute"
      (Just 744) Should (Just "Base: SHOULD include; Delta: MAY include"))

  --
  -- ============================================================================
  -- Value checks (VAL-001 to VAL-017)
  -- ============================================================================
  --
  , (CheckId Value 1, SpecReference IWGProfile "3.1.2" "platformManufacturerStr UTF8String"
      (Just 808) Must (Just "UTF8String (SIZE (1..STRMAX))"))
  , (CheckId Value 2, SpecReference IWGProfile "3.1.2" "platformModel UTF8String"
      (Just 813) Must (Just "UTF8String (SIZE (1..STRMAX))"))
  , (CheckId Value 3, SpecReference IWGProfile "3.1.2" "platformVersion UTF8String"
      (Just 818) Must (Just "UTF8String (SIZE (1..STRMAX))"))
  , (CheckId Value 4, SpecReference IWGProfile "3.1.2" "platformSerial UTF8String"
      (Just 821) May (Just "UTF8String (SIZE (1..STRMAX)) OPTIONAL"))
  , (CheckId Value 5, SpecReference IWGProfile "3.1.2" "platformManufacturerId format"
      (Just 824) May (Just "PrivateEnterpriseNumber OPTIONAL"))
  , (CheckId Value 6, SpecReference IWGProfile "3.1.1" "tBBSecurityAssertions SEQUENCE"
      (Just 710) Should (Just "Base: SHOULD include; Delta: MUST NOT include"))
  , (CheckId Value 7, SpecReference IWGProfile "3.1.1" "tBBSecurityAssertions.version INTEGER"
      (Just 711) Must (Just "version Version DEFAULT v1"))
  , (CheckId Value 8, SpecReference IWGProfile "3.1.1" "fipsLevel SecurityLevel 1-4"
      (Just 783) May (Just "SecurityLevel ::= ENUMERATED { level1(1)..level4(4) }"))
  , (CheckId Value 9, SpecReference IWGProfile "3.1.1" "iso9000Certified BOOLEAN"
      (Just 717) May (Just "iso9000Certified BOOLEAN DEFAULT FALSE"))
  , (CheckId Value 10, SpecReference IWGProfile "3.1.1" "EvaluationAssuranceLevel 1-7"
      (Just 749) May (Just "EvaluationAssuranceLevel ::= ENUMERATED { level1(1)..level7(7) }"))
  , (CheckId Value 11, SpecReference IWGProfile "3.1.6" "componentIdentifier structure"
      (Just 960) Must (Just "ComponentIdentifier ::= SEQUENCE"))
  , (CheckId Value 12, SpecReference IWGProfile "3.1.6" "componentClassRegistry OID"
      (Just 977) Must (Just "ComponentClassRegistry ::= OBJECT IDENTIFIER"))
  , (CheckId Value 13, SpecReference TCGRegistry "3" "componentClassValue 4-byte OCTET STRING"
      (Just 228) Must (Just "4-byte OCTET STRING: 2 bytes category + 2 bytes sub-category"))
  , (CheckId Value 14, SpecReference IWGProfile "3.1.6" "attributeCertificateIdentifier"
      (Just 996) Must (Just "AttributeCertificateIdentifier ::= SEQUENCE"))
  , (CheckId Value 15, SpecReference IWGProfile "3.1.6" "componentIdentifierV2 extensions"
      (Just 960) Should (Just "ComponentIdentifier with status field for Delta"))
  , (CheckId Value 16, SpecReference IWGProfile "3.1.6" "certificateIdentifier"
      (Just 992) Must (Just "CertificateIdentifier ::= SEQUENCE"))
  , (CheckId Value 17, SpecReference IWGProfile "3.1.1" "strengthOfFunction 0-2"
      (Just 758) May (Just "StrengthOfFunction ::= ENUMERATED { basic(0), medium(1), high(2) }"))

  --
  -- ============================================================================
  -- Delta checks (DLT-001 to DLT-012)
  -- ============================================================================
  --
  , (CheckId Delta 1, SpecReference IWGProfile "2.2.6.13" "Delta platformConfiguration change semantics"
      (Just 654) May (Just "If included, Delta platformConfiguration MUST only include changed properties"))
  , (CheckId Delta 2, SpecReference IWGProfile "3.3" "Delta must have tcgCredentialType"
      (Just 1296) Must (Just "TCG Certificate Type attribute MUST be included"))
  , (CheckId Delta 3, SpecReference IWGProfile "3.3.2" "Serial Number positive integer"
      (Just 1282) Must (Just "Positive integer value unique relative to the issuer"))
  , (CheckId Delta 4, SpecReference IWGProfile "3.3.4" "Holder references base certificate"
      (Just 1286) Must (Just "Identity of the associated base Platform/Delta Certificate"))
  , (CheckId Delta 5, SpecReference IWGProfile "3.3.6" "Delta validity notAfter must not precede base"
      (Just 823) ShouldNot (Just "notAfter date SHOULD NOT precede that of the base certificate"))
  , (CheckId Delta 6, SpecReference IWGProfile "3.1.6" "AttributeStatus values"
      (Just 1006) Must (Just "AttributeStatus ::= ENUMERATED { added(0), modified(1), removed(2) }"))
  , (CheckId Delta 7, SpecReference IWGProfile "3.1.6" "status field for Delta only"
      (Just 928) Must (Just "status field MUST be used only in Delta Platform Certificates"))
  , (CheckId Delta 8, SpecReference IWGProfile "3.1.6" "componentIdentifiers in Delta"
      (Just 938) Must (Just "status enumerator MUST be included"))
  , (CheckId Delta 9, SpecReference IWGProfile "2.2.6.4" "platformManufacturerStr matches base"
      (Just 611) Must (Just "This field MUST equal that of the base Platform Certificate"))
  , (CheckId Delta 10, SpecReference IWGProfile "2.2.6.6" "platformModel matches base"
      (Just 625) Must (Just "This field MUST equal that of the base Platform Certificate"))
  , (CheckId Delta 11, SpecReference IWGProfile "2.2.6.7" "platformVersion matches base"
      (Just 629) Must (Just "This field MUST equal that of the base Platform Certificate"))
  , (CheckId Delta 12, SpecReference IWGProfile "2.2.6.12" "platformSerial matches base"
      (Just 646) Must (Just "This field MUST equal that of the base Platform Certificate"))

  --
  -- ============================================================================
  -- Chain validation checks (CHN-001 to CHN-005)
  -- ============================================================================
  --
  , (CheckId Chain 1, SpecReference IWGProfile "3.2.11" "Authority Key Identifier"
      (Just 1249) Must (Just "Assign 'critical' the value FALSE; include keyIdentifier if AKI is present"))
  , (CheckId Chain 2, SpecReference IWGProfile "3.2.12" "Authority Info Access"
      (Just 1253) Should (Just "Assign 'critical' the value FALSE; extension MAY be omitted"))
  , (CheckId Chain 3, SpecReference IWGProfile "3.2.13" "CRL Distribution"
      (Just 1262) May (Just "Assign 'critical' the value FALSE; extension MAY be omitted"))
  , (CheckId Chain 4, SpecReference IWGProfile "2.1.5.2" "EK Certificate binding"
      (Just 375) Must (Just "SHALL be an unambiguous indication of the EK Certificates"))
  , (CheckId Chain 5, SpecReference IWGProfile "3.2.9" "Targeting Information"
      (Just 1206) Must (Just "If included, assign 'critical' the value TRUE"))

  --
  -- ============================================================================
  -- Registry validation checks (REG-001 to REG-004)
  -- ============================================================================
  --
  , (CheckId Registry 1, SpecReference IWGProfile "3.1.6" "componentClassRegistry mode-aware OID allowlist"
      (Just 599) Must (Just "OperationalCompatibility: tcg/ietf/dmtf/pcie/storage, StrictV11: tcg/ietf/dmtf"))
  , (CheckId Registry 2, SpecReference IWGProfile "3.1.6" "componentClassValue OCTET STRING SIZE(4)"
      (Just 597) Must (Just "componentClassValue MUST be SIZE(4) and paired with componentClassRegistry"))
  , (CheckId Registry 3, SpecReference TCGRegistry "3" "TCG registry Table 1 class-value conformance"
      (Just 233) Must (Just "tcg registry componentClassValue should conform to normative class table"))
  , (CheckId Registry 4, SpecReference PCIeRegistry "3" "Registry translation-table conformance scope"
      (Just 287) Must (Just "Translation-table constraints are validated where possible; source-data evidence may be required"))

  --
  -- ============================================================================
  -- Extension validation checks (EXT-001 to EXT-005)
  -- ============================================================================
  --
  , (CheckId Extension 1, SpecReference IWGProfile "3.2.7" "Certificate Policies"
      (Just 1186) Must (Just "CertificatePolicies extension MUST be included"))
  , (CheckId Extension 2, SpecReference IWGProfile "3.2.8" "Subject Alternative Names"
      (Just 1197) Must (Just "Subject Alternative Names extension MUST be included"))
  , (CheckId Extension 3, SpecReference IWGProfile "3.2.7" "userNotice policy qualifier"
      (Just 1190) Must (Just "userNotice MUST be 'TCG Trusted Platform Endorsement'"))
  , (CheckId Extension 4, SpecReference IWGProfile "3.2.14" "Issuer Unique Id"
      (Just 1267) MustNot (Just "Issuer Unique Id fields MUST be omitted"))
  , (CheckId Extension 5, SpecReference IWGProfile "3.2.9" "Targeting Information critical"
      (Just 1208) Must (Just "if included, assign 'critical' the value of TRUE"))

  --
  -- ============================================================================
  -- Security assertion checks (SEC-001 to SEC-005)
  -- ============================================================================
  --
  , (CheckId Security 1, SpecReference IWGProfile "3.1.1" "TBBSecurityAssertions for Base only"
      (Just 693) MustNot (Just "tBBSecurityAssertions MUST NOT be included in Delta"))
  , (CheckId Security 2, SpecReference IWGProfile "3.1.3" "TCGPlatformSpecification for Base only"
      (Just 851) MustNot (Just "TCGPlatformSpecification MUST NOT be included in Delta"))
  , (CheckId Security 3, SpecReference IWGProfile "3.1.1" "MeasurementRootType values"
      (Just 727) Must (Just "MeasurementRootType ::= ENUMERATED { static(0)..virtual(5) }"))
  , (CheckId Security 4, SpecReference IWGProfile "3.1.1" "CommonCriteriaMeasures consistency"
      (Just 688) Must (Just "profileOid/profileUri and targetOid/targetUri consistency requires semantic validation"))
  , (CheckId Security 5, SpecReference IWGProfile "3.1.1" "URIReference hash requirements"
      (Just 764) Must (Just "hashAlgorithm and hashValue MUST both exist if either appear"))

  --
  -- ============================================================================
  -- Errata checks (ERR-001 to ERR-005)
  -- ============================================================================
  --
  , (CheckId Errata 1, SpecReference IWGErrata "3.1" "ComponentIdentifier order independence"
      (Just 164) Must (Just "Validators MUST treat componentIdentifiers order as non-significant"))
  , (CheckId Errata 2, SpecReference IWGErrata "2.4" "MAC address format support"
      (Just 109) Should (Just "Verifiers need to support multiple MAC address formats"))
  , (CheckId Errata 3, SpecReference IWGErrata "3.9" "PrivateEnterpriseNumber correction"
      (Just 291) Must (Just "PrivateEnterpriseNumber type correction"))
  , (CheckId Errata 4, SpecReference IWGErrata "2.1" "baseCertificateID encoding"
      (Just 92) Must (Just "TPM EK certificate's Issuer and Serial number must be included"))
  , (CheckId Errata 5, SpecReference IWGErrata "3.6" "48-bit MAC address OIDs"
      (Just 226) Must (Just "tcg-address-ethernetmac/wlanmac/bluetoothmac are limited to 48-bit MAC addresses"))
  ]
