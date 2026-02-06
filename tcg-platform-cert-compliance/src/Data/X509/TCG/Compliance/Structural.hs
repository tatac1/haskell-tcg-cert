{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Structural
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Structural integrity checks (STR-001 to STR-010).
--
-- Validates RFC 5755 and IWG Profile structural requirements for
-- Platform Certificates.

module Data.X509.TCG.Compliance.Structural
  ( -- * All Structural Checks
    runStructuralChecks

    -- * Individual Checks
  , checkVersion        -- STR-001
  , checkHolder         -- STR-002
  , checkIssuer         -- STR-003
  , checkSignatureAlg   -- STR-004
  , checkSerialNumber   -- STR-005
  , checkValidityPeriod -- STR-006
  , checkAttributes     -- STR-007
  , checkExtensionOIDs  -- STR-008
  , checkCriticalExts   -- STR-009
  , checkPlatformUri    -- STR-010
  , checkTcgPlatformSpecification  -- STR-011
  , checkTcgCredentialType         -- STR-012
  , checkTcgCredentialSpecification -- STR-013
  ) where

import Data.Maybe (isJust)
import qualified Data.ByteString as B
import Control.Applicative ((<|>))
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T

import Data.X509 (AltName(..), Extensions(..), ExtensionRaw(..))
 
import Data.X509.AttCert (AttCertIssuer(..), AttCertValidityPeriod(..), Holder(..), V2Form(..))
import qualified Data.X509.AttCert as AC
import Data.X509.Attribute (Attributes(..))

import Data.X509.TCG.Platform (SignedPlatformCertificate, getPlatformCertificate)
import Data.X509.TCG.Platform (PlatformCertificateInfo(..))
import Data.X509.TCG.OID
  ( tcg_ce_relevantCredentials
  , tcg_ce_relevantManifests
  , tcg_ce_virtualPlatform
  , tcg_ce_multiTenant
  , tcg_paa_platformConfigUri
  , tcg_at_platformConfigUri
  , tcg_at_tcgPlatformSpecification
  , tcg_at_tcgCredentialSpecification
  , tcg_at_tcgCredentialType
  )
import Data.X509.TCG.Utils (lookupAttributeByOID)
import qualified Data.X509.TCG.Operations as Ops

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.ASN1
  ( decodeAttributeASN1
  , stripSequenceOrContent
  , parseURIReferenceContent
  , ParsedURIReference(..)
  )
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Internal (lookupRef, ComplianceCheck)

-- | Helper function for showing values as Text
tshow :: Show a => a -> Text
tshow = T.pack . show

withRequirement :: RequirementLevel -> SpecReference -> SpecReference
withRequirement lvl ref = ref { srLevel = lvl }

-- | Run all structural compliance checks
runStructuralChecks :: SignedPlatformCertificate -> ReferenceDB -> IO [CheckResult]
runStructuralChecks cert refDB = sequence
  [ checkVersion cert refDB
  , checkHolder cert refDB
  , checkIssuer cert refDB
  , checkSignatureAlg cert refDB
  , checkSerialNumber cert refDB
  , checkValidityPeriod cert refDB
  , checkAttributes cert refDB
  , checkExtensionOIDs cert refDB
  , checkCriticalExts cert refDB
  , checkPlatformUri cert refDB
  , checkTcgPlatformSpecification cert refDB
  , checkTcgCredentialType cert refDB
  , checkTcgCredentialSpecification cert refDB
  ]

-- | STR-001: Version must be v2 (integer value 1)
-- Reference: IWG Profile §3.2.1, line 1152
-- "version number MUST be set to 2 (which is encoded as the value 1 in ASN.1)"
checkVersion :: ComplianceCheck
checkVersion cert refDB = do
  let cid = CheckId Structural 1
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      version = pciVersion pci
  if version == 1  -- v2 is encoded as integer 1
    then mkPass cid "Version is v2" ref
    else mkFail cid "Version is v2" ref $
           "Expected version 1 (v2), got " <> tshow version

-- | STR-002: Holder must use BaseCertificateID
-- Reference: IWG Profile §3.2.4, line 1168
-- "The BaseCertificateID choice MUST be used"
checkHolder :: ComplianceCheck
checkHolder cert refDB = do
  let cid = CheckId Structural 2
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      holder = pciHolder pci
  -- Validate holder structure per RFC 5755
  -- The holder should have at least baseCertificateID per IWG Profile
  case validateHolderStructure holder of
    Right () -> mkPass cid "Holder uses BaseCertificateID" ref
    Left err -> mkFail cid "Holder uses BaseCertificateID" ref err

-- | Validate holder structure
-- Per IWG Profile, BaseCertificateID MUST be used
-- Per IWG Errata §2.1: "The TPM EK certificate's Issuer and Serial number must be included"
validateHolderStructure :: Holder -> Either Text ()
validateHolderStructure holder = case holderBaseCertificateID holder of
  Nothing
    | isJust (holderEntityName holder) -> Left "Holder uses entityName instead of baseCertificateID"
    | isJust (holderObjectDigestInfo holder) -> Left "Holder uses objectDigestInfo instead of baseCertificateID"
    | otherwise -> Left "Holder is empty (no identification method present)"
  Just issuerSerial ->
    -- Validate content: issuer GeneralNames must not be empty, serial must be present
    let issuerGNs = AC.issuer issuerSerial
        serialNum = AC.serial issuerSerial
    in if null issuerGNs
         then Left "baseCertificateID issuer GeneralNames is empty (must contain EK certificate issuer)"
         else if serialNum <= 0
           then Left "baseCertificateID serial must be a positive integer"
           else Right ()

-- | STR-003: Issuer must contain distinguished name
-- Reference: IWG Profile §3.2.5, line 1175
checkIssuer :: ComplianceCheck
checkIssuer cert refDB = do
  let cid = CheckId Structural 3
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      issuer = pciIssuer pci
  case validateIssuerNotEmpty issuer of
    Right () -> mkPass cid "Issuer contains distinguished name" ref
    Left err -> mkFail cid "Issuer contains distinguished name" ref err

-- | Validate issuer contains a distinguished name (directoryName)
validateIssuerNotEmpty :: AttCertIssuer -> Either Text ()
validateIssuerNotEmpty (AttCertIssuerV1 _) =
  Left "Issuer MUST use v2Form per IWG Profile §3.2.5 (v1Form is not allowed)"
validateIssuerNotEmpty (AttCertIssuerV2 v2form)
  | hasDirectoryName (v2fromIssuerName v2form) = Right ()
  | null (v2fromIssuerName v2form) = Left "Issuer (v2Form) has empty issuerName"
  | otherwise = Left "Issuer (v2Form) must include distinguished name (directoryName)"

hasDirectoryName :: [AltName] -> Bool
hasDirectoryName = any isDirectoryName
  where
    isDirectoryName (AltDirectoryName _) = True
    isDirectoryName _ = False

-- | STR-004: Signature algorithm must be valid AlgorithmIdentifier
-- Reference: IWG Profile §3.2.3, line 1164
checkSignatureAlg :: ComplianceCheck
checkSignatureAlg cert refDB = do
  let cid = CheckId Structural 4
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      sigAlg = pciSignature pci
  case Ops.validateSignatureAlgorithm sigAlg of
    Right () -> mkPass cid "Signature algorithm is valid" ref
    Left err -> mkFail cid "Signature algorithm is valid" ref (T.pack err)

-- | STR-005: Serial number must be positive integer
-- Reference: IWG Profile §3.2.2, line 1159
-- "The serial number MUST be a positive integer"
checkSerialNumber :: ComplianceCheck
checkSerialNumber cert refDB = do
  let cid = CheckId Structural 5
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      serial = pciSerialNumber pci
  if serial > 0
    then mkPass cid "Serial number is positive" ref
    else mkFail cid "Serial number is positive" ref $
           "Serial number must be positive, got " <> tshow serial

-- | STR-006: Validity period must have notBefore <= notAfter
-- Reference: IWG Profile §3.2.6, line 1179
checkValidityPeriod :: ComplianceCheck
checkValidityPeriod cert refDB = do
  let cid = CheckId Structural 6
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      validity = pciValidity pci
  case validateValidityPeriod validity of
    Right () -> mkPass cid "Validity period is valid (notBefore <= notAfter)" ref
    Left err -> mkFail cid "Validity period is valid (notBefore <= notAfter)" ref err

-- | Validate validity period
validateValidityPeriod :: AttCertValidityPeriod -> Either Text ()
validateValidityPeriod validity
  | acNotBefore validity <= acNotAfter validity = Right ()
  | otherwise = Left "notBefore is after notAfter"

-- | STR-007: Attributes SHOULD be included
-- Reference: IWG Profile §3.2.10, line 1213
checkAttributes :: ComplianceCheck
checkAttributes cert refDB = do
  let cid = CheckId Structural 7
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      Attributes attrs = pciAttributes pci
  if not (null attrs)
    then mkPass cid "Attributes are present" ref
    else mkFail cid "Attributes are present" ref "Attributes should be included per IWG Profile"

-- | STR-011: TCG Platform Specification attribute
-- Base: SHOULD be included
-- Delta: MUST NOT be included
-- Reference: IWG Profile §3.2.10, line 740
checkTcgPlatformSpecification :: ComplianceCheck
checkTcgPlatformSpecification cert refDB = do
  let cid = CheckId Structural 11
      certType = detectCertificateType cert
      reqLevel = getRequirementLevel cid certType
      ref = withRequirement reqLevel (lookupRef cid refDB)
      attrs = pciAttributes (getPlatformCertificate cert)
  case certType of
    BasePlatformCert ->
      case lookupAttributeByOID tcg_at_tcgPlatformSpecification attrs of
        Nothing -> mkFail cid "TCG Platform Specification attribute present" ref
          "TCG Platform Specification attribute SHOULD be included per IWG §3.2.10"
        Just [] -> mkFail cid "TCG Platform Specification attribute present" ref
          "TCG Platform Specification attribute is empty"
        Just _ -> mkPass cid "TCG Platform Specification attribute present" ref
    DeltaPlatformCert ->
      case lookupAttributeByOID tcg_at_tcgPlatformSpecification attrs of
        Nothing -> mkPass cid "TCG Platform Specification correctly omitted in Delta" ref
        Just _ -> mkFail cid "TCG Platform Specification omitted in Delta" ref
          "TCG Platform Specification MUST NOT be included in Delta certificates"

-- | STR-012: TCG Credential Type attribute
-- Base: SHOULD be included
-- Delta: MUST be included
-- Reference: IWG Profile §3.2.10, line 743
checkTcgCredentialType :: ComplianceCheck
checkTcgCredentialType cert refDB = do
  let cid = CheckId Structural 12
      certType = detectCertificateType cert
      reqLevel = getRequirementLevel cid certType
      ref = withRequirement reqLevel (lookupRef cid refDB)
      attrs = pciAttributes (getPlatformCertificate cert)
  case lookupAttributeByOID tcg_at_tcgCredentialType attrs of
    Nothing ->
      case certType of
        BasePlatformCert ->
          mkFail cid "TCG Credential Type attribute present" ref
            "TCG Credential Type attribute SHOULD be included per IWG §3.2.10"
        DeltaPlatformCert ->
          mkFail cid "TCG Credential Type attribute present in Delta" ref
            "Delta certificates MUST include TCG Credential Type attribute"
    Just [] -> mkFail cid "TCG Credential Type attribute present" ref
      "TCG Credential Type attribute is empty"
    Just _ -> mkPass cid "TCG Credential Type attribute present" ref

-- | STR-013: TCG Credential Specification attribute
-- Base: SHOULD be included
-- Delta: MAY be included
-- Reference: IWG Profile §3.2.10, line 744
checkTcgCredentialSpecification :: ComplianceCheck
checkTcgCredentialSpecification cert refDB = do
  let cid = CheckId Structural 13
      certType = detectCertificateType cert
      reqLevel = getRequirementLevel cid certType
      ref = withRequirement reqLevel (lookupRef cid refDB)
      attrs = pciAttributes (getPlatformCertificate cert)
  case lookupAttributeByOID tcg_at_tcgCredentialSpecification attrs of
    Nothing ->
      case certType of
        BasePlatformCert ->
          mkFail cid "TCG Credential Specification attribute present" ref
            "TCG Credential Specification attribute SHOULD be included per IWG §3.2.10"
        DeltaPlatformCert ->
          mkSkip cid "TCG Credential Specification attribute in Delta" ref
            "TCG Credential Specification is optional for Delta certificates"
    Just [] -> mkFail cid "TCG Credential Specification attribute present" ref
      "TCG Credential Specification attribute is empty"
    Just _ -> mkPass cid "TCG Credential Specification attribute present" ref

-- | STR-008: Extension OIDs must be unique
-- Reference: RFC 5755 §4.2
checkExtensionOIDs :: ComplianceCheck
checkExtensionOIDs cert refDB = do
  let cid = CheckId Structural 8
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      Extensions mexts = pciExtensions pci
  case mexts of
    Nothing -> mkPass cid "No extensions (unique by vacuity)" ref
    Just exts ->
      let oids = map extRawOID exts
          duplicates = findDuplicates oids
      in if null duplicates
           then mkPass cid "Extension OIDs are unique" ref
           else mkFail cid "Extension OIDs are unique" ref $
                  "Duplicate OIDs: " <> tshow duplicates

-- | Find duplicate elements in a list (unique duplicates)
findDuplicates :: Ord a => [a] -> [a]
findDuplicates xs =
  Map.keys $ Map.filter (> (1 :: Int)) $ Map.fromListWith (+) [(x, 1) | x <- xs]

-- | STR-009: Critical extensions must be processable
-- Reference: RFC 5755 §4.2
checkCriticalExts :: ComplianceCheck
checkCriticalExts cert refDB = do
  let cid = CheckId Structural 9
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      Extensions mexts = pciExtensions pci
  case mexts of
    Nothing -> mkPass cid "No critical extensions" ref
    Just exts ->
      let criticals = filter extRawCritical exts
          unknown = filter (not . isKnownExtension . extRawOID) criticals
      in if null unknown
           then mkPass cid "All critical extensions are processable" ref
           else mkFail cid "All critical extensions are processable" ref $
                  "Unknown critical extensions: " <> tshow (map extRawOID unknown)

-- | Check if an OID is a known extension
isKnownExtension :: [Integer] -> Bool
isKnownExtension oid = oid `elem` knownExtensionOIDs

-- | List of known extension OIDs
knownExtensionOIDs :: [[Integer]]
knownExtensionOIDs =
  [ [2,5,29,35]    -- Authority Key Identifier
  , [2,5,29,14]    -- Subject Key Identifier
  , [2,5,29,31]    -- CRL Distribution Points
  , [1,3,6,1,5,5,7,1,1]  -- Authority Info Access
  , tcg_ce_relevantCredentials
  , tcg_ce_relevantManifests
  , tcg_ce_virtualPlatform
  , tcg_ce_multiTenant
  , [2,5,29,32]    -- Certificate Policies
  , [2,5,29,17]    -- Subject Alternative Name
  , [2,5,29,9]     -- Subject Directory Attributes
  , [2,5,29,37]    -- Extended Key Usage
  , [2,5,29,19]    -- Basic Constraints
  , [2,5,29,54]    -- Inhibit Any Policy (old OID)
  , [2,5,29,55]    -- AC Targeting (RFC 5755)
  , [2,5,29,56]    -- No Assertion (RFC 5755)
  , [2,5,29,57]    -- AA Controls (RFC 5755)
  ]

-- | STR-010: Platform config URI format validation
-- Reference: IWG Profile §3.1.7, line 1044
checkPlatformUri :: ComplianceCheck
checkPlatformUri cert refDB = do
  let cid = CheckId Structural 10
      ref = lookupRef cid refDB
      attrs = pciAttributes (getPlatformCertificate cert)
      values = lookupAttributeByOID tcg_paa_platformConfigUri attrs
        <|> lookupAttributeByOID tcg_at_platformConfigUri attrs
      uriMax = 1024
  case values of
    Nothing -> mkSkip cid "Platform config URI format" ref "No URI present"
    Just [] -> mkFail cid "Platform config URI format" ref "platformConfigUri attribute is empty"
    Just vals ->
      case decodeAttributeASN1 (256 * 1024) vals of
        Left err -> mkFail cid "Platform config URI format" ref err
        Right asn1 ->
          case stripSequenceOrContent asn1 >>= parseURIReferenceContent of
            Left err -> mkFail cid "Platform config URI format" ref err
            Right uriRef ->
              let uriLen = B.length (puriUri uriRef)
                  hasAlg = isJust (puriHashAlg uriRef)
                  hasVal = isJust (puriHashValue uriRef)
              in if uriLen < 1 || uriLen > uriMax
                   then mkFail cid "Platform config URI format" ref "URIReference.uniformResourceIdentifier length out of range"
                   else if hasAlg /= hasVal
                     then mkFail cid "Platform config URI format" ref "URIReference hashAlgorithm/hashValue must both be present"
                     else mkPass cid "Platform config URI format is valid" ref
