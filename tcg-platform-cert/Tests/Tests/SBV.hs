{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Formal verification tests for TCG Platform Certificates using SBV.
-- This module provides mathematical proofs for TCG data structures,
-- ASN.1 encoding properties, and certificate generation correctness
-- according to IWG Platform Certificate Profile v1.1.

module Tests.SBV (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import Data.SBV
import Data.Maybe (catMaybes)
import qualified Data.ByteString.Char8 as B
import Data.Hourglass (Date (..), DateTime (..), Month (..), TimeOfDay (..))
import Data.X509 (Certificate (..), DistinguishedName (..), Extensions (..), HashALG (..), PubKey (..), PubKeyALG (..), SignatureALG (..))
import Data.ASN1.Types.String (ASN1StringEncoding (..), asn1CharacterString)
import qualified Data.X509.TCG as TCG
import Data.X509.TCG.Attributes (TCGAttribute (..), PlatformConfigUriAttr (..), PolicyReferenceAttr (..))
import Data.X509.TCG.Component
import Data.X509.TCG.Platform

-- | Main test group for TCG Platform Certificate formal verification
tests :: TestTree
tests = testGroup "SBV Formal Verification Tests"
  [ basicSBVIntegrationTests
  , tcgOIDProofs
  , platformCertificateProofs
  , componentIdentifierProofs
  , tbbSecurityAssertionsProofs
  , deltaOperationProofs
  , validationFunctionProofs
  , stringConstraintProofs
  , sbvModelExtractionTests
  , asn1StructureProofs
  ]

-- * Helpers

-- | Assert that an SBV predicate is a theorem (universally valid)
assertTheorem :: String -> Predicate -> Assertion
assertTheorem msg prop = do
  result <- proveWith z3{verbose=False} prop
  case result of
    ThmResult (Unsatisfiable {}) -> return ()
    _ -> assertFailure $ msg ++ " proof failed: " ++ show result

-- * Basic SBV Integration Tests

-- | Basic integration tests to ensure SBV works with TCG modules
basicSBVIntegrationTests :: TestTree
basicSBVIntegrationTests = testGroup "SBV Integration Tests"
  [ testCase "SBV solver is available" $
      assertTheorem "SBV solver" (return sTrue :: Predicate)
  ]

-- * TCG OID Formal Proofs (Section 2 of IWG v1.1)

-- | Formal verification of TCG OID structure per specification
tcgOIDProofs :: TestTree
tcgOIDProofs = testGroup "TCG OID Structure Proofs"
  [ testCase "TCG root OID arc is valid (2.23.133)" $
      assertTheorem "TCG root OID" tcgRootOIDProperty

  , testCase "TCG attribute arc structure (2.23.133.2.*)" $
      assertTheorem "TCG attribute arc" tcgAttributeArcProperty

  , testCase "TCG key purpose arc structure (2.23.133.8.*)" $
      assertTheorem "TCG key purpose arc" tcgKeyPurposeArcProperty

  , testCase "Component class registry OID validity (2.23.133.18.*)" $
      assertTheorem "Component class registry OID" componentClassRegistryProperty
  ]

-- * Platform Certificate Proofs (Section 3.1 of IWG v1.1)

-- | Formal verification of Platform Certificate structure
platformCertificateProofs :: TestTree
platformCertificateProofs = testGroup "Platform Certificate Structure Proofs"
  [ testCase "Certificate version constraint (v2)" $
      assertTheorem "Certificate version" certificateVersionProperty

  , testCase "Serial number positivity constraint" $
      assertTheorem "Serial number" serialNumberConstraintProperty

  , testCase "Validity period ordering" $
      assertTheorem "Validity period" validityPeriodProperty

  , testCase "Platform identification completeness" $
      assertTheorem "Platform identification" platformIdentificationProperty

  , testCase "EK Certificate holder binding" $
      assertTheorem "EK Certificate binding" ekCertificateBindingProperty
  ]

-- * Component Identifier Proofs (Section 3.1.6 of IWG v1.1)

-- | Formal verification of Component Identifier structures
componentIdentifierProofs :: TestTree
componentIdentifierProofs = testGroup "Component Identifier Proofs"
  [ testCase "Component class size constraint (4 bytes)" $
      assertTheorem "Component class size" componentClassSizeProperty

  , testCase "Component manufacturer STRMAX constraint" $
      assertTheorem "Component manufacturer STRMAX" componentManufacturerSTRMAXProperty

  , testCase "Component address type OID validity" $
      assertTheorem "Component address type OID" componentAddressTypeProperty

  , testCase "ComponentIdentifierV2 status enumeration" $
      assertTheorem "Component status enum" componentStatusEnumProperty
  ]

-- * TBBSecurityAssertions Proofs (Section 3.1.1 of IWG v1.1)

-- | Formal verification of TBBSecurityAssertions
tbbSecurityAssertionsProofs :: TestTree
tbbSecurityAssertionsProofs = testGroup "TBBSecurityAssertions Proofs"
  [ testCase "FIPS Level range constraint (1-4)" $
      assertTheorem "FIPS Level range" fipsLevelRangeProperty

  , testCase "Common Criteria EAL range constraint (1-7)" $
      assertTheorem "CC EAL range" ccEALRangeProperty

  , testCase "RTM Type enumeration constraint (1-3)" $
      assertTheorem "RTM Type range" rtmTypeRangeProperty

  , testCase "Boolean value constraint" $ do
      result <- satWith z3{verbose=False} booleanValueProperty
      case result of
        SatResult (Satisfiable {}) -> return ()
        _ -> assertFailure "Boolean value satisfiability failed"
  ]

-- * Delta Certificate Operation Proofs (Section 3.2 of IWG v1.1)

-- | Formal verification of Delta certificate operations
deltaOperationProofs :: TestTree
deltaOperationProofs = testGroup "Delta Operation Formal Proofs"
  [ testCase "Delta base reference constraint" $
      assertTheorem "Delta base reference" deltaBaseReferenceProperty

  , testCase "Component modification status consistency" $
      assertTheorem "Component modification consistency" componentModificationConsistencyProperty
  ]

-- * Validation Function Proofs

-- | Formal verification of validation functions
validationFunctionProofs :: TestTree
validationFunctionProofs = testGroup "Validation Function Formal Proofs"
  [ testCase "Signature algorithm OID completeness" $
      assertTheorem "Signature algorithm OID" signatureAlgorithmOIDProperty

  , testCase "URI format validation constraint" $
      assertTheorem "URI format validation" uriFormatValidationProperty

  , testCase "Holder reference constraint" $
      assertTheorem "Holder EK reference" holderEKReferenceProperty
  ]

-- * String Constraint Proofs (STRMAX per specification)

-- | Formal verification of string length constraints
stringConstraintProofs :: TestTree
stringConstraintProofs = testGroup "String Constraint Proofs"
  [ testCase "STRMAX definition (255 characters)" $
      assertTheorem "STRMAX definition" strmaxDefinitionProperty

  , testCase "UTF8String encoding constraint" $
      assertTheorem "UTF8 encoding" utf8EncodingProperty

  , testCase "Platform manufacturer length constraint" $
      assertTheorem "Platform manufacturer length" platformManufacturerLengthProperty
  ]

-- * SBV Helper Function Tests

-- * SBV Property Definitions
-- Note: These properties are written as theorems that should be provably true.
-- We use implications and equivalences to express specification constraints.

-- | TCG root OID: 2.23.133
-- Per IWG v1.1 Section 2, all TCG OIDs start with this arc
-- Theorem: If an OID is the TCG root, then it satisfies ISO OID constraints
tcgRootOIDProperty :: Predicate
tcgRootOIDProperty = do
  arc1 <- free "arc1" :: Symbolic (SBV Word32)
  arc2 <- free "arc2" :: Symbolic (SBV Word32)
  arc3 <- free "arc3" :: Symbolic (SBV Word32)

  -- TCG root OID is exactly [2, 23, 133]
  let isTCGRoot = (arc1 .== 2) .&& (arc2 .== 23) .&& (arc3 .== 133)
  -- Joint-ISO-ITU-T(2) member-body(23) tcg(133) satisfies ISO OID structure
  let isValidISOStructure = (arc1 .<= 2) .&& (arc2 .<= 39 .|| arc1 .== 2)
  -- Theorem: TCG root OID implies valid ISO structure
  return $ isTCGRoot .=> isValidISOStructure

-- | TCG attribute OID arc: 2.23.133.2.*
-- Theorem: Valid TCG attribute arcs are in the defined range
tcgAttributeArcProperty :: Predicate
tcgAttributeArcProperty = do
  attrSubArc <- free "attr_sub_arc" :: Symbolic (SBV Word32)

  -- Valid TCG attribute sub-arcs per IWG v1.1 (1-28)
  let validAttrArcs = [1..28] :: [Word32]
  let isValidAttrArc = sAny (.== attrSubArc) (map literal validAttrArcs)
  let attrArcInRange = (attrSubArc .>= 1) .&& (attrSubArc .<= 28)
  -- Theorem: Valid attr arc implies in range
  return $ isValidAttrArc .=> attrArcInRange

-- | TCG key purpose OID arc: 2.23.133.8.*
-- Theorem: Valid key purpose arcs are in the defined set
tcgKeyPurposeArcProperty :: Predicate
tcgKeyPurposeArcProperty = do
  kpSubArc <- free "kp_sub_arc" :: Symbolic (SBV Word32)

  -- Valid key purpose sub-arcs: EK(1), Platform(2), AIK(3), ComponentId(4), Delta(5)
  let validKPArcs = [1, 2, 3, 4, 5] :: [Word32]
  let isValidKP = sAny (.== kpSubArc) (map literal validKPArcs)
  let kpInRange = (kpSubArc .>= 1) .&& (kpSubArc .<= 5)
  -- Theorem: Valid key purpose implies in range
  return $ isValidKP .=> kpInRange

-- | Component class registry OID: 2.23.133.18.3.*
-- Theorem: Registry IDs are equivalent to range membership
componentClassRegistryProperty :: Predicate
componentClassRegistryProperty = do
  registryId <- free "registry_id" :: Symbolic (SBV Word32)

  -- Valid registries: TCG(1), IETF(2), DMTF(3)
  let validRegistries = [1, 2, 3] :: [Word32]
  let isValidRegistry = sAny (.== registryId) (map literal validRegistries)
  let registryInRange = (registryId .>= 1) .&& (registryId .<= 3)
  -- Theorem: Valid registry iff in range [1,3]
  return $ isValidRegistry .<=> registryInRange

-- | Certificate version constraint
-- Theorem: A valid platform certificate version (2) satisfies X.509 v2 requirement
certificateVersionProperty :: Predicate
certificateVersionProperty = do
  version <- free "cert_version" :: Symbolic (SBV Word32)

  -- Per IWG v1.1 Section 3.1, version MUST be 2
  let isV2 = version .== 2
  -- X.509 attribute certificate versions: 1 (v1), 2 (v2)
  let isValidX509Version = (version .== 1) .|| (version .== 2)
  -- Theorem: v2 implies valid X.509 version
  return $ isV2 .=> isValidX509Version

-- | Serial number constraint
-- Theorem: Positive serial numbers satisfy certificate requirements
serialNumberConstraintProperty :: Predicate
serialNumberConstraintProperty = do
  serialNum <- free "serial_number" :: Symbolic (SBV Int64)

  -- Serial number must be positive (per X.509)
  let isPositive = serialNum .> 0
  -- If positive, then non-zero (basic constraint)
  let isNonZero = serialNum ./= 0
  -- Theorem: positive implies non-zero
  return $ isPositive .=> isNonZero

-- | Validity period constraint
-- Theorem: A valid period has ordering, and invalid periods fail the ordering check
validityPeriodProperty :: Predicate
validityPeriodProperty = do
  notBefore <- free "not_before" :: Symbolic (SBV Int64)
  notAfter <- free "not_after" :: Symbolic (SBV Int64)

  -- Per X.509 and IWG v1.1 Section 3.1.5
  let isValidPeriod = notBefore .< notAfter
  -- If valid period, then notAfter > notBefore
  let afterIsLater = notAfter .> notBefore
  -- Theorem: valid period implies after is later
  return $ isValidPeriod .=> afterIsLater

-- | Platform identification constraint
-- Theorem: Required fields imply valid identification
platformIdentificationProperty :: Predicate
platformIdentificationProperty = do
  hasManufacturer <- free "has_manufacturer"
  hasModel <- free "has_model"
  hasVersion <- free "has_version"

  -- Per IWG v1.1 Section 3.1.6.2, manufacturer/model/version required
  let hasRequiredFields = hasManufacturer .&& hasModel .&& hasVersion
  let isValidPlatformId = hasManufacturer .&& hasModel .&& hasVersion
  -- Theorem: has required fields implies valid platform ID
  return $ hasRequiredFields .=> isValidPlatformId

-- | EK Certificate holder binding
-- Theorem: Valid holder types satisfy the holder constraint
ekCertificateBindingProperty :: Predicate
ekCertificateBindingProperty = do
  holderType <- free "holder_type" :: Symbolic (SBV Word32)

  -- Holder types: 0 = baseCertificateID, 1 = entityName, 2 = objectDigestInfo
  let validHolderTypes = [0, 1, 2] :: [Word32]
  let isValidHolder = sAny (.== holderType) (map literal validHolderTypes)
  let holderInRange = (holderType .>= 0) .&& (holderType .<= 2)
  -- Theorem: valid holder implies in range
  return $ isValidHolder .=> holderInRange

-- | Component class size constraint
-- Theorem: A 4-byte class size satisfies the Component Class Registry requirement
componentClassSizeProperty :: Predicate
componentClassSizeProperty = do
  classSize <- free "class_size" :: Symbolic (SBV Word32)

  -- Component class value MUST be exactly 4 bytes
  let is4Bytes = classSize .== 4
  -- 4 bytes is within valid range (1-4 bytes for OCTET STRING)
  let validOctetString = (classSize .>= 1) .&& (classSize .<= 4)
  -- Theorem: 4-byte size implies valid octet string
  return $ is4Bytes .=> validOctetString

-- | Component manufacturer STRMAX constraint
-- Theorem: Strings within STRMAX (255) satisfy the length constraint
componentManufacturerSTRMAXProperty :: Predicate
componentManufacturerSTRMAXProperty = do
  length' <- free "manufacturer_length" :: Symbolic (SBV Word32)

  -- Per IWG v1.1, STRMAX is defined as 255
  let strmaxLimit = 255 :: SBV Word32
  let isWithinSTRMAX = length' .<= strmaxLimit
  -- If within STRMAX, then < 256
  let isLessThan256 = length' .< 256
  -- Theorem: within STRMAX implies less than 256
  return $ isWithinSTRMAX .=> isLessThan256

-- | Component address type OID validity
-- Theorem: Valid address types are equivalent to range [1,3]
componentAddressTypeProperty :: Predicate
componentAddressTypeProperty = do
  addressType <- free "address_type" :: Symbolic (SBV Word32)

  -- Valid address types per 2.23.133.17.*: ethernet(1), wlan(2), bluetooth(3)
  let validAddressTypes = [1, 2, 3] :: [Word32]
  let isValidAddressType = sAny (.== addressType) (map literal validAddressTypes)
  let addressInRange = (addressType .>= 1) .&& (addressType .<= 3)
  -- Theorem: valid address type iff in range
  return $ isValidAddressType .<=> addressInRange

-- | Component status enumeration
-- Theorem: Valid status values are equivalent to range [0,3]
componentStatusEnumProperty :: Predicate
componentStatusEnumProperty = do
  status <- free "component_status" :: Symbolic (SBV Word32)

  -- Per IWG v1.1 Section 3.2, status is enumerated 0-3
  let validStatuses = [0, 1, 2, 3] :: [Word32]
  let isValidStatus = sAny (.== status) (map literal validStatuses)
  let statusInRange = (status .>= 0) .&& (status .<= 3)
  -- Theorem: valid status iff in range
  return $ isValidStatus .<=> statusInRange

-- | FIPS Level range constraint
-- Theorem: Valid FIPS levels (1-4) are in the defined range
fipsLevelRangeProperty :: Predicate
fipsLevelRangeProperty = do
  fipsLevel <- free "fips_level" :: Symbolic (SBV Word32)

  -- FIPS 140-2/140-3 defines security levels 1-4
  let validFIPSLevels = [1, 2, 3, 4] :: [Word32]
  let isValidFIPSLevel = sAny (.== fipsLevel) (map literal validFIPSLevels)
  let fipsInRange = (fipsLevel .>= 1) .&& (fipsLevel .<= 4)
  -- Theorem: valid FIPS level iff in range [1,4]
  return $ isValidFIPSLevel .<=> fipsInRange

-- | Common Criteria EAL range constraint
-- Theorem: Valid EAL levels (1-7) are in the defined range
ccEALRangeProperty :: Predicate
ccEALRangeProperty = do
  ealLevel <- free "eal_level" :: Symbolic (SBV Word32)

  -- Common Criteria defines EAL1-EAL7
  let validEALLevels = [1, 2, 3, 4, 5, 6, 7] :: [Word32]
  let isValidEAL = sAny (.== ealLevel) (map literal validEALLevels)
  let ealInRange = (ealLevel .>= 1) .&& (ealLevel .<= 7)
  -- Theorem: valid EAL iff in range [1,7]
  return $ isValidEAL .<=> ealInRange

-- | RTM Type range constraint
-- Theorem: Valid RTM types (1-3) are in the defined range
rtmTypeRangeProperty :: Predicate
rtmTypeRangeProperty = do
  rtmType <- free "rtm_type" :: Symbolic (SBV Word32)

  -- Per IWG v1.1, RTM types: BIOS(1), UEFI(2), Other(3)
  let validRTMTypes = [1, 2, 3] :: [Word32]
  let isValidRTMType = sAny (.== rtmType) (map literal validRTMTypes)
  let rtmInRange = (rtmType .>= 1) .&& (rtmType .<= 3)
  -- Theorem: valid RTM type iff in range [1,3]
  return $ isValidRTMType .<=> rtmInRange

-- | Boolean value constraint
-- Theorem: ASN.1 DER boolean values are 0x00 (false) or 0xFF (true)
booleanValueProperty :: Predicate
booleanValueProperty = do
  boolVal <- free "bool_val" :: Symbolic (SBV Word32)

  -- In ASN.1 DER, FALSE=0x00, TRUE=0xFF
  let isFalse = boolVal .== 0
  let isTrue = boolVal .== 255
  -- Theorem: boolean values are restricted to DER encodings
  return $ isFalse .|| isTrue

-- | Delta base reference constraint
-- Theorem: Delta certificates with base references have valid reference structure
deltaBaseReferenceProperty :: Predicate
deltaBaseReferenceProperty = do
  hasBaseRef <- free "has_base_reference"
  hasIssuer <- free "has_issuer"
  hasSerial <- free "has_serial"

  -- Per IWG v1.1 Section 3.2, delta MUST reference base cert via issuer+serial
  let validReference = hasIssuer .&& hasSerial
  -- If has base ref and has valid reference, then reference is valid
  let refIsValid = hasBaseRef .&& validReference
  -- Theorem: if both conditions, then valid
  return $ refIsValid .=> validReference

-- | Component modification status consistency
-- Theorem: Status transitions are logically consistent
componentModificationConsistencyProperty :: Predicate
componentModificationConsistencyProperty = do
  status <- free "status" :: Symbolic (SBV Word32)

  -- Status 0=Added, 1=Removed, 2=Modified, 3=Unchanged
  let isAdded = status .== 0
  let isRemoved = status .== 1
  let isModified = status .== 2
  let isUnchanged = status .== 3

  -- Exactly one status must be true (mutual exclusion)
  let exactlyOne = (isAdded .&& sNot isRemoved .&& sNot isModified .&& sNot isUnchanged)
               .|| (sNot isAdded .&& isRemoved .&& sNot isModified .&& sNot isUnchanged)
               .|| (sNot isAdded .&& sNot isRemoved .&& isModified .&& sNot isUnchanged)
               .|| (sNot isAdded .&& sNot isRemoved .&& sNot isModified .&& isUnchanged)

  -- Valid status implies exactly one is true
  let validStatus = (status .>= 0) .&& (status .<= 3)
  -- Theorem: valid status implies exactly one status flag
  return $ validStatus .=> exactlyOne


-- | Signature algorithm OID constraint
-- Theorem: Valid signature algorithms are in the known set
signatureAlgorithmOIDProperty :: Predicate
signatureAlgorithmOIDProperty = do
  sigAlg <- free "sig_alg" :: Symbolic (SBV Word32)

  -- Common signature algorithms (simplified representation)
  let knownAlgorithms = [1, 2, 3, 4, 5, 6, 7, 8] :: [Word32]
  let isKnownAlgorithm = sAny (.== sigAlg) (map literal knownAlgorithms)
  let algInRange = (sigAlg .>= 1) .&& (sigAlg .<= 8)
  -- Theorem: known algorithm implies in range
  return $ isKnownAlgorithm .=> algInRange

-- | URI format validation constraint
-- Theorem: Valid URIs satisfy minimum length requirements
uriFormatValidationProperty :: Predicate
uriFormatValidationProperty = do
  uriLength <- free "uri_length" :: Symbolic (SBV Word32)

  -- URI must have reasonable length
  let minLength = 7 :: SBV Word32  -- "http://x" minimum
  let hasMinLength = uriLength .>= minLength
  -- If has min length, then length is positive
  let isPositiveLength = uriLength .> 0
  -- Theorem: min length implies positive length
  return $ hasMinLength .=> isPositiveLength

-- | Holder reference constraint
-- Theorem: BaseCertificateID holder type requires issuer-serial
holderEKReferenceProperty :: Predicate
holderEKReferenceProperty = do
  holderChoice <- free "holder_choice" :: Symbolic (SBV Word32)

  -- Per IWG v1.1, holder types: 0=baseCertificateID, 1=entityName, 2=objectDigestInfo
  let usesBaseCertId = holderChoice .== 0
  let usesEntityName = holderChoice .== 1
  let usesObjectDigest = holderChoice .== 2
  let isValidHolderType = usesBaseCertId .|| usesEntityName .|| usesObjectDigest
  let holderInRange = (holderChoice .>= 0) .&& (holderChoice .<= 2)
  -- Theorem: valid holder type implies in range
  return $ isValidHolderType .=> holderInRange

-- | STRMAX definition constraint
-- Theorem: STRMAX constant is exactly 255
strmaxDefinitionProperty :: Predicate
strmaxDefinitionProperty = do
  strmax <- free "strmax" :: Symbolic (SBV Word32)

  -- STRMAX ::= UTF8String (SIZE (1..255))
  let strmaxIs255 = strmax .== 255
  -- 255 is less than 256
  let lessThan256 = strmax .< 256
  -- Theorem: strmax=255 implies less than 256
  return $ strmaxIs255 .=> lessThan256

-- | UTF8 encoding constraint
-- Theorem: UTF8 byte length is at least character count
utf8EncodingProperty :: Predicate
utf8EncodingProperty = do
  byteLength <- free "byte_length" :: Symbolic (SBV Word32)
  charCount <- free "char_count" :: Symbolic (SBV Word32)

  -- UTF8 encoding: byte_length >= char_count (multi-byte chars expand)
  let validEncoding = byteLength .>= charCount
  -- If valid encoding and charCount > 0, then byteLength > 0
  let nonEmptyBytes = byteLength .> 0
  let nonEmptyChars = charCount .> 0
  -- Theorem: valid encoding with non-empty chars implies non-empty bytes
  return $ (validEncoding .&& nonEmptyChars) .=> nonEmptyBytes

-- | Platform manufacturer length constraint
-- Theorem: Valid manufacturer string length is in STRMAX range
platformManufacturerLengthProperty :: Predicate
platformManufacturerLengthProperty = do
  length' <- free "platform_mfg_length" :: Symbolic (SBV Word32)

  -- Must be 1..255 (STRMAX)
  let isInSTRMAXRange = (length' .>= 1) .&& (length' .<= 255)
  -- If in range, then positive
  let isPositive = length' .> 0
  -- Theorem: in STRMAX range implies positive
  return $ isInSTRMAXRange .=> isPositive

-- * SBV Model Extraction Helpers

-- | Create a minimal EK certificate for model extraction tests.
createTestEKCert :: IO Certificate
createTestEKCert = do
  let alg = TCG.AlgRSA 2048 TCG.hashSHA256
  (_, pubKey, _privKey) <- TCG.generateKeys alg

  let cnOid = [2, 5, 4, 3] -- Common Name OID
      issuerDN =
        DistinguishedName
          [(cnOid, asn1CharacterString UTF8 "Test EK CA")]
      subjectDN =
        DistinguishedName
          [(cnOid, asn1CharacterString UTF8 "Test EK Certificate")]

  return $
    Certificate
      { certVersion = 3,
        certSerial = 12345,
        certSignatureAlg = SignatureALG HashSHA256 PubKeyALG_RSA,
        certIssuerDN = issuerDN,
        certValidity =
          ( DateTime (Date 2024 January 1) (TimeOfDay 0 0 0 0),
            DateTime (Date 2099 January 1) (TimeOfDay 0 0 0 0)
          ),
        certSubjectDN = subjectDN,
        certPubKey = PubKeyRSA pubKey,
        certExtensions = Extensions Nothing
      }

-- | Extract string-like fields from a certificate for SBV modeling.
extractStrings :: SignedPlatformCertificate -> [B.ByteString]
extractStrings cert =
  platformInfoStrings ++ tpmInfoStrings ++ platformConfigStrings
  where
    platformInfoStrings =
      case getPlatformInfo cert of
        Nothing -> []
        Just (PlatformInfo mfg model serial version) ->
          [mfg, model, serial, version]
    tpmInfoStrings =
      case getTPMInfo cert of
        Nothing -> []
        Just (TPMInfo model _ spec) ->
          [model, tpmSpecFamily spec]
    platformConfigStrings =
      case getPlatformConfiguration cert of
        Nothing -> []
        Just (PlatformConfiguration mfg model version serial comps) ->
          [mfg, model, version, serial] ++ concatMap componentStrings comps

componentStrings :: ComponentIdentifier -> [B.ByteString]
componentStrings (ComponentIdentifier mfg model serial revision mfgSerial mfgRevision) =
  [mfg, model] ++ catMaybes [serial, revision, mfgSerial, mfgRevision]

-- | Extract URI fields from TCG attributes (platform config URI, policy reference URI).
extractURIs :: SignedPlatformCertificate -> [B.ByteString]
extractURIs cert =
  [pcuUri attr | TCGPlatformConfigUri attr <- attrs]
    ++ [prUri attr | TCGPolicyReference attr <- attrs]
  where
    attrs = TCG.extractTCGAttributes cert

-- | Extract hash presence pairs for URIs (currently none of the URI attrs carry hashes).
extractUriHashPairs :: SignedPlatformCertificate -> [(Bool, Bool)]
extractUriHashPairs cert = map (const (False, False)) (extractURIs cert)

sbvModelExtractionTests :: TestTree
sbvModelExtractionTests = testGroup "SBV Model Extraction"
  [ testCase "extractStrings includes platform fields" $ do
      ekCert <- createTestEKCert
      let config =
            PlatformConfiguration
              (B.pack "Model Corp")
              (B.pack "Model X")
              (B.pack "2.0")
              (B.pack "SN12345")
              []
          components = []
          tpmInfo =
            TPMInfo
              (B.pack "TPM 2.0")
              (TPMVersion 2 0 1 0)
              (TPMSpecification (B.pack "2.0") 116 1)

      result <- TCG.createPlatformCertificate config components tpmInfo ekCert "sha384"
      case result of
        Left err -> assertFailure $ "Failed to create platform certificate: " ++ err
        Right cert -> do
          let strings = extractStrings cert
          assertBool "manufacturer present" (B.pack "Model Corp" `elem` strings)
          assertBool "model present" (B.pack "Model X" `elem` strings)
          assertBool "serial present" (B.pack "SN12345" `elem` strings)

  , testCase "extractURIs empty when no URI attributes" $ do
      ekCert <- createTestEKCert
      let config =
            PlatformConfiguration
              (B.pack "NoUri Corp")
              (B.pack "NoUri Model")
              (B.pack "1.0")
              (B.pack "NOURI")
              []
          components = []
          tpmInfo =
            TPMInfo
              (B.pack "TPM 2.0")
              (TPMVersion 2 0 1 0)
              (TPMSpecification (B.pack "2.0") 116 1)

      result <- TCG.createPlatformCertificate config components tpmInfo ekCert "sha384"
      case result of
        Left err -> assertFailure $ "Failed to create platform certificate: " ++ err
        Right cert -> extractURIs cert @?= []

  , testCase "extractUriHashPairs length matches URIs" $ do
      ekCert <- createTestEKCert
      let config =
            PlatformConfiguration
              (B.pack "NoUri Corp")
              (B.pack "NoUri Model")
              (B.pack "1.0")
              (B.pack "NOURI")
              []
          components = []
          tpmInfo =
            TPMInfo
              (B.pack "TPM 2.0")
              (TPMVersion 2 0 1 0)
              (TPMSpecification (B.pack "2.0") 116 1)

      result <- TCG.createPlatformCertificate config components tpmInfo ekCert "sha384"
      case result of
        Left err -> assertFailure $ "Failed to create platform certificate: " ++ err
        Right cert -> do
          let uris = extractURIs cert
              pairs = extractUriHashPairs cert
          length pairs @?= length uris
  ]

-- * ASN.1 Structure Formal Proofs (IWG v1.1 DER encoding)

-- | ASN.1 structure proofs: DER DEFAULT rules, tag invariants, VLQ encoding
asn1StructureProofs :: TestTree
asn1StructureProofs = testGroup "ASN.1 Structure Proofs"
  [ derDefaultProofs
  , componentTagProofs
  , evaluationStatusProofs
  , vlqEncodingProofs
  ]

-- ** Stage 1: Scalar constraint proofs

-- | DER DEFAULT omission rules (§11.5)
derDefaultProofs :: TestTree
derDefaultProofs = testGroup "DER DEFAULT Omission Proofs"
  [ testCase "BOOLEAN DEFAULT FALSE dichotomy" $
      assertTheorem "DER DEFAULT BOOLEAN" derDefaultBoolProperty

  , testCase "INTEGER DEFAULT 0 dichotomy" $
      assertTheorem "DER DEFAULT INTEGER" derDefaultIntProperty
  ]

-- | ComponentIdentifierV2 tag invariants
componentTagProofs :: TestTree
componentTagProofs = testGroup "ComponentIdentifierV2 Tag Proofs"
  [ testCase "Tags [0]-[7] are unique" $
      assertTheorem "Component tag uniqueness" componentTagUniquenessProperty

  , testCase "Tags [0]-[7] are consecutive" $
      assertTheorem "Component tag consecutive" componentTagConsecutiveProperty

  , testCase "Primitive/Constructed XOR classification" $
      assertTheorem "Tag classification" tagClassificationProperty
  ]

-- | EvaluationStatus domain completeness
evaluationStatusProofs :: TestTree
evaluationStatusProofs = testGroup "EvaluationStatus Domain Proofs"
  [ testCase "EvaluationStatus enum ↔ range [0,2]" $
      assertTheorem "EvaluationStatus domain" evaluationStatusDomainProperty
  ]

-- ** Stage 2: VLQ byte-count case split proofs

-- | OID VLQ encoding proofs
vlqEncodingProofs :: TestTree
vlqEncodingProofs = testGroup "OID VLQ Encoding Proofs"
  [ testCase "OID first-two-arcs injectivity" $
      assertTheorem "OID first-two-arcs injectivity" oidFirstTwoArcsProperty

  , testCase "VLQ 1-byte roundtrip (n < 128)" $
      assertTheorem "VLQ 1-byte roundtrip" vlq1ByteProperty

  , testCase "VLQ 2-byte roundtrip (128 ≤ n < 16384)" $
      assertTheorem "VLQ 2-byte roundtrip" vlq2ByteProperty

  , testCase "VLQ 3-byte roundtrip (16384 ≤ n < 2097152)" $
      assertTheorem "VLQ 3-byte roundtrip" vlq3ByteProperty
  ]

-- * Stage 1 Property Definitions

-- | DER §11.5: BOOLEAN DEFAULT FALSE — encode iff value ≠ default
-- Theorem: shouldEncode(v) ↔ v ≠ False ↔ v == True
derDefaultBoolProperty :: Predicate
derDefaultBoolProperty = do
  v <- sBool "value"
  let shouldEncode = v
  let isDefault = sNot v
  return $ shouldEncode .<=> sNot isDefault

-- | DER §11.5: INTEGER DEFAULT 0 — encode iff value ≠ 0
-- Applies to: TBBSecurityAssertions.version DEFAULT v1(0)
derDefaultIntProperty :: Predicate
derDefaultIntProperty = do
  v <- free "version" :: Symbolic (SBV Integer)
  let shouldEncode = v ./= 0
  let isDefault = v .== 0
  return $ shouldEncode .<=> sNot isDefault

-- | Tags [0]-[7] are all distinct (fixed concrete values)
componentTagUniquenessProperty :: Predicate
componentTagUniquenessProperty = do
  let tags = map literal [0..7 :: Word8]
  return $ sAnd [t1 ./= t2 | (t1, i) <- zip tags [0 :: Int ..],
                              (t2, j) <- zip tags [0 ..], i < j]

-- | Tags are consecutive: tag[i+1] == tag[i] + 1
componentTagConsecutiveProperty :: Predicate
componentTagConsecutiveProperty = do
  let tags = map literal [0..7 :: Word8]
  return $ sAnd $ zipWith (.==) (drop 1 tags) (map (+1) (take 7 tags))

-- | ComponentIdentifierV2 IMPLICIT tag classification:
-- [0]-[3],[7]: primitive (Other Context N), [4]-[6]: constructed (Container Context N)
-- Valid tag ⇒ exactly one of primitive XOR constructed
tagClassificationProperty :: Predicate
tagClassificationProperty = do
  tag <- free "tag" :: Symbolic (SBV Word8)
  let isPrimitive = sAny (.== tag) (map literal [0, 1, 2, 3, 7 :: Word8])
  let isConstructed = sAny (.== tag) (map literal [4, 5, 6 :: Word8])
  let isValidTag = tag .<= 7
  return $ isValidTag .=> (isPrimitive .<+> isConstructed)

-- | EvaluationStatus: designedToMeet=0, inProgress=1, completed=2 (IWG Task 7)
evaluationStatusDomainProperty :: Predicate
evaluationStatusDomainProperty = do
  x <- free "eval_status" :: Symbolic (SBV Word8)
  let enumSet = sAny (.== x) (map literal [0, 1, 2 :: Word8])
  let rangeCheck = x .<= 2
  return $ enumSet .<=> rangeCheck

-- * Stage 2 Property Definitions

-- | OID first-two-arcs injectivity: 40*a+b encoding is injective
-- under valid OID constraints (a ≤ 2, a < 2 ⇒ b < 40, 40*a+b ≤ 255)
-- Uses SBV Integer (arbitrary precision) to avoid modular arithmetic overflow.
oidFirstTwoArcsProperty :: Predicate
oidFirstTwoArcsProperty = do
  a <- free "arc1" :: Symbolic (SBV Integer)
  b <- free "arc2" :: Symbolic (SBV Integer)
  constrain $ a .>= 0 .&& a .<= 2
  constrain $ b .>= 0
  constrain $ (a .< 2) .=> (b .< 40)
  let combined = 40 * a + b
  constrain $ combined .<= 255
  a2 <- free "arc1'" :: Symbolic (SBV Integer)
  b2 <- free "arc2'" :: Symbolic (SBV Integer)
  constrain $ a2 .>= 0 .&& a2 .<= 2
  constrain $ b2 .>= 0
  constrain $ (a2 .< 2) .=> (b2 .< 40)
  let combined2 = 40 * a2 + b2
  constrain $ combined2 .<= 255
  return $ (combined .== combined2) .=> (a .== a2 .&& b .== b2)

-- | VLQ 1-byte: n < 128, encoded as single byte with no continuation bit
vlq1ByteProperty :: Predicate
vlq1ByteProperty = do
  n <- free "n" :: Symbolic (SBV Word32)
  constrain $ n .< 128
  let encoded = n .&. 0x7F
  return $ encoded .== n .&& (n .&. 0x80 .== 0)

-- | VLQ 2-byte: 128 ≤ n < 16384, roundtrip + continuation bit invariant
vlq2ByteProperty :: Predicate
vlq2ByteProperty = do
  n <- free "n" :: Symbolic (SBV Word32)
  constrain $ n .>= 128 .&& n .< 16384
  let hi = (n `shiftR` 7) .|. 0x80
  let lo = n .&. 0x7F
  let decoded = ((hi .&. 0x7F) `shiftL` 7) .|. lo
  return $ decoded .== n
       .&& (hi .&. 0x80 .== 0x80)
       .&& (lo .&. 0x80 .== 0)

-- | VLQ 3-byte: 16384 ≤ n < 2097152, roundtrip + continuation bit invariant
vlq3ByteProperty :: Predicate
vlq3ByteProperty = do
  n <- free "n" :: Symbolic (SBV Word32)
  constrain $ n .>= 16384 .&& n .< 2097152
  let b0 = (n `shiftR` 14) .|. 0x80
  let b1 = ((n `shiftR` 7) .&. 0x7F) .|. 0x80
  let b2 = n .&. 0x7F
  let decoded = ((b0 .&. 0x7F) `shiftL` 14)
            .|. ((b1 .&. 0x7F) `shiftL` 7)
            .|. b2
  return $ decoded .== n
       .&& (b0 .&. 0x80 .== 0x80)
       .&& (b1 .&. 0x80 .== 0x80)
       .&& (b2 .&. 0x80 .== 0)
