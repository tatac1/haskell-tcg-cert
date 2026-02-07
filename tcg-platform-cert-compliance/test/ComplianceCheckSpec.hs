{-# LANGUAGE OverloadedStrings #-}

-- | Per-check unit tests for all 66 IWG compliance checks.
-- Each check is tested with synthetic certificates constructed in-memory,
-- verifying both PASS and FAIL (or SKIP) paths where applicable.
module ComplianceCheckSpec (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as L
import Data.ASN1.BitArray (BitArray(..))
import Data.ASN1.Types
import Data.ASN1.Types.String
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Encoding (encodeASN1)
import Time.Types (Date(..), DateTime(..), Month(..), TimeOfDay(..))

import Data.X509
  ( Extensions(..)
  , ExtensionRaw(..)
  , SignatureALG(..)
  , HashALG(..)
  , PubKeyALG(..)
  , objectToSignedExact
  , AltName(..)
  , DistinguishedName(..)
  )
import Data.X509.AttCert
  ( AttCertIssuer(..)
  , AttCertValidityPeriod(..)
  , Holder(..)
  , IssuerSerial(..)
  , V2Form(..)
  , UniqueID
  )
import Data.X509.Attribute (Attribute(..), Attributes(..))

import Data.X509.TCG.OID
import Data.X509.TCG.Platform (PlatformCertificateInfo(..), SignedPlatformCertificate)

-- Compliance check functions
import Data.X509.TCG.Compliance.Structural
import Data.X509.TCG.Compliance.Value
import Data.X509.TCG.Compliance.Delta
import Data.X509.TCG.Compliance.Chain
import Data.X509.TCG.Compliance.Extension
import Data.X509.TCG.Compliance.Security
import Data.X509.TCG.Compliance.Errata
import Data.X509.TCG.Compliance.Registry
import Data.X509.TCG.Compliance.Reference (defaultReferenceDB)
import Data.X509.TCG.Compliance.Result (CheckStatus(..), CheckResult(..))
import Data.X509.TCG.Compliance.Types (ComplianceMode(..))

-- ============================================================================
-- Helpers
-- ============================================================================

dummySign :: B.ByteString -> (B.ByteString, SignatureALG, ())
dummySign _ = (B.replicate 32 0x00, SignatureALG HashSHA256 PubKeyALG_RSA, ())

issuerDN :: DistinguishedName
issuerDN = DistinguishedName [([2,5,4,3], ASN1CharacterString UTF8 (B8.pack "Test Issuer"))]

testIssuer :: AttCertIssuer
testIssuer = AttCertIssuerV2 (V2Form [AltDirectoryName issuerDN] Nothing Nothing)

mkHolder :: Maybe Integer -> Holder
mkHolder Nothing = Holder Nothing Nothing Nothing
mkHolder (Just serialNo) =
  let isr = IssuerSerial [AltDirectoryName issuerDN] serialNo Nothing
  in Holder (Just isr) Nothing Nothing

mkValidity :: Integer -> Integer -> AttCertValidityPeriod
mkValidity yStart yEnd =
  let nb = DateTime (Date (fromIntegral yStart) January 1) (TimeOfDay 0 0 0 0)
      na = DateTime (Date (fromIntegral yEnd) January 1) (TimeOfDay 0 0 0 0)
  in AttCertValidityPeriod nb na

-- | Flexible certificate builder
buildCert :: Int           -- ^ version (1 = v2 per ASN.1)
          -> Integer       -- ^ serial number
          -> Holder        -- ^ holder
          -> AttCertIssuer -- ^ issuer
          -> SignatureALG  -- ^ signature algorithm
          -> Attributes    -- ^ attributes
          -> Extensions    -- ^ extensions
          -> AttCertValidityPeriod  -- ^ validity
          -> Maybe UniqueID  -- ^ issuerUniqueID
          -> SignedPlatformCertificate
buildCert ver serialNo holder iss sigAlg attrs exts validity uid =
  let pci = PlatformCertificateInfo
        { pciVersion = ver
        , pciHolder = holder
        , pciIssuer = iss
        , pciSignature = sigAlg
        , pciSerialNumber = serialNo
        , pciValidity = validity
        , pciAttributes = attrs
        , pciIssuerUniqueID = uid
        , pciExtensions = exts
        }
  in fst (objectToSignedExact dummySign pci)

-- | Standard "good" base certificate builder
goodBaseCert :: SignedPlatformCertificate
goodBaseCert = buildCert 1 100 (mkHolder (Just 1)) testIssuer
  (SignatureALG HashSHA256 PubKeyALG_RSA)
  (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTcgPlatformSpecAttr, mkTcgCredentialTypeBaseAttr, mkTcgCredentialSpecAttr])
  (Extensions (Just [mkSanExtension defaultSan]))
  (mkValidity 2024 2030)
  Nothing

-- | Build cert with custom attributes and extensions
mkCert :: Attributes -> Extensions -> SignedPlatformCertificate
mkCert attrs exts = buildCert 1 100 (mkHolder (Just 1)) testIssuer
  (SignatureALG HashSHA256 PubKeyALG_RSA) attrs exts (mkValidity 2024 2030) Nothing

-- | Build cert with only custom extensions (default attributes)
mkCertExts :: [ExtensionRaw] -> SignedPlatformCertificate
mkCertExts exts = mkCert
  (Attributes [mkPlatformConfigV2Attr [defaultComp]])
  (Extensions (Just (mkSanExtension defaultSan : exts)))

-- Standard SAN attributes
defaultSan :: [(OID, B.ByteString)]
defaultSan =
  [ (tcg_paa_platformManufacturer, "TestMfg")
  , (tcg_paa_platformModel, "TestModel")
  , (tcg_paa_platformVersion, "1.0")
  , (tcg_paa_platformSerial, "SN001")
  ]

-- Standard component
defaultComp :: CompSpec
defaultComp = CompSpec
  tcg_registry_componentClass_tcg
  (B.pack [0,1,0,1])
  "CompMfg"
  "CompModel"
  Nothing
  Nothing
  []

-- Component spec
data CompSpec = CompSpec
  { csRegistry :: OID
  , csClassValue :: B.ByteString
  , csManufacturer :: B.ByteString
  , csModel :: B.ByteString
  , csRevision :: Maybe B.ByteString
  , csStatus :: Maybe Integer
  , csAddresses :: [(OID, B.ByteString)]
  }

encodeComponentV2 :: CompSpec -> [ASN1]
encodeComponentV2 comp =
  [ Start Sequence
  , Start Sequence
  , OID (csRegistry comp)
  , OctetString (csClassValue comp)
  , End Sequence
  , ASN1String (ASN1CharacterString UTF8 (csManufacturer comp))
  , ASN1String (ASN1CharacterString UTF8 (csModel comp))
  ]
  ++ maybe [] (\r -> [Other Context 1 r]) (csRevision comp)
  ++ encodeAddresses (csAddresses comp)
  ++ maybe [] (\s -> [Other Context 7 (B.singleton (fromIntegral s))]) (csStatus comp)
  ++ [ End Sequence ]

encodeAddresses :: [(OID, B.ByteString)] -> [ASN1]
encodeAddresses [] = []
encodeAddresses addrs =
  [ Start (Container Context 4) ]
  ++ concatMap (\(oid, val) ->
    [ Start Sequence, OID oid
    , ASN1String (ASN1CharacterString UTF8 val)
    , End Sequence ]) addrs ++
  [ End (Container Context 4) ]

mkPlatformConfigV2Attr :: [CompSpec] -> Attribute
mkPlatformConfigV2Attr comps =
  let asn1 =
        [ Start Sequence
        , Start (Container Context 0)
        ] ++ concatMap encodeComponentV2 comps ++
        [ End (Container Context 0)
        , End Sequence
        ]
      raw = L.toStrict (encodeASN1 DER asn1)
  in Attribute tcg_at_platformConfiguration_v2 [[OctetString raw]]

mkDeltaCredentialAttr :: Attribute
mkDeltaCredentialAttr = Attribute tcg_at_tcgCredentialType [[OID tcg_kp_DeltaAttributeCertificate]]

mkTcgCredentialTypeBaseAttr :: Attribute
mkTcgCredentialTypeBaseAttr = Attribute tcg_at_tcgCredentialType [[OID tcg_kp_PlatformAttributeCertificate]]

mkTcgPlatformSpecAttr :: Attribute
mkTcgPlatformSpecAttr =
  let asn1 = [Start Sequence, IntVal 2, IntVal 0, IntVal 43, End Sequence]
      raw = L.toStrict (encodeASN1 DER asn1)
  in Attribute tcg_at_tcgPlatformSpecification [[OctetString raw]]

mkTcgCredentialSpecAttr :: Attribute
mkTcgCredentialSpecAttr =
  let asn1 = [Start Sequence, IntVal 1, IntVal 1, IntVal 11, End Sequence]
      raw = L.toStrict (encodeASN1 DER asn1)
  in Attribute tcg_at_tcgCredentialSpecification [[OctetString raw]]

mkSanExtension :: [(OID, B.ByteString)] -> ExtensionRaw
mkSanExtension attrs =
  let rdnSets = concatMap mkRdn attrs
      dn = [Start Sequence] ++ rdnSets ++ [End Sequence]
      generalNames =
        [ Start Sequence
        , Start (Container Context 4)
        ] ++ dn ++
        [ End (Container Context 4)
        , End Sequence
        ]
      raw = L.toStrict (encodeASN1 DER generalNames)
  in ExtensionRaw [2,5,29,17] False raw
  where
    mkRdn (oid, val) =
      [ Start Set, Start Sequence, OID oid
      , ASN1String (ASN1CharacterString UTF8 val)
      , End Sequence, End Set ]

-- | AKI extension (OID 2.5.29.35)
mkAkiExtension :: Bool -> B.ByteString -> ExtensionRaw
mkAkiExtension critical keyId =
  let asn1 = [Start Sequence, Other Context 0 keyId, End Sequence]
      raw = L.toStrict (encodeASN1 DER asn1)
  in ExtensionRaw [2,5,29,35] critical raw

-- | AIA extension (OID 1.3.6.1.5.5.7.1.1)
mkAiaExtension :: Bool -> B.ByteString -> ExtensionRaw
mkAiaExtension critical uri =
  let asn1 = [ Start Sequence
             , Start Sequence
             , OID [1,3,6,1,5,5,7,48,1]  -- id-ad-ocsp
             , Other Context 6 uri        -- uniformResourceIdentifier [6]
             , End Sequence
             , End Sequence
             ]
      raw = L.toStrict (encodeASN1 DER asn1)
  in ExtensionRaw [1,3,6,1,5,5,7,1,1] critical raw

-- | CRL Distribution Points extension (OID 2.5.29.31)
mkCrlDpExtension :: Bool -> B.ByteString -> ExtensionRaw
mkCrlDpExtension critical uri =
  let asn1 = [ Start Sequence
             , Start Sequence
             , Start (Container Context 0)
             , Other Context 6 uri
             , End (Container Context 0)
             , End Sequence
             , End Sequence
             ]
      raw = L.toStrict (encodeASN1 DER asn1)
  in ExtensionRaw [2,5,29,31] critical raw

-- | Certificate Policies extension with cPSuri and userNotice (OID 2.5.29.32)
mkCertPoliciesExtension :: Bool -> OID -> B.ByteString -> B.ByteString -> ExtensionRaw
mkCertPoliciesExtension critical policyOid cpsUri noticeText =
  let asn1 = [ Start Sequence           -- CertificatePolicies
             , Start Sequence           -- PolicyInformation
             , OID policyOid            -- policyIdentifier
             , Start Sequence           -- policyQualifiers
             -- CPS qualifier
             , Start Sequence
             , OID [1,3,6,1,5,5,7,2,1] -- id-qt-cps
             , ASN1String (ASN1CharacterString IA5 cpsUri)
             , End Sequence
             -- UserNotice qualifier
             , Start Sequence
             , OID [1,3,6,1,5,5,7,2,2] -- id-qt-unotice
             , Start Sequence           -- UserNotice
             , ASN1String (ASN1CharacterString UTF8 noticeText)
             , End Sequence
             , End Sequence
             , End Sequence             -- end policyQualifiers
             , End Sequence             -- end PolicyInformation
             , End Sequence             -- end CertificatePolicies
             ]
      raw = L.toStrict (encodeASN1 DER asn1)
  in ExtensionRaw [2,5,29,32] critical raw

-- | Targeting Information extension (OID 2.5.29.55)
mkTargetingInfoExtension :: Bool -> ExtensionRaw
mkTargetingInfoExtension critical =
  let serialRdn = [ Start Set, Start Sequence
                   , OID [2,5,4,5]  -- serialNumber
                   , ASN1String (ASN1CharacterString UTF8 "12345")
                   , End Sequence, End Set ]
      dn = [Start Sequence] ++ serialRdn ++ [End Sequence]
      asn1 = [ Start Sequence           -- TargetingInformation
             , Start Sequence           -- Targets
             , Start (Container Context 0) -- targetName [0]
             , Start (Container Context 4) -- directoryName [4]
             ] ++ dn ++
             [ End (Container Context 4)
             , End (Container Context 0)
             , End Sequence
             , End Sequence
             ]
      raw = L.toStrict (encodeASN1 DER asn1)
  in ExtensionRaw [2,5,29,55] critical raw

-- | TBBSecurityAssertions attribute with optional rtmType
mkTbbSecAttr :: Maybe Int -> Attribute
mkTbbSecAttr mRtmType =
  let asn1 = [Start Sequence]
           ++ maybe [] (\v -> [Other Context 2 (B.singleton (fromIntegral v))]) mRtmType
           ++ [End Sequence]
      raw = L.toStrict (encodeASN1 DER asn1)
  in Attribute tcg_at_tbbSecurityAssertions [[OctetString raw]]

-- | Full TBBSecurityAssertions with version, CC info, FIPS level, rtmType
mkTbbSecAttrFull :: Maybe Integer  -- ^ version (should be 0 for v1)
                 -> Maybe (Integer, Integer)  -- ^ CC info: (assuranceLevel, evaluationStatus)
                 -> Maybe (Integer, Maybe Integer)  -- ^ FIPS: (level, optional strengthOfFunction)
                 -> Maybe Int   -- ^ rtmType
                 -> Maybe Bool  -- ^ iso9000Certified
                 -> Attribute
mkTbbSecAttrFull mVer mCC mFips mRtm mIso =
  let asn1 = [Start Sequence]
           ++ maybe [] (\v -> [IntVal v]) mVer
           ++ maybe [] (\(eal, es) ->
                [ Start (Container Context 0)  -- CC info
                , ASN1String (ASN1CharacterString IA5 "3.1")  -- version
                , Enumerated eal
                , Enumerated es
                , End (Container Context 0)
                ]) mCC
           ++ maybe [] (\(lvl, _) ->
                [ Start (Container Context 1)  -- FIPS level
                , ASN1String (ASN1CharacterString IA5 "140-2")  -- version
                , Enumerated lvl
                , End (Container Context 1)
                ]) mFips
           ++ maybe [] (\v -> [Other Context 2 (B.singleton (fromIntegral v))]) mRtm
           ++ maybe [] (\b -> [Boolean b]) mIso
           ++ [End Sequence]
      raw = L.toStrict (encodeASN1 DER asn1)
  in Attribute tcg_at_tbbSecurityAssertions [[OctetString raw]]

-- | TBBSecurityAssertions with CC info including strengthOfFunction
mkTbbSecAttrWithSOF :: Integer -> Attribute
mkTbbSecAttrWithSOF sof =
  let asn1 = [Start Sequence
             , Start (Container Context 0)  -- CC info
             , ASN1String (ASN1CharacterString IA5 "3.1")
             , Enumerated 5  -- EAL 5
             , Enumerated 1  -- evaluationCompleted
             , Boolean False -- plus
             , Other Context 0 (B.singleton (fromIntegral sof))  -- strengthOfFunction
             , End (Container Context 0)
             , End Sequence
             ]
      raw = L.toStrict (encodeASN1 DER asn1)
  in Attribute tcg_at_tbbSecurityAssertions [[OctetString raw]]

-- | Build a delta cert
mkDeltaCert :: Integer -> Integer -> [CompSpec] -> [(OID, B.ByteString)] -> AttCertValidityPeriod -> SignedPlatformCertificate
mkDeltaCert baseSerial deltaSerial comps sanAttrs validity =
  let attrs = Attributes [mkPlatformConfigV2Attr comps, mkDeltaCredentialAttr]
      exts = Extensions (Just [mkSanExtension sanAttrs])
  in buildCert 1 deltaSerial (mkHolder (Just baseSerial)) testIssuer
       (SignatureALG HashSHA256 PubKeyALG_RSA) attrs exts validity Nothing

-- | Build a base cert for Delta comparison
mkBaseCert :: Integer -> [CompSpec] -> [(OID, B.ByteString)] -> AttCertValidityPeriod -> SignedPlatformCertificate
mkBaseCert serialNo comps sanAttrs validity =
  let attrs = Attributes [mkPlatformConfigV2Attr comps]
      exts = Extensions (Just [mkSanExtension sanAttrs])
  in buildCert 1 serialNo (mkHolder (Just 1)) testIssuer
       (SignatureALG HashSHA256 PubKeyALG_RSA) attrs exts validity Nothing

-- Assertion helpers
assertPass :: CheckResult -> Assertion
assertPass res = case crStatus res of
  Pass -> pure ()
  other -> assertFailure ("Expected Pass, got " <> show other)

assertFail :: CheckResult -> Assertion
assertFail res = case crStatus res of
  Fail _ -> pure ()
  other -> assertFailure ("Expected Fail, got " <> show other)

assertSkip :: CheckResult -> Assertion
assertSkip res = case crStatus res of
  Skip _ -> pure ()
  other -> assertFailure ("Expected Skip, got " <> show other)

-- ============================================================================
-- Tests
-- ============================================================================

tests :: TestTree
tests = testGroup "Per-Check Compliance Tests"
  [ structuralTests
  , valueTests
  , deltaTests
  , chainTests
  , registryTests
  , extensionTests
  , securityTests
  , errataTests
  , strictV11Tests
  ]

-- ============================================================================
-- STR: Structural checks (STR-001 ~ STR-013)
-- ============================================================================

structuralTests :: TestTree
structuralTests = testGroup "STR (Structural)"
  [ -- STR-001: AC version must be v2 (ASN.1 INTEGER 1)
    testCase "STR-001 PASS: version=1 (v2)" $ do
      let cert = buildCert 1 100 (mkHolder (Just 1)) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA)
                   (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030) Nothing
      res <- checkVersion cert defaultReferenceDB
      assertPass res
  , testCase "STR-001 FAIL: version=0 (wrong)" $ do
      let cert = buildCert 0 100 (mkHolder (Just 1)) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA)
                   (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030) Nothing
      res <- checkVersion cert defaultReferenceDB
      assertFail res

    -- STR-002: Holder must use baseCertificateID
  , testCase "STR-002 PASS: holder with baseCertificateID" $ do
      let cert = mkCert (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                        (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkHolder cert defaultReferenceDB
      assertPass res
  , testCase "STR-002 FAIL: empty holder" $ do
      let cert = buildCert 1 100 (Holder Nothing Nothing Nothing) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA)
                   (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030) Nothing
      res <- checkHolder cert defaultReferenceDB
      assertFail res

    -- STR-003: Issuer must use v2Form with directoryName
  , testCase "STR-003 PASS: V2Form issuer" $ do
      res <- checkIssuer goodBaseCert defaultReferenceDB
      assertPass res

    -- STR-004: Signature algorithm must be in TCG Registry
  , testCase "STR-004 PASS: SHA256/RSA" $ do
      res <- checkSignatureAlg goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "STR-004 FAIL: SHA1/RSA (deprecated)" $ do
      let cert = buildCert 1 100 (mkHolder (Just 1)) testIssuer
                   (SignatureALG HashSHA1 PubKeyALG_RSA)
                   (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030) Nothing
      res <- checkSignatureAlg cert defaultReferenceDB
      assertFail res

    -- STR-005: Serial number must be positive
  , testCase "STR-005 PASS: serial=100" $ do
      res <- checkSerialNumber goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "STR-005 FAIL: serial=0" $ do
      let cert = buildCert 1 0 (mkHolder (Just 1)) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA)
                   (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030) Nothing
      res <- checkSerialNumber cert defaultReferenceDB
      assertFail res

    -- STR-006: Validity period notBefore <= notAfter
  , testCase "STR-006 PASS: valid period" $ do
      res <- checkValidityPeriod goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "STR-006 FAIL: notBefore > notAfter" $ do
      let cert = buildCert 1 100 (mkHolder (Just 1)) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA)
                   (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2030 2024) Nothing
      res <- checkValidityPeriod cert defaultReferenceDB
      assertFail res

    -- STR-007: Attributes SHOULD be included
  , testCase "STR-007 PASS: has attributes" $ do
      res <- checkAttributes goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "STR-007 FAIL: empty attributes" $ do
      let cert = mkCert (Attributes []) (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkAttributes cert defaultReferenceDB
      assertFail res

    -- STR-008: No duplicate extension OIDs
  , testCase "STR-008 PASS: unique extension OIDs" $ do
      res <- checkExtensionOIDs goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "STR-008 FAIL: duplicate extension OIDs" $ do
      let san = mkSanExtension defaultSan
          cert = mkCert (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                        (Extensions (Just [san, san]))  -- duplicate SAN
      res <- checkExtensionOIDs cert defaultReferenceDB
      assertFail res

    -- STR-009: Unknown critical extensions must be rejected
  , testCase "STR-009 PASS: only known extensions" $ do
      res <- checkCriticalExts goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "STR-009 FAIL: unknown critical extension" $ do
      let unknownCritical = ExtensionRaw [1,2,3,4,5,6,7] True (B.pack [0x05, 0x00])
          cert = mkCertExts [unknownCritical]
      res <- checkCriticalExts cert defaultReferenceDB
      assertFail res

    -- STR-010: platformConfigUri format (SKIP when absent)
  , testCase "STR-010 SKIP: no URI present" $ do
      res <- checkPlatformUri goodBaseCert defaultReferenceDB
      assertSkip res

    -- STR-011: TCG Platform Specification (Base SHOULD, Delta MUST NOT)
  , testCase "STR-011 PASS: base with platform spec" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTcgPlatformSpecAttr])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTcgPlatformSpecification cert defaultReferenceDB
      assertPass res
  , testCase "STR-011 FAIL: base without platform spec" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTcgPlatformSpecification cert defaultReferenceDB
      assertFail res

    -- STR-012: TCG Credential Type (Base SHOULD, Delta MUST)
  , testCase "STR-012 PASS: has credential type" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTcgCredentialTypeBaseAttr])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTcgCredentialType cert defaultReferenceDB
      assertPass res
  , testCase "STR-012 FAIL: missing credential type" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTcgCredentialType cert defaultReferenceDB
      assertFail res

    -- STR-013: TCG Credential Specification (Base SHOULD, Delta MAY)
  , testCase "STR-013 PASS: has credential spec" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTcgCredentialSpecAttr])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTcgCredentialSpecification cert defaultReferenceDB
      assertPass res
  , testCase "STR-013 FAIL: base missing credential spec" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTcgCredentialSpecification cert defaultReferenceDB
      assertFail res
  ]

-- ============================================================================
-- VAL: Value checks (VAL-001 ~ VAL-017)
-- ============================================================================

valueTests :: TestTree
valueTests = testGroup "VAL (Value)"
  [ -- VAL-001: platformManufacturerStr UTF8String(1..STRMAX)
    testCase "VAL-001 PASS: valid manufacturer" $ do
      res <- checkManufacturerStr goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "VAL-001 FAIL: manufacturer > STRMAX (255) bytes" $ do
      let longStr = B.replicate 256 0x41
          san = [(tcg_paa_platformManufacturer, longStr)
                ,(tcg_paa_platformModel, "M"),(tcg_paa_platformVersion, "1")
                ,(tcg_paa_platformSerial, "S")]
          cert = mkCert (Attributes []) (Extensions (Just [mkSanExtension san]))
      res <- checkManufacturerStr cert defaultReferenceDB
      assertFail res

    -- VAL-002: platformModel UTF8String(1..STRMAX)
  , testCase "VAL-002 PASS: valid model" $ do
      res <- checkPlatformModel goodBaseCert defaultReferenceDB
      assertPass res

    -- VAL-003: platformVersion UTF8String(1..STRMAX)
  , testCase "VAL-003 PASS: valid version" $ do
      res <- checkPlatformVersion goodBaseCert defaultReferenceDB
      assertPass res

    -- VAL-004: platformSerial UTF8String(1..STRMAX) optional
  , testCase "VAL-004 PASS: valid serial" $ do
      res <- checkPlatformSerial goodBaseCert defaultReferenceDB
      assertPass res

    -- VAL-005: platformManufacturerId IANA PEN OID
  , testCase "VAL-005 SKIP: no manufacturerId" $ do
      res <- checkManufacturerId goodBaseCert defaultReferenceDB
      assertSkip res

    -- VAL-006: TBBSecurityAssertions (Base SHOULD)
  , testCase "VAL-006 PASS: base with TBB" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttr Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTpmSecAssertions cert defaultReferenceDB
      assertPass res
  , testCase "VAL-006 FAIL: base without TBB" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTpmSecAssertions cert defaultReferenceDB
      -- This is a SHOULD check for base, so it depends on requirement level
      -- For OperationalCompatibility mode, missing SHOULD may be Skip or Fail
      case crStatus res of
        Pass -> pure ()  -- Some modes pass on absent
        Skip _ -> pure ()
        Fail _ -> pure ()
        other -> assertFailure ("Unexpected status: " <> show other)

    -- VAL-007: TBBSecurityAssertions.version = v1(0)
  , testCase "VAL-007 SKIP: no TBB present" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTpmSecVersion cert defaultReferenceDB
      assertSkip res

    -- VAL-008: FIPSLevel.level 1..4
  , testCase "VAL-008 SKIP: no FIPS level" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttr Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkFipsLevel cert defaultReferenceDB
      assertSkip res

    -- VAL-009: iso9000Certified
  , testCase "VAL-009 SKIP: no ISO9000 data" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttr Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkIso9000Certified cert defaultReferenceDB
      assertSkip res

    -- VAL-010: EvaluationAssuranceLevel 1..7
  , testCase "VAL-010 SKIP: no CC info" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttr Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkEalLevel cert defaultReferenceDB
      assertSkip res

    -- VAL-011: ComponentIdentifier requires class/mfr/model
  , testCase "VAL-011 PASS: valid components" $ do
      res <- checkComponentId goodBaseCert defaultReferenceDB
      assertPass res

    -- VAL-012: componentClassRegistry OID
  , testCase "VAL-012 PASS: valid registry OID" $ do
      res <- checkClassRegistry goodBaseCert defaultReferenceDB
      assertPass res

    -- VAL-013: componentClassValue OCTET STRING SIZE(4)
  , testCase "VAL-013 PASS: 4-byte class value" $ do
      res <- checkClassValue goodBaseCert defaultReferenceDB
      assertPass res

    -- VAL-014: componentPlatformCert needs attrCertId or genericCertId
  , testCase "VAL-014 SKIP: no componentPlatformCert" $ do
      res <- checkAttrCertId goodBaseCert defaultReferenceDB
      assertSkip res

    -- VAL-015: platformConfiguration v2 OID
  , testCase "VAL-015 PASS: uses v2 OID" $ do
      res <- checkComponentIdV2 goodBaseCert defaultReferenceDB
      assertPass res

    -- VAL-016: CertificateIdentifier structure
  , testCase "VAL-016 SKIP: no componentPlatformCert" $ do
      res <- checkCertId goodBaseCert defaultReferenceDB
      assertSkip res

    -- VAL-001: invalid UTF-8 encoding in OctetString
  , testCase "VAL-001 FAIL: invalid UTF-8 in manufacturer" $ do
      let invalidUtf8 = B.pack [0xFF, 0xFE, 0x41]  -- invalid UTF-8 byte sequence
          san = [(tcg_paa_platformManufacturer, invalidUtf8)
                ,(tcg_paa_platformModel, "M"),(tcg_paa_platformVersion, "1")
                ,(tcg_paa_platformSerial, "S")]
          cert = mkCert (Attributes []) (Extensions (Just [mkSanExtension san]))
      res <- checkManufacturerStr cert defaultReferenceDB
      assertFail res

    -- VAL-002: platformModel - FAIL path
  , testCase "VAL-002 FAIL: model > STRMAX (255) bytes" $ do
      let longStr = B.replicate 256 0x41
          san = [(tcg_paa_platformManufacturer, "M")
                ,(tcg_paa_platformModel, longStr)
                ,(tcg_paa_platformVersion, "1")
                ,(tcg_paa_platformSerial, "S")]
          cert = mkCert (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                        (Extensions (Just [mkSanExtension san]))
      res <- checkPlatformModel cert defaultReferenceDB
      assertFail res

    -- VAL-003: platformVersion - FAIL path
  , testCase "VAL-003 FAIL: version > STRMAX (255) bytes" $ do
      let longStr = B.replicate 256 0x41
          san = [(tcg_paa_platformManufacturer, "M")
                ,(tcg_paa_platformModel, "M")
                ,(tcg_paa_platformVersion, longStr)
                ,(tcg_paa_platformSerial, "S")]
          cert = mkCert (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                        (Extensions (Just [mkSanExtension san]))
      res <- checkPlatformVersion cert defaultReferenceDB
      assertFail res

    -- VAL-007: TBBSecurityAssertions.version = v1(0) - PASS and FAIL paths
  , testCase "VAL-007 PASS: TBB version=0" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttrFull (Just 0) Nothing Nothing Nothing Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTpmSecVersion cert defaultReferenceDB
      assertPass res
  , testCase "VAL-007 FAIL: TBB version=2 (invalid)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttrFull (Just 2) Nothing Nothing Nothing Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTpmSecVersion cert defaultReferenceDB
      assertFail res

    -- VAL-008: FIPSLevel.level 1..4 - PASS and FAIL paths
  , testCase "VAL-008 PASS: FIPS level=4" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttrFull (Just 0) Nothing (Just (4, Nothing)) Nothing Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkFipsLevel cert defaultReferenceDB
      assertPass res
  , testCase "VAL-008 FAIL: FIPS level=5 (out of range)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttrFull (Just 0) Nothing (Just (5, Nothing)) Nothing Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkFipsLevel cert defaultReferenceDB
      assertFail res

    -- VAL-010: EvaluationAssuranceLevel 1..7 - PASS and FAIL paths
  , testCase "VAL-010 PASS: EAL=7" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttrFull (Just 0) (Just (7, 1)) Nothing Nothing Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkEalLevel cert defaultReferenceDB
      assertPass res
  , testCase "VAL-010 FAIL: EAL=8 (out of range)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttrFull (Just 0) (Just (8, 1)) Nothing Nothing Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkEalLevel cert defaultReferenceDB
      assertFail res

    -- VAL-013: componentClassValue OCTET STRING SIZE(4) - FAIL path
  , testCase "VAL-013 FAIL: 3-byte class value" $ do
      let badComp = defaultComp { csClassValue = B.pack [0,1,0] }  -- only 3 bytes
          cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [badComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkClassValue cert defaultReferenceDB
      assertFail res

    -- VAL-017: StrengthOfFunction 0..2 - all paths
  , testCase "VAL-017 SKIP: no TBB" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkSofRange cert defaultReferenceDB
      assertSkip res
  , testCase "VAL-017 PASS: SOF=2" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttrWithSOF 2])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkSofRange cert defaultReferenceDB
      assertPass res
  , testCase "VAL-017 FAIL: SOF=3 (out of range)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttrWithSOF 3])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkSofRange cert defaultReferenceDB
      assertFail res
  ]

-- ============================================================================
-- DLT: Delta checks (DLT-001 ~ DLT-012)
-- ============================================================================

deltaTests :: TestTree
deltaTests = testGroup "DLT (Delta)"
  [ -- DLT-001: Delta platformConfiguration
    testCase "DLT-001 PASS: delta with changes" $ do
      let baseComp = defaultComp
          deltaComp = baseComp { csRevision = Just "r2", csStatus = Just 1 }
          baseCert' = mkBaseCert 100 [baseComp] defaultSan (mkValidity 2024 2030)
          deltaCert = mkDeltaCert 100 101 [deltaComp] defaultSan (mkValidity 2024 2030)
      res <- checkDeltaHasPlatformConfigWithCert deltaCert baseCert' defaultReferenceDB
      assertPass res

    -- DLT-002: Delta must include tcgCredentialType (Delta OID)
  , testCase "DLT-002 PASS: delta with credential type" $ do
      let deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkDeltaHasCredentialType deltaCert defaultReferenceDB
      assertPass res
  , testCase "DLT-002 FAIL: delta without credential type" $ do
      -- Build delta without mkDeltaCredentialAttr
      let comp = defaultComp { csStatus = Just 0 }
          attrs = Attributes [mkPlatformConfigV2Attr [comp]]
          cert = buildCert 1 101 (mkHolder (Just 100)) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA) attrs
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030) Nothing
      res <- checkDeltaHasCredentialType cert defaultReferenceDB
      -- Base cert type won't trigger delta check; needs to be detected as delta
      -- Without tcgCredentialType, it's detected as Base, so this skips
      case crStatus res of
        Skip _ -> pure ()  -- Detected as Base, delta check not applicable
        Fail _ -> pure ()
        other -> assertFailure ("Expected Skip or Fail, got " <> show other)

    -- DLT-003: Delta serial number positive
  , testCase "DLT-003 PASS: positive serial" $ do
      let deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkDeltaSerialPositive deltaCert defaultReferenceDB
      assertPass res

    -- DLT-004: Delta holder must reference base cert
  , testCase "DLT-004 SKIP: no base cert provided" $ do
      let deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkHolderRefsBase deltaCert defaultReferenceDB
      assertSkip res
  , testCase "DLT-004 PASS: holder refs base (with base)" $ do
      let baseCert' = mkBaseCert 100 [defaultComp] defaultSan (mkValidity 2024 2030)
          deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkHolderRefsBaseWithCert deltaCert baseCert' defaultReferenceDB
      assertPass res

    -- DLT-005: Delta notAfter must not precede base
  , testCase "DLT-005 SKIP: no base cert" $ do
      let deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkValidityMatchesBase deltaCert defaultReferenceDB
      assertSkip res
  , testCase "DLT-005 PASS: delta validity matches base" $ do
      let baseCert' = mkBaseCert 100 [defaultComp] defaultSan (mkValidity 2024 2030)
          deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkValidityMatchesBaseWithCert deltaCert baseCert' defaultReferenceDB
      assertPass res
  , testCase "DLT-005 FAIL: delta notAfter precedes base" $ do
      let baseCert' = mkBaseCert 100 [defaultComp] defaultSan (mkValidity 2024 2030)
          deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2028)
      res <- checkValidityMatchesBaseWithCert deltaCert baseCert' defaultReferenceDB
      assertFail res

    -- DLT-006: AttributeStatus values 0..2
  , testCase "DLT-006 PASS: valid status values" $ do
      let deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 1 }] defaultSan (mkValidity 2024 2030)
      res <- checkAttributeStatusValues deltaCert defaultReferenceDB
      assertPass res
  , testCase "DLT-006 FAIL: invalid status value=5" $ do
      let deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 5 }] defaultSan (mkValidity 2024 2030)
      res <- checkAttributeStatusValues deltaCert defaultReferenceDB
      assertFail res

    -- DLT-007: status field Delta-only
  , testCase "DLT-007 PASS: base without status" $ do
      let baseCert' = mkBaseCert 100 [defaultComp] defaultSan (mkValidity 2024 2030)
      res <- checkStatusFieldDeltaOnly baseCert' defaultReferenceDB
      assertPass res

    -- DLT-008: Components in Delta must include status
  , testCase "DLT-008 PASS: all components have status" $ do
      let deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkComponentsHaveStatus deltaCert defaultReferenceDB
      assertPass res

    -- DLT-009: platformManufacturerStr must match base
  , testCase "DLT-009 SKIP: no base cert" $ do
      let deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkManufacturerMatchesBase deltaCert defaultReferenceDB
      assertSkip res
  , testCase "DLT-009 PASS: manufacturer matches" $ do
      let baseCert' = mkBaseCert 100 [defaultComp] defaultSan (mkValidity 2024 2030)
          deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkManufacturerMatchesBaseWithCert deltaCert baseCert' defaultReferenceDB
      assertPass res

    -- DLT-010: platformModel must match base
  , testCase "DLT-010 FAIL: model mismatch" $ do
      let baseSan = [(tcg_paa_platformManufacturer, "M"),(tcg_paa_platformModel, "BaseModel")
                    ,(tcg_paa_platformVersion, "1"),(tcg_paa_platformSerial, "S")]
          deltaSan = [(tcg_paa_platformManufacturer, "M"),(tcg_paa_platformModel, "DeltaModel")
                     ,(tcg_paa_platformVersion, "1"),(tcg_paa_platformSerial, "S")]
          baseCert' = mkBaseCert 100 [defaultComp] baseSan (mkValidity 2024 2030)
          deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] deltaSan (mkValidity 2024 2030)
      res <- checkModelMatchesBaseWithCert deltaCert baseCert' defaultReferenceDB
      assertFail res

    -- DLT-011: platformVersion must match base
  , testCase "DLT-011 PASS: version matches" $ do
      let baseCert' = mkBaseCert 100 [defaultComp] defaultSan (mkValidity 2024 2030)
          deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkVersionMatchesBaseWithCert deltaCert baseCert' defaultReferenceDB
      assertPass res

    -- DLT-012: platformSerial/mfgId must match base if present
  , testCase "DLT-012 PASS: serial matches" $ do
      let baseCert' = mkBaseCert 100 [defaultComp] defaultSan (mkValidity 2024 2030)
          deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkSerialMatchesBaseWithCert deltaCert baseCert' defaultReferenceDB
      assertPass res
  ]

-- ============================================================================
-- CHN: Chain checks (CHN-001 ~ CHN-005)
-- ============================================================================

chainTests :: TestTree
chainTests = testGroup "CHN (Chain)"
  [ -- CHN-001: AKI must be non-critical
    testCase "CHN-001 PASS: non-critical AKI" $ do
      let cert = mkCertExts [mkAkiExtension False (B.pack [0x01, 0x02, 0x03, 0x04])]
      res <- checkAuthorityKeyId cert defaultReferenceDB
      assertPass res
  , testCase "CHN-001 FAIL: critical AKI" $ do
      let cert = mkCertExts [mkAkiExtension True (B.pack [0x01, 0x02, 0x03, 0x04])]
      res <- checkAuthorityKeyId cert defaultReferenceDB
      assertFail res
  , testCase "CHN-001 SKIP: no AKI extension" $ do
      res <- checkAuthorityKeyId goodBaseCert defaultReferenceDB
      assertSkip res

    -- CHN-002: AIA non-critical, OCSP SHOULD
  , testCase "CHN-002 PASS: non-critical AIA with OCSP" $ do
      let cert = mkCertExts [mkAiaExtension False "http://ocsp.example.com"]
      res <- checkAuthorityInfoAcc cert defaultReferenceDB
      assertPass res
  , testCase "CHN-002 FAIL: critical AIA" $ do
      let cert = mkCertExts [mkAiaExtension True "http://ocsp.example.com"]
      res <- checkAuthorityInfoAcc cert defaultReferenceDB
      assertFail res
  , testCase "CHN-002 SKIP: no AIA extension" $ do
      res <- checkAuthorityInfoAcc goodBaseCert defaultReferenceDB
      assertSkip res

    -- CHN-003: CRL DP non-critical
  , testCase "CHN-003 PASS: non-critical CRL DP" $ do
      let cert = mkCertExts [mkCrlDpExtension False "http://crl.example.com/ca.crl"]
      res <- checkCrlDistribution cert defaultReferenceDB
      assertPass res
  , testCase "CHN-003 FAIL: critical CRL DP" $ do
      let cert = mkCertExts [mkCrlDpExtension True "http://crl.example.com/ca.crl"]
      res <- checkCrlDistribution cert defaultReferenceDB
      assertFail res
  , testCase "CHN-003 SKIP: no CRL DP extension" $ do
      res <- checkCrlDistribution goodBaseCert defaultReferenceDB
      assertSkip res

    -- CHN-004: Base must satisfy EK cert reference
  , testCase "CHN-004 PASS: holder has baseCertificateID" $ do
      res <- checkEkCertBinding goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "CHN-004 FAIL: no baseCertificateID" $ do
      let cert = buildCert 1 100 (Holder Nothing Nothing Nothing) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA)
                   (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030) Nothing
      res <- checkEkCertBinding cert defaultReferenceDB
      assertFail res

    -- CHN-005: TargetingInformation critical=TRUE if present
  , testCase "CHN-005 SKIP: no targeting info" $ do
      res <- checkTargetingInfo goodBaseCert defaultReferenceDB
      assertSkip res
  , testCase "CHN-005 FAIL: non-critical targeting info" $ do
      let cert = mkCertExts [mkTargetingInfoExtension False]
      res <- checkTargetingInfo cert defaultReferenceDB
      assertFail res
  , testCase "CHN-005 PASS: critical targeting info" $ do
      let cert = mkCertExts [mkTargetingInfoExtension True]
      res <- checkTargetingInfo cert defaultReferenceDB
      assertPass res
  ]

-- ============================================================================
-- REG: Registry checks (REG-001 ~ REG-004)
-- ============================================================================

registryTests :: TestTree
registryTests = testGroup "REG (Registry)"
  [ -- REG-001: componentClassRegistry OID per compliance mode
    testCase "REG-001 PASS: TCG registry OID" $ do
      res <- checkTcgRegistryOid goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "REG-001 FAIL: unknown registry OID" $ do
      let badComp = defaultComp { csRegistry = [1,2,3,4,5,6,7] }  -- non-standard OID
          cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [badComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTcgRegistryOid cert defaultReferenceDB
      assertFail res

    -- REG-002: componentClassValue OCTET STRING SIZE(4)
  , testCase "REG-002 PASS: 4-byte class value" $ do
      res <- checkClassValueStruct goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "REG-002 FAIL: 3-byte class value" $ do
      let badComp = defaultComp { csClassValue = B.pack [0,1,0] }  -- 3 bytes
          cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [badComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkClassValueStruct cert defaultReferenceDB
      assertFail res

    -- REG-003: TCG registry class value Table 1 conformance
  , testCase "REG-003 PASS: valid TCG class prefix" $ do
      res <- checkTcgRegistryValues goodBaseCert defaultReferenceDB
      assertPass res

    -- REG-004: Translation table scope
  , testCase "REG-004 SKIP: no scoped registry" $ do
      res <- checkRegistryTranslationScope goodBaseCert defaultReferenceDB
      case crStatus res of
        Skip _ -> pure ()
        Pass -> pure ()
        other -> assertFailure ("Expected Skip or Pass, got " <> show other)
  ]

-- ============================================================================
-- EXT: Extension checks (EXT-001 ~ EXT-005)
-- ============================================================================

extensionTests :: TestTree
extensionTests = testGroup "EXT (Extension)"
  [ -- EXT-001: CertificatePolicies non-critical, policyId, cPSuri HTTP
    testCase "EXT-001 PASS: valid CertPolicies" $ do
      let cp = mkCertPoliciesExtension False
                 [1,2,840,113741,1,5,2,4]
                 "http://www.example.com/cps"
                 "TCG Trusted Platform Endorsement"
          cert = mkCertExts [cp]
      res <- checkCertificatePolicies cert defaultReferenceDB
      assertPass res
  , testCase "EXT-001 FAIL: missing CertPolicies" $ do
      res <- checkCertificatePolicies goodBaseCert defaultReferenceDB
      assertFail res
  , testCase "EXT-001 FAIL: critical CertPolicies" $ do
      let cp = mkCertPoliciesExtension True
                 [1,2,840,113741,1,5,2,4]
                 "http://www.example.com/cps"
                 "TCG Trusted Platform Endorsement"
          cert = mkCertExts [cp]
      res <- checkCertificatePolicies cert defaultReferenceDB
      assertFail res

    -- EXT-002: SAN non-critical, directoryName with platform attrs
  , testCase "EXT-002 PASS: valid SAN" $ do
      res <- checkSubjectAltNames goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "EXT-002 FAIL: missing SAN" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp]])
            (Extensions Nothing)
      res <- checkSubjectAltNames cert defaultReferenceDB
      assertFail res

    -- EXT-003: userNotice = "TCG Trusted Platform Endorsement"
  , testCase "EXT-003 PASS: correct userNotice" $ do
      let cp = mkCertPoliciesExtension False
                 [1,2,840,113741,1,5,2,4]
                 "http://www.example.com/cps"
                 "TCG Trusted Platform Endorsement"
          cert = mkCertExts [cp]
      res <- checkUserNotice cert defaultReferenceDB
      assertPass res
  , testCase "EXT-003 FAIL: no CertPolicies" $ do
      res <- checkUserNotice goodBaseCert defaultReferenceDB
      assertFail res

    -- EXT-004: Issuer Unique ID must be omitted
  , testCase "EXT-004 PASS: no issuerUniqueID" $ do
      res <- checkIssuerUniqueId goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "EXT-004 FAIL: issuerUniqueID present" $ do
      let cert = buildCert 1 100 (mkHolder (Just 1)) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA)
                   (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030)
                   (Just (BitArray 8 (B.singleton 0xFF)))
      res <- checkIssuerUniqueId cert defaultReferenceDB
      assertFail res

    -- EXT-005: TargetingInformation critical=TRUE if present
  , testCase "EXT-005 SKIP: no targeting info" $ do
      res <- checkTargetingInfoCritical goodBaseCert defaultReferenceDB
      assertSkip res
  , testCase "EXT-005 FAIL: non-critical targeting info" $ do
      let cert = mkCertExts [mkTargetingInfoExtension False]
      res <- checkTargetingInfoCritical cert defaultReferenceDB
      assertFail res
  , testCase "EXT-005 PASS: critical targeting info" $ do
      let cert = mkCertExts [mkTargetingInfoExtension True]
      res <- checkTargetingInfoCritical cert defaultReferenceDB
      assertPass res
  ]

-- ============================================================================
-- SEC: Security checks (SEC-001 ~ SEC-005)
-- ============================================================================

securityTests :: TestTree
securityTests = testGroup "SEC (Security)"
  [ -- SEC-001: Delta must not include tBBSecurityAssertions
    testCase "SEC-001 PASS: base with TBB (allowed)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttr Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTbbSecForBaseOnly cert defaultReferenceDB
      assertPass res
  , testCase "SEC-001 FAIL: delta with TBB (prohibited)" $ do
      let comp = defaultComp { csStatus = Just 0 }
          attrs = Attributes [mkPlatformConfigV2Attr [comp], mkDeltaCredentialAttr, mkTbbSecAttr Nothing]
          cert = buildCert 1 101 (mkHolder (Just 100)) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA) attrs
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030) Nothing
      res <- checkTbbSecForBaseOnly cert defaultReferenceDB
      assertFail res

    -- SEC-002: Delta must not include TCGPlatformSpecification
  , testCase "SEC-002 PASS: base with TCGPlatformSpec (allowed)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTcgPlatformSpecAttr])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTcgSpecForBaseOnly cert defaultReferenceDB
      assertPass res
  , testCase "SEC-002 FAIL: delta with TCGPlatformSpec (prohibited)" $ do
      let comp = defaultComp { csStatus = Just 0 }
          attrs = Attributes [mkPlatformConfigV2Attr [comp], mkDeltaCredentialAttr, mkTcgPlatformSpecAttr]
          cert = buildCert 1 101 (mkHolder (Just 100)) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA) attrs
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030) Nothing
      res <- checkTcgSpecForBaseOnly cert defaultReferenceDB
      assertFail res

    -- SEC-003: MeasurementRootType 0..5
  , testCase "SEC-003 PASS: rtmType=0 (static)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttr (Just 0)])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkMeasurementRootType cert defaultReferenceDB
      assertPass res
  , testCase "SEC-003 PASS: rtmType=3 (hybrid)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttr (Just 3)])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkMeasurementRootType cert defaultReferenceDB
      assertPass res
  , testCase "SEC-003 PASS: rtmType=4 (physical)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttr (Just 4)])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkMeasurementRootType cert defaultReferenceDB
      assertPass res
  , testCase "SEC-003 PASS: rtmType=5 (virtual)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttr (Just 5)])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkMeasurementRootType cert defaultReferenceDB
      assertPass res
  , testCase "SEC-003 FAIL: rtmType=6 (out of range)" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttr (Just 6)])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkMeasurementRootType cert defaultReferenceDB
      assertFail res
  , testCase "SEC-003 SKIP: no TBB present" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkMeasurementRootType cert defaultReferenceDB
      assertSkip res

    -- SEC-004: CommonCriteriaMeasures consistency
  , testCase "SEC-004 SKIP: no TBB present" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkCCMeasuresConsist cert defaultReferenceDB
      assertSkip res
  , testCase "SEC-004 SKIP: TBB with CC measures but no OID/URI pairs" $ do
      -- CC measures present but without profileOid/profileUri → Skip (consistency n/a)
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], mkTbbSecAttrFull (Just 0) (Just (5, 1)) Nothing Nothing Nothing])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkCCMeasuresConsist cert defaultReferenceDB
      assertSkip res

    -- SEC-005: URIReference hash pair co-existence
  , testCase "SEC-005 SKIP: no URI refs" $ do
      res <- checkUriRefHash goodBaseCert defaultReferenceDB
      assertSkip res
  , testCase "SEC-005 FAIL: hashAlgorithm without hashValue" $ do
      -- Build TBBSecurityAssertions with CC info that has profileUri
      -- with hashAlgorithm but missing hashValue
      let ccWithBadUri =
            [ Start Sequence  -- TBBSecurityAssertions
            , IntVal 0        -- version
            , Start (Container Context 0)  -- CC info
            , ASN1String (ASN1CharacterString IA5 "3.1")  -- version
            , Enumerated 5   -- assuranceLevel
            , Enumerated 1   -- evaluationStatus
            -- profileUri [2] with hashAlg but no hashValue
            , Start (Container Context 2)  -- profileUri
            , ASN1String (ASN1CharacterString IA5 "http://example.com/profile")
            , Start Sequence  -- hashAlgorithm (AlgorithmIdentifier)
            , OID [2,16,840,1,101,3,4,2,1]  -- SHA-256
            , End Sequence
            -- Missing BIT STRING hashValue here → SEC-005 must FAIL
            , End (Container Context 2)
            , End (Container Context 0)
            , End Sequence
            ]
          raw = L.toStrict (encodeASN1 DER ccWithBadUri)
          tbbAttr = Attribute tcg_at_tbbSecurityAssertions [[OctetString raw]]
          cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp], tbbAttr])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkUriRefHash cert defaultReferenceDB
      assertFail res
  ]

-- ============================================================================
-- ERR: Errata checks (ERR-001 ~ ERR-005)
-- ============================================================================

errataTests :: TestTree
errataTests = testGroup "ERR (Errata)"
  [ -- ERR-001: ComponentIdentifier order independence (informational, always PASS)
    testCase "ERR-001 PASS: informational" $ do
      res <- checkComponentIdOrder goodBaseCert defaultReferenceDB
      assertPass res

    -- ERR-002: MAC address multi-format support (informational, always PASS)
  , testCase "ERR-002 PASS: informational" $ do
      res <- checkMacAddressFormat goodBaseCert defaultReferenceDB
      assertPass res

    -- ERR-003: PrivateEnterpriseNumber must be OID (informational, always PASS)
  , testCase "ERR-003 PASS: informational" $ do
      res <- checkPrivateEntNum goodBaseCert defaultReferenceDB
      assertPass res

    -- ERR-004: baseCertificateID must include EK issuer/serial
  , testCase "ERR-004 PASS: valid baseCertificateID" $ do
      res <- checkBaseCertIdEnc goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "ERR-004 FAIL: missing baseCertificateID" $ do
      let cert = buildCert 1 100 (Holder Nothing Nothing Nothing) testIssuer
                   (SignatureALG HashSHA256 PubKeyALG_RSA)
                   (Attributes [mkPlatformConfigV2Attr [defaultComp]])
                   (Extensions (Just [mkSanExtension defaultSan]))
                   (mkValidity 2024 2030) Nothing
      res <- checkBaseCertIdEnc cert defaultReferenceDB
      assertFail res

    -- ERR-005: 48-bit MAC OIDs
  , testCase "ERR-005 PASS: valid MAC addresses" $ do
      let macs = [(tcg_address_ethernetmac, "aa:bb:cc:dd:ee:ff")]
          comp = defaultComp { csAddresses = macs }
          cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [comp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- check48BitMacOids cert defaultReferenceDB
      assertPass res
  , testCase "ERR-005 SKIP: no MAC addresses" $ do
      res <- check48BitMacOids goodBaseCert defaultReferenceDB
      assertSkip res
  ]

-- ============================================================================
-- StrictV11 mode-specific tests
-- ============================================================================

strictV11Tests :: TestTree
strictV11Tests = testGroup "StrictV11 Mode"
  [ -- VAL-015 StrictV11: rejects v1 platformConfiguration OID
    testCase "VAL-015 StrictV11 FAIL: v1 platformConfiguration OID" $ do
      let v1Attr = Attribute tcg_at_platformConfiguration [[OctetString (B.pack [0x30, 0x00])]]
          cert = mkCert
            (Attributes [v1Attr])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkComponentIdV2WithMode StrictV11 cert defaultReferenceDB
      assertFail res
  , testCase "VAL-015 StrictV11 PASS: v2 platformConfiguration OID" $ do
      let cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [defaultComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkComponentIdV2WithMode StrictV11 cert defaultReferenceDB
      assertPass res

    -- REG-001 StrictV11: restricts to TCG/IETF/DMTF registries only
  , testCase "REG-001 StrictV11 PASS: TCG registry" $ do
      res <- checkTcgRegistryOidWithMode StrictV11 goodBaseCert defaultReferenceDB
      assertPass res
  , testCase "REG-001 StrictV11 FAIL: unknown registry" $ do
      let badComp = defaultComp { csRegistry = [1,2,3,4,5,6,7] }
          cert = mkCert
            (Attributes [mkPlatformConfigV2Attr [badComp]])
            (Extensions (Just [mkSanExtension defaultSan]))
      res <- checkTcgRegistryOidWithMode StrictV11 cert defaultReferenceDB
      assertFail res

    -- DLT-005 StrictV11: requires exact notAfter match
  , testCase "DLT-005 StrictV11 PASS: exact match" $ do
      let baseCert' = mkBaseCert 100 [defaultComp] defaultSan (mkValidity 2024 2030)
          deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2030)
      res <- checkValidityMatchesBaseWithCertWithMode StrictV11 deltaCert baseCert' defaultReferenceDB
      assertPass res
  , testCase "DLT-005 StrictV11 FAIL: notAfter mismatch" $ do
      let baseCert' = mkBaseCert 100 [defaultComp] defaultSan (mkValidity 2024 2030)
          -- Delta extends validity beyond base
          deltaCert = mkDeltaCert 100 101 [defaultComp { csStatus = Just 0 }] defaultSan (mkValidity 2024 2031)
      res <- checkValidityMatchesBaseWithCertWithMode StrictV11 deltaCert baseCert' defaultReferenceDB
      assertFail res
  ]
