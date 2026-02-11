{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Compliance fuzzer: generates valid and mutated Platform Certificates,
-- then verifies the compliance checker correctly classifies them.
--
-- Properties:
--   * Soundness: valid input → compliant certificate
--   * Mutation detection: injected violations → non-compliant or specific check failure
--   * Consistency: InputValidation acceptance ⇒ compliance acceptance
module FuzzerSpec (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Data.ASN1.Types (OID)

import Data.X509 (SignatureALG(..), HashALG(..), PubKeyALG(..), Extensions(..))
import Data.X509.Attribute (Attribute(..), Attributes(..))
import Data.X509.AttCert (Holder(..))

import Data.X509.TCG.OID
import Data.X509.TCG
  ( TBBSecurityAssertions(..)
  , ComponentConfigV2(..)
  , ExtendedTCGAttributes(..)
  , defaultExtendedTCGAttributes
  , buildExtendedTCGAttrs
  )
import Data.X509.TCG.InputValidation (validateExtendedTCGAttributes)

import Data.X509.TCG.Compliance.Check
  ( runComplianceTest
  , defaultComplianceOptions
  )
import Data.X509.TCG.Compliance.Result (ComplianceResult(..), CheckStatus(..), CheckResult(..), CategoryResult(catChecks))
import Data.X509.TCG.Compliance.Reference (defaultReferenceDB)

-- Individual check functions for May-level mutation detection
import Data.X509.TCG.Compliance.Value
  ( checkEalLevel, checkFipsLevel, checkSofRange
  , checkTpmSecVersion, checkManufacturerStr
  )

-- Cert building helpers from ComplianceCheckSpec
import ComplianceCheckSpec
  ( buildCert, mkCert, mkHolder, mkValidity, testIssuer
  , mkSanExtension, mkCertPoliciesExtension
  , mkPlatformConfigV2Attr, mkTcgPlatformSpecAttr
  , mkTcgCredentialTypeBaseAttr, mkTcgCredentialSpecAttr
  , mkTbbSecAttr, mkTbbSecAttrFull, mkTbbSecAttrWithSOF
  , defaultSan, defaultComp, CompSpec(..)
  , assertFail
  )

-- ============================================================================
-- Generators
-- ============================================================================

-- | Generate a short ByteString of printable ASCII chars (1-n bytes)
genBS :: Int -> Int -> Gen B.ByteString
genBS lo hi = do
  len <- choose (lo, hi)
  B8.pack <$> vectorOf len (choose ('A', 'Z'))

-- | Generate a valid TBBSecurityAssertions
genValidTBB :: Gen TBBSecurityAssertions
genValidTBB = do
  let ver = 0  -- v1(0), the only defined TBBSecurityAssertions version
  -- CC fields: paired (both present or both absent)
  (ccVer, eal, evalSt, plus', sof) <- oneof
    [ pure (Nothing, Nothing, Nothing, Nothing, Nothing)
    , do v <- genBS 1 10
         e <- choose (1, 7)
         s <- oneof [pure Nothing, Just <$> choose (0, 2)]
         p <- oneof [pure Nothing, Just <$> elements [True, False]]
         f <- oneof [pure Nothing, Just <$> choose (0, 2)]
         return (Just v, Just e, s, p, f)
    ]
  -- FIPS fields: paired
  (fipsVer, fipsLvl, fipsP) <- oneof
    [ pure (Nothing, Nothing, Nothing)
    , do v <- genBS 1 10
         l <- choose (1, 4)
         p <- oneof [pure Nothing, Just <$> elements [True, False]]
         return (Just v, Just l, p)
    ]
  rtm <- oneof [pure Nothing, Just <$> choose (0, 5)]
  iso <- oneof [pure Nothing, Just <$> elements [True, False]]
  return TBBSecurityAssertions
    { tbbVersion              = ver
    , tbbCCVersion            = ccVer
    , tbbEvalAssuranceLevel   = eal
    , tbbEvalStatus           = evalSt
    , tbbPlus                 = plus'
    , tbbStrengthOfFunction   = sof
    , tbbProtectionProfileOID = Nothing
    , tbbProtectionProfileURI = Nothing
    , tbbSecurityTargetOID    = Nothing
    , tbbSecurityTargetURI    = Nothing
    , tbbFIPSVersion          = fipsVer
    , tbbFIPSSecurityLevel    = fipsLvl
    , tbbFIPSPlus             = fipsP
    , tbbRTMType              = rtm
    , tbbISO9000Certified     = iso
    , tbbISO9000URI           = Nothing
    }

-- | Generate a valid ComponentConfigV2
genValidComponentV2 :: Gen ComponentConfigV2
genValidComponentV2 = do
  cls <- B.pack <$> vectorOf 4 (choose (0, 255))
  mfg <- genBS 1 50
  mdl <- genBS 1 50
  ser <- oneof [pure Nothing, Just <$> genBS 1 50]
  rev' <- oneof [pure Nothing, Just <$> genBS 1 20]
  return ComponentConfigV2
    { ccv2Class           = cls
    , ccv2Manufacturer    = mfg
    , ccv2Model           = mdl
    , ccv2Serial          = ser
    , ccv2Revision        = rev'
    , ccv2ManufacturerId  = Nothing
    , ccv2FieldReplaceable = Nothing
    , ccv2Addresses       = Nothing
    , ccv2PlatformCert    = Nothing
    , ccv2PlatformCertUri = Nothing
    , ccv2Status          = Nothing
    }

-- | Generate valid SAN attributes (4 required fields)
genValidSan :: Gen [(OID, B.ByteString)]
genValidSan = do
  mfg <- genBS 1 100
  mdl <- genBS 1 100
  ver <- genBS 1 20
  ser <- genBS 1 100
  return
    [ (tcg_paa_platformManufacturer, mfg)
    , (tcg_paa_platformModel, mdl)
    , (tcg_paa_platformVersion, ver)
    , (tcg_paa_platformSerial, ser)
    ]

-- | Generate a valid ExtendedTCGAttributes
genValidExtendedAttrs :: Gen ExtendedTCGAttributes
genValidExtendedAttrs = do
  tbb <- genValidTBB
  numComps <- choose (1, 3)
  comps <- vectorOf numComps genValidComponentV2
  return defaultExtendedTCGAttributes
    { etaSecurityAssertions   = Just tbb
    , etaComponentsV2         = Just comps
    , etaPlatformSpecVersion  = Just (2, 0, 43)
    , etaCredentialSpecVersion = Just (1, 1, 11)
    }

-- ============================================================================
-- Mutation Types
-- ============================================================================

-- | Must-level mutations that guarantee resCompliant = False
data MutationType
  = MutRTM6
  | MutClass3Bytes
  | MutClass5Bytes
  | MutBadRegistry
  | MutCertVersion0
  | MutEmptyHolder
  | MutSHA1Sig
  | MutSerial0
  | MutInvertedValidity
  deriving (Show, Eq, Enum, Bounded)

instance Arbitrary MutationType where
  arbitrary = elements [minBound .. maxBound]

-- ============================================================================
-- Certificate Builders
-- ============================================================================

-- | Standard attributes for compliant certs
standardAttrs :: [Attribute]
standardAttrs =
  [ mkPlatformConfigV2Attr [defaultComp]
  , mkTcgPlatformSpecAttr
  , mkTcgCredentialTypeBaseAttr
  , mkTcgCredentialSpecAttr
  ]

-- | Standard extensions including CertificatePolicies (for EXT-001/EXT-003)
standardExts :: [(OID, B.ByteString)] -> Extensions
standardExts san = Extensions (Just
  [ mkSanExtension san
  , mkCertPoliciesExtension False
      [1,2,840,113741,1,5,2,4]
      "http://www.example.com/cps"
      "TCG Trusted Platform Endorsement"
  ])

-- | Build a compliant cert from ExtendedTCGAttributes using the real encoding pipeline
buildCompliantCert :: ExtendedTCGAttributes -> [(OID, B.ByteString)] -> IO ComplianceResult
buildCompliantCert eta san = do
  let attrs = Attributes (buildExtendedTCGAttrs eta)
      cert = buildCert 1 100 (mkHolder (Just 1)) testIssuer
               (SignatureALG HashSHA256 PubKeyALG_RSA)
               attrs (standardExts san) (mkValidity 2024 2030) Nothing
  runComplianceTest cert defaultComplianceOptions

-- | Build a mutated cert for a given mutation type
buildMutatedCert :: MutationType -> IO ComplianceResult
buildMutatedCert mut = do
  let cert = case mut of
        MutRTM6 -> mkCert
          (Attributes (mkTbbSecAttr (Just 6) : standardAttrs))
          (standardExts defaultSan)
        MutClass3Bytes -> mkCert
          (Attributes [mkPlatformConfigV2Attr [defaultComp { csClassValue = B.pack [0,1,0] }]
                      , mkTcgPlatformSpecAttr, mkTcgCredentialTypeBaseAttr, mkTcgCredentialSpecAttr])
          (standardExts defaultSan)
        MutClass5Bytes -> mkCert
          (Attributes [mkPlatformConfigV2Attr [defaultComp { csClassValue = B.pack [0,1,0,1,0] }]
                      , mkTcgPlatformSpecAttr, mkTcgCredentialTypeBaseAttr, mkTcgCredentialSpecAttr])
          (standardExts defaultSan)
        MutBadRegistry -> mkCert
          (Attributes [mkPlatformConfigV2Attr [defaultComp { csRegistry = [1,2,3,4,5] }]
                      , mkTcgPlatformSpecAttr, mkTcgCredentialTypeBaseAttr, mkTcgCredentialSpecAttr])
          (standardExts defaultSan)
        MutCertVersion0 -> buildCert 0 100 (mkHolder (Just 1)) testIssuer
          (SignatureALG HashSHA256 PubKeyALG_RSA)
          (Attributes standardAttrs) (standardExts defaultSan) (mkValidity 2024 2030) Nothing
        MutEmptyHolder -> buildCert 1 100 (Holder Nothing Nothing Nothing) testIssuer
          (SignatureALG HashSHA256 PubKeyALG_RSA)
          (Attributes standardAttrs) (standardExts defaultSan) (mkValidity 2024 2030) Nothing
        MutSHA1Sig -> buildCert 1 100 (mkHolder (Just 1)) testIssuer
          (SignatureALG HashSHA1 PubKeyALG_RSA)
          (Attributes standardAttrs) (standardExts defaultSan) (mkValidity 2024 2030) Nothing
        MutSerial0 -> buildCert 1 0 (mkHolder (Just 1)) testIssuer
          (SignatureALG HashSHA256 PubKeyALG_RSA)
          (Attributes standardAttrs) (standardExts defaultSan) (mkValidity 2024 2030) Nothing
        MutInvertedValidity -> buildCert 1 100 (mkHolder (Just 1)) testIssuer
          (SignatureALG HashSHA256 PubKeyALG_RSA)
          (Attributes standardAttrs) (standardExts defaultSan) (mkValidity 2030 2024) Nothing
  runComplianceTest cert defaultComplianceOptions

-- ============================================================================
-- QuickCheck Properties
-- ============================================================================

propertiesGroup :: TestTree
propertiesGroup = testGroup "QuickCheck Properties"
  [ testProperty "Soundness: valid input produces compliant certificate" $
      withMaxSuccess 100 prop_soundness
  , testProperty "Mutation detection: Must-level mutations produce non-compliant certificate" $
      withMaxSuccess 100 prop_mutation_nonCompliant
  , testProperty "Consistency: InputValidation acceptance implies compliance" $
      withMaxSuccess 100 prop_consistency
  ]

-- | Show which checks failed in a ComplianceResult
showFailedChecks :: ComplianceResult -> String
showFailedChecks res =
  let allChecks = concatMap catChecks (resCategories res)
      failed = [cr | cr <- allChecks, isFail (crStatus cr)]
  in joinLines (map (\cr -> show (crId cr) ++ ": " ++ show (crStatus cr)) failed)
  where
    isFail (Fail _) = True
    isFail _ = False
    joinLines [] = "(none)"
    joinLines xs = concatMap (\x -> "\n  " ++ x) xs

-- | Valid ExtendedTCGAttributes + valid SAN → compliant certificate
prop_soundness :: Property
prop_soundness = forAll genValidExtendedAttrs $ \eta ->
  forAll genValidSan $ \san ->
    ioProperty $ do
      result <- buildCompliantCert eta san
      return $ counterexample
        ("failedRequired=" ++ show (resTotalFailedRequired result)
         ++ "\nfailedChecks:" ++ showFailedChecks result)
        (resTotalFailedRequired result === 0)

-- | Each Must-level mutation → resCompliant == False
prop_mutation_nonCompliant :: Property
prop_mutation_nonCompliant = forAll arbitrary $ \(mut :: MutationType) ->
  ioProperty $ do
    result <- buildMutatedCert mut
    return $ counterexample
      ("mutation=" ++ show mut ++ " compliant=" ++ show (resCompliant result))
      (not (resCompliant result))

-- | If validateExtendedTCGAttributes accepts, the cert is compliant
prop_consistency :: Property
prop_consistency = forAll genValidExtendedAttrs $ \eta ->
  forAll genValidSan $ \san ->
    ioProperty $ do
      let validationResult = validateExtendedTCGAttributes eta
      case validationResult of
        Left _ -> return $ property True  -- invalid input: skip (not the property under test)
        Right () -> do
          result <- buildCompliantCert eta san
          return $ counterexample
            ("validation=Right () but failedRequired=" ++ show (resTotalFailedRequired result))
            (resTotalFailedRequired result === 0)

-- ============================================================================
-- Must-Level Mutation Detection (HUnit)
-- ============================================================================

mustMutationTests :: TestTree
mustMutationTests = testGroup "Must-Level Mutation Detection"
  [ testCase "MutRTM6: RTM=6 → SEC-003 (non-compliant)" $ do
      result <- buildMutatedCert MutRTM6
      assertBool "Expected non-compliant" (not (resCompliant result))

  , testCase "MutClass3Bytes: class=3 bytes → VAL-013/REG-002 (non-compliant)" $ do
      result <- buildMutatedCert MutClass3Bytes
      assertBool "Expected non-compliant" (not (resCompliant result))

  , testCase "MutClass5Bytes: class=5 bytes → VAL-013/REG-002 (non-compliant)" $ do
      result <- buildMutatedCert MutClass5Bytes
      assertBool "Expected non-compliant" (not (resCompliant result))

  , testCase "MutBadRegistry: unknown registry OID → REG-001 (non-compliant)" $ do
      result <- buildMutatedCert MutBadRegistry
      assertBool "Expected non-compliant" (not (resCompliant result))

  , testCase "MutCertVersion0: pciVersion=0 → STR-001 (non-compliant)" $ do
      result <- buildMutatedCert MutCertVersion0
      assertBool "Expected non-compliant" (not (resCompliant result))

  , testCase "MutEmptyHolder: no baseCertificateID → STR-002 (non-compliant)" $ do
      result <- buildMutatedCert MutEmptyHolder
      assertBool "Expected non-compliant" (not (resCompliant result))

  , testCase "MutSHA1Sig: SHA1 signature → STR-004 (non-compliant)" $ do
      result <- buildMutatedCert MutSHA1Sig
      assertBool "Expected non-compliant" (not (resCompliant result))

  , testCase "MutSerial0: serial=0 → STR-005 (non-compliant)" $ do
      result <- buildMutatedCert MutSerial0
      assertBool "Expected non-compliant" (not (resCompliant result))

  , testCase "MutInvertedValidity: notBefore>notAfter → STR-006 (non-compliant)" $ do
      result <- buildMutatedCert MutInvertedValidity
      assertBool "Expected non-compliant" (not (resCompliant result))
  ]

-- ============================================================================
-- May-Level Mutation Detection (HUnit with individual check functions)
-- ============================================================================

mayMutationTests :: TestTree
mayMutationTests = testGroup "May-Level Mutation Detection"
  [ testCase "EAL=0 → VAL-010 Fail" $ do
      let cert = mkCert
            (Attributes (mkTbbSecAttrFull (Just 0) (Just (0, 1)) Nothing Nothing Nothing : standardAttrs))
            (standardExts defaultSan)
      res <- checkEalLevel cert defaultReferenceDB
      assertFail res

  , testCase "EAL=8 → VAL-010 Fail" $ do
      let cert = mkCert
            (Attributes (mkTbbSecAttrFull (Just 0) (Just (8, 1)) Nothing Nothing Nothing : standardAttrs))
            (standardExts defaultSan)
      res <- checkEalLevel cert defaultReferenceDB
      assertFail res

  , testCase "FIPS=0 → VAL-008 Fail" $ do
      let cert = mkCert
            (Attributes (mkTbbSecAttrFull (Just 0) Nothing (Just (0, Nothing)) Nothing Nothing : standardAttrs))
            (standardExts defaultSan)
      res <- checkFipsLevel cert defaultReferenceDB
      assertFail res

  , testCase "FIPS=5 → VAL-008 Fail" $ do
      let cert = mkCert
            (Attributes (mkTbbSecAttrFull (Just 0) Nothing (Just (5, Nothing)) Nothing Nothing : standardAttrs))
            (standardExts defaultSan)
      res <- checkFipsLevel cert defaultReferenceDB
      assertFail res

  , testCase "SOF=3 → VAL-017 Fail" $ do
      let cert = mkCert
            (Attributes (mkTbbSecAttrWithSOF 3 : standardAttrs))
            (standardExts defaultSan)
      res <- checkSofRange cert defaultReferenceDB
      assertFail res

  , testCase "TBBVersion=2 → VAL-007 Fail" $ do
      let cert = mkCert
            (Attributes (mkTbbSecAttrFull (Just 2) Nothing Nothing Nothing Nothing : standardAttrs))
            (standardExts defaultSan)
      res <- checkTpmSecVersion cert defaultReferenceDB
      assertFail res

  , testCase "SAN manufacturer > 255 bytes → VAL-001 Fail" $ do
      let longMfg = B.replicate 256 0x41  -- 256 bytes of 'A'
          badSan = [ (tcg_paa_platformManufacturer, longMfg)
                   , (tcg_paa_platformModel, "TestModel")
                   , (tcg_paa_platformVersion, "1.0")
                   , (tcg_paa_platformSerial, "SN001")
                   ]
          cert = mkCert (Attributes standardAttrs) (standardExts badSan)
      res <- checkManufacturerStr cert defaultReferenceDB
      assertFail res
  ]

-- ============================================================================
-- Test Tree
-- ============================================================================

tests :: TestTree
tests = testGroup "Fuzzer Tests"
  [ propertiesGroup
  , mustMutationTests
  , mayMutationTests
  ]
