{-# LANGUAGE OverloadedStrings #-}

module ConfigLintTests (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import Data.X509.TCG.Util.ConfigLint
import Data.X509.TCG.Util.Config
    ( PlatformCertConfig(..)
    , ComponentConfig(..)
    , SecurityAssertionsConfig(..)
    , URIReferenceConfig(..)
    , ComponentClassConfig(..)
    )
import Data.X509.TCG.Compliance.Types (CheckId(..), CheckCategory(..), RequirementLevel(..))

-- | Minimal valid Base config for testing
validBaseConfig :: PlatformCertConfig
validBaseConfig = PlatformCertConfig
  { pccManufacturer = "Test Corp"
  , pccModel = "Test Model"
  , pccVersion = "1.0"
  , pccSerial = "S001"
  , pccManufacturerId = Nothing
  , pccValidityDays = Just 365
  , pccKeySize = Just 2048
  , pccComponents = []
  , pccProperties = Nothing
  , pccPlatformConfigUri = Nothing
  , pccComponentsUri = Nothing
  , pccPropertiesUri = Nothing
  , pccPlatformClass = Nothing
  , pccSpecificationVersion = Nothing
  , pccMajorVersion = Nothing
  , pccMinorVersion = Nothing
  , pccPatchVersion = Nothing
  , pccPlatformQualifier = Nothing
  , pccCredentialSpecMajor = Just 1
  , pccCredentialSpecMinor = Just 1
  , pccCredentialSpecRevision = Just 13
  , pccPlatformSpecMajor = Just 2
  , pccPlatformSpecMinor = Just 0
  , pccPlatformSpecRevision = Just 164
  , pccSecurityAssertions = Nothing
  }

tests :: TestTree
tests = testGroup "ConfigLint"
  [ testGroup "lintPlatformConfig"
    [ testCase "valid config produces no failures" $ do
        let results = lintPlatformConfig validBaseConfig
            failures = filter (\r -> clrStatus r == LintFail) results
        assertEqual "no failures" 0 (length failures)

    , testCase "empty manufacturer fails VAL-001" $ do
        let config = validBaseConfig { pccManufacturer = "" }
            results = lintPlatformConfig config
            val001Fails = filter (isFailForCheck (PreflightCheck (CheckId Value 1))) results
        assertBool "VAL-001 fails" (not (null val001Fails))

    , testCase "empty model fails VAL-002" $ do
        let config = validBaseConfig { pccModel = "" }
            results = lintPlatformConfig config
            val002Fails = filter (isFailForCheck (PreflightCheck (CheckId Value 2))) results
        assertBool "VAL-002 fails" (not (null val002Fails))

    , testCase "empty version fails VAL-003" $ do
        let config = validBaseConfig { pccVersion = "" }
            results = lintPlatformConfig config
            val003Fails = filter (isFailForCheck (PreflightCheck (CheckId Value 3))) results
        assertBool "VAL-003 fails" (not (null val003Fails))

    , testCase "string exceeding STRMAX warns" $ do
        let longStr = replicate 300 'A'
            config = validBaseConfig { pccManufacturer = longStr }
            results = lintPlatformConfig config
            warns = filter (\r -> clrStatus r == LintWarn
                              && clrCheckId r == ConfigOnly "G-004") results
        assertBool "warns for long string" (not (null warns))

    , testCase "FIPS level out of range fails VAL-008" $ do
        let sa = defaultSecAssertions { sacFIPSSecurityLevel = Just 5 }
            config = validBaseConfig { pccSecurityAssertions = Just sa }
            results = lintPlatformConfig config
            val008Fails = filter (isFailForCheck (PreflightCheck (CheckId Value 8))) results
        assertBool "VAL-008 fails" (not (null val008Fails))

    , testCase "FIPS level in range passes VAL-008" $ do
        let sa = defaultSecAssertions { sacFIPSSecurityLevel = Just 3 }
            config = validBaseConfig { pccSecurityAssertions = Just sa }
            results = lintPlatformConfig config
            val008Fails = filter (isFailForCheck (PreflightCheck (CheckId Value 8))) results
        assertEqual "no VAL-008 failures" 0 (length val008Fails)

    , testCase "EAL out of range fails VAL-010" $ do
        let sa = defaultSecAssertions { sacEvalAssuranceLevel = Just 8 }
            config = validBaseConfig { pccSecurityAssertions = Just sa }
            results = lintPlatformConfig config
            val010Fails = filter (isFailForCheck (PreflightCheck (CheckId Value 10))) results
        assertBool "VAL-010 fails" (not (null val010Fails))

    , testCase "URI hash pair mismatch fails SEC-005" $ do
        let uri = URIReferenceConfig
              { uriUri = "https://example.com/config"
              , uriHashAlgorithm = Just "sha256"
              , uriHashValue = Nothing  -- missing hashValue
              }
            config = validBaseConfig { pccPlatformConfigUri = Just uri }
            results = lintPlatformConfig config
            sec005Fails = filter (isFailForCheck (PreflightCheck (CheckId Security 5))) results
        assertBool "SEC-005 fails" (not (null sec005Fails))

    , testCase "URI hash pair both present passes" $ do
        let uri = URIReferenceConfig
              { uriUri = "https://example.com/config"
              , uriHashAlgorithm = Just "sha256"
              , uriHashValue = Just "abcdef123456"
              }
            config = validBaseConfig { pccPlatformConfigUri = Just uri }
            results = lintPlatformConfig config
            sec005Fails = filter (isFailForCheck (PreflightCheck (CheckId Security 5))) results
        assertEqual "no SEC-005 failures" 0 (length sec005Fails)

    , testCase "duplicate component serials warns CFG-001" $ do
        let comp1 = testComponent { ccSerial = Just "SAME-SERIAL" }
            comp2 = testComponent { ccSerial = Just "SAME-SERIAL", ccModel = "Other" }
            config = validBaseConfig { pccComponents = [comp1, comp2] }
            results = lintPlatformConfig config
            cfg001Warns = filter (isWarnForCheck (ConfigOnly "CFG-001")) results
        assertBool "CFG-001 warns" (not (null cfg001Warns))

    , testCase "unique component serials pass CFG-001" $ do
        let comp1 = testComponent { ccSerial = Just "SERIAL-1" }
            comp2 = testComponent { ccSerial = Just "SERIAL-2", ccModel = "Other" }
            config = validBaseConfig { pccComponents = [comp1, comp2] }
            results = lintPlatformConfig config
            cfg001Warns = filter (isWarnForCheck (ConfigOnly "CFG-001")) results
        assertEqual "no CFG-001 warnings" 0 (length cfg001Warns)

    , testCase "empty component manufacturer fails VAL-011" $ do
        let comp = testComponent { ccManufacturer = "" }
            config = validBaseConfig { pccComponents = [comp] }
            results = lintPlatformConfig config
            val011Fails = filter (isFailForCheck (PreflightCheck (CheckId Value 11))) results
        assertBool "VAL-011 fails" (not (null val011Fails))

    , testCase "invalid hex class value fails VAL-013" $ do
        let comp = testComponent { ccClass = "ZZZZZZZZ" }
            config = validBaseConfig { pccComponents = [comp] }
            results = lintPlatformConfig config
            val013Fails = filter (isFailForCheck (PreflightCheck (CheckId Value 13))) results
        assertBool "VAL-013 fails" (not (null val013Fails))

    , testCase "all failures have suggestions" $ do
        let config = validBaseConfig { pccManufacturer = "" }
            results = lintPlatformConfig config
            failsWithoutSuggestion = filter
              (\r -> clrStatus r == LintFail && clrSuggestion r == Nothing) results
        assertEqual "all failures have suggestions" 0 (length failsWithoutSuggestion)

    , testCase "missing credential spec warns STR-013" $ do
        let config = validBaseConfig
              { pccCredentialSpecMajor = Nothing
              , pccCredentialSpecMinor = Nothing
              }
            results = lintPlatformConfig config
            str013Warns = filter (isWarnForCheck (PreflightCheck (CheckId Structural 13))) results
        assertBool "STR-013 warns" (not (null str013Warns))

    , testCase "invalid strengthOfFunction fails VAL-017" $ do
        let sa = defaultSecAssertions { sacStrengthOfFunction = Just "invalid" }
            config = validBaseConfig { pccSecurityAssertions = Just sa }
            results = lintPlatformConfig config
            val017Fails = filter (isFailForCheck (PreflightCheck (CheckId Value 17))) results
        assertBool "VAL-017 fails" (not (null val017Fails))

    , testCase "invalid rtmType fails SEC-003" $ do
        let sa = defaultSecAssertions { sacRTMType = Just "unknown" }
            config = validBaseConfig { pccSecurityAssertions = Just sa }
            results = lintPlatformConfig config
            sec003Fails = filter (isFailForCheck (PreflightCheck (CheckId Security 3))) results
        assertBool "SEC-003 fails" (not (null sec003Fails))
    ]
  ]

-- Helpers
isFailForCheck :: LintCheckId -> ConfigLintResult -> Bool
isFailForCheck cid r = clrCheckId r == cid && clrStatus r == LintFail

isWarnForCheck :: LintCheckId -> ConfigLintResult -> Bool
isWarnForCheck cid r = clrCheckId r == cid && clrStatus r == LintWarn

defaultSecAssertions :: SecurityAssertionsConfig
defaultSecAssertions = SecurityAssertionsConfig
  { sacVersion = Just 0
  , sacCCVersion = Nothing
  , sacEvalAssuranceLevel = Nothing
  , sacEvalStatus = Nothing
  , sacPlus = Nothing
  , sacStrengthOfFunction = Nothing
  , sacProtectionProfileOID = Nothing
  , sacProtectionProfileURI = Nothing
  , sacSecurityTargetOID = Nothing
  , sacSecurityTargetURI = Nothing
  , sacFIPSVersion = Nothing
  , sacFIPSSecurityLevel = Nothing
  , sacFIPSPlus = Nothing
  , sacRTMType = Nothing
  , sacISO9000Certified = Nothing
  , sacISO9000URI = Nothing
  }

testComponent :: ComponentConfig
testComponent = ComponentConfig
  { ccComponentClass = Just (ComponentClassConfig "2.23.133.18.3.1" "00030003")
  , ccClass = "00030003"
  , ccManufacturer = "Test Corp"
  , ccModel = "Test Component"
  , ccSerial = Just "C001"
  , ccRevision = Nothing
  , ccManufacturerId = Nothing
  , ccFieldReplaceable = Nothing
  , ccAddresses = Nothing
  , ccPlatformCert = Nothing
  , ccPlatformCertUri = Nothing
  , ccStatus = Nothing
  }
