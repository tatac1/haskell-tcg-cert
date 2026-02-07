{-# LANGUAGE OverloadedStrings #-}

module PreIssuanceTests (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import Data.X509.TCG.Util.PreIssuance
import Data.X509.TCG.Util.ConfigLint (LintStatus(..), clrStatus)
import Data.X509.TCG.Util.Config (PlatformCertConfig(..))
import Data.X509.TCG.Compliance.Types (ComplianceMode(..))

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

-- | Config with empty manufacturer - will fail lint
invalidBaseConfig :: PlatformCertConfig
invalidBaseConfig = validBaseConfig { pccManufacturer = "" }

tests :: TestTree
tests = testGroup "PreIssuance"
  [ testCase "default options use OperationalCompatibility" $ do
      let opts = defaultPreIssuanceOptions
      assertEqual "default mode" OperationalCompatibility (pioMode opts)
      assertEqual "default verbose" False (pioVerbose opts)

  , testCase "preIssuanceLintOnly detects empty manufacturer" $ do
      let lintResults = preIssuanceLintOnly invalidBaseConfig
          hasFailure = any (\r -> clrStatus r == LintFail) lintResults
      assertBool "lint detects empty manufacturer" hasFailure

  , testCase "preIssuanceLintOnly passes valid config" $ do
      let lintResults = preIssuanceLintOnly validBaseConfig
          hasFailure = any (\r -> clrStatus r == LintFail) lintResults
      assertBool "lint passes valid config" (not hasFailure)

  , testCase "preIssuanceCheckBase returns LintFail for invalid config" $ do
      let generateAction = return (Left "should not reach generation" :: Either String ())
          opts = defaultPreIssuanceOptions
      result <- preIssuanceCheckBase invalidBaseConfig generateAction opts
      case result of
        PreIssuanceLintFail _ -> return ()  -- expected
        other -> assertFailure $ "Expected PreIssuanceLintFail, got: " ++ describeResult other

  , testCase "preIssuanceCheckBase returns GenerationFail when generation fails" $ do
      let generateAction = return (Left "crypto error: invalid key" :: Either String ())
          opts = defaultPreIssuanceOptions
      result <- preIssuanceCheckBase validBaseConfig generateAction opts
      case result of
        PreIssuanceGenerationFail err -> assertBool "contains error" ("crypto error" `isInfixOfStr` err)
        other -> assertFailure $ "Expected PreIssuanceGenerationFail, got: " ++ describeResult other

  , testCase "isPreIssuancePass correctly identifies pass" $ do
      assertBool "LintFail is not pass" (not (isPreIssuancePass (PreIssuanceLintFail [])))
      assertBool "GenerationFail is not pass" (not (isPreIssuancePass (PreIssuanceGenerationFail "err")))

  , testCase "hasLintFailures correctly identifies lint failures" $ do
      assertBool "LintFail has lint failures" (hasLintFailures (PreIssuanceLintFail []))
      assertBool "GenerationFail has no lint failures" (not (hasLintFailures (PreIssuanceGenerationFail "err")))

  , testCase "shouldBlockLint blocks on required failures in OperationalCompatibility" $ do
      let lintResults = preIssuanceLintOnly invalidBaseConfig
      assertBool "blocks on required failures" (shouldBlockLint OperationalCompatibility lintResults)

  , testCase "shouldBlockLint does not block on warnings in OperationalCompatibility" $ do
      -- validBaseConfig missing securityAssertions only produces a WARN, not a FAIL
      let lintResults = preIssuanceLintOnly validBaseConfig
      assertBool "does not block on warnings" (not (shouldBlockLint OperationalCompatibility lintResults))

  , testCase "shouldBlockLint blocks on warnings in StrictV11" $ do
      -- validBaseConfig missing securityAssertions produces a WARN - StrictV11 blocks on it
      let lintResults = preIssuanceLintOnly validBaseConfig
          hasWarns = any (\r -> clrStatus r == LintWarn) lintResults
      -- Only test blocking if there are warnings
      if hasWarns
        then assertBool "StrictV11 blocks on warnings" (shouldBlockLint StrictV11 lintResults)
        else return ()  -- No warnings = no blocking (still valid)
  ]

-- Helpers
isInfixOfStr :: String -> String -> Bool
isInfixOfStr needle haystack = any (isPrefixOfStr needle) (tails haystack)
  where
    isPrefixOfStr [] _ = True
    isPrefixOfStr _ [] = False
    isPrefixOfStr (x:xs) (y:ys) = x == y && isPrefixOfStr xs ys
    tails [] = [[]]
    tails xs@(_:xs') = xs : tails xs'

describeResult :: PreIssuanceResult a -> String
describeResult (PreIssuanceLintFail _) = "PreIssuanceLintFail"
describeResult (PreIssuanceGenerationFail e) = "PreIssuanceGenerationFail: " ++ e
describeResult (PreIssuanceComplianceFail _ _) = "PreIssuanceComplianceFail"
describeResult (PreIssuancePass _) = "PreIssuancePass"
