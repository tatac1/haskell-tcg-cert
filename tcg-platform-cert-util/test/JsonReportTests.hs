{-# LANGUAGE OverloadedStrings #-}

module JsonReportTests (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Data.Aeson (decode, Value(..))
import qualified Data.Aeson.KeyMap as KM
import Data.Time (UTCTime(..))
import Data.Time.Calendar (fromGregorian)

import Data.X509.TCG.Util.JsonReport
import Data.X509.TCG.Util.ConfigLint
import Data.X509.TCG.Compliance.Types (CheckId(..), CheckCategory(..), RequirementLevel(..), ComplianceMode(..))
import Data.X509.TCG.Compliance.Suggestion (Suggestion(..))

-- Helper: a fixed timestamp for deterministic testing
fixedTime :: UTCTime
fixedTime = UTCTime (fromGregorian 2026 2 7) 43200  -- 2026-02-07T12:00:00Z

tests :: TestTree
tests = testGroup "JsonReport"
  [ testGroup "renderJsonReport"
    [ testCase "produces valid JSON" $ do
        let report = minimalReport
            bs = renderJsonReport report
        case decode bs :: Maybe Value of
          Nothing -> assertFailure "renderJsonReport did not produce valid JSON"
          Just _  -> return ()

    , testCase "contains required fields" $ do
        let report = minimalReport
            bs = renderJsonReport report
        case decode bs :: Maybe Value of
          Nothing -> assertFailure "not valid JSON"
          Just (Object obj) -> do
            assertBool "has tool" (KM.member "tool" obj)
            assertBool "has version" (KM.member "version" obj)
            assertBool "has command" (KM.member "command" obj)
            assertBool "has compliant" (KM.member "compliant" obj)
            assertBool "has exitCode" (KM.member "exitCode" obj)
            assertBool "has timestamp" (KM.member "timestamp" obj)
            assertBool "has mode" (KM.member "mode" obj)
          Just _ -> assertFailure "top-level is not an object"

    , testCase "exitCode matches compliant status" $ do
        let report = minimalReport { crCompliant = True, crExitCode = 0 }
            bs = renderJsonReport report
        case decode bs :: Maybe Value of
          Just (Object obj) -> do
            assertEqual "exitCode" (Just (Number 0)) (KM.lookup "exitCode" obj)
            assertEqual "compliant" (Just (Bool True)) (KM.lookup "compliant" obj)
          _ -> assertFailure "not valid JSON object"

    , testCase "non-compliant report has exitCode 1" $ do
        let report = minimalReport { crCompliant = False, crExitCode = 1 }
            bs = renderJsonReport report
        case decode bs :: Maybe Value of
          Just (Object obj) ->
            assertEqual "exitCode" (Just (Number 1)) (KM.lookup "exitCode" obj)
          _ -> assertFailure "not valid JSON object"
    ]

  , testGroup "buildLintReport"
    [ testCase "builds report from lint results" $ do
        let lintResults =
              [ ConfigLintResult (PreflightCheck (CheckId Value 1)) Must LintPass
                  "platformManufacturerStr is valid" Nothing
              , ConfigLintResult (PreflightCheck (CheckId Value 8)) Must LintFail
                  "fipsSecurityLevel out of range"
                  (Just (ValueSuggestion "fipsSecurityLevel" "must be in range 1..4"))
              ]
            report = buildLintReport "lint" OperationalCompatibility lintResults fixedTime
        assertEqual "command" "lint" (crCommand report)
        assertEqual "mode" OperationalCompatibility (crMode report)
        assertBool "not compliant" (not (crCompliant report))

    , testCase "lint report with all pass is compliant" $ do
        let lintResults =
              [ ConfigLintResult (PreflightCheck (CheckId Value 1)) Must LintPass
                  "valid" Nothing
              ]
            report = buildLintReport "lint" OperationalCompatibility lintResults fixedTime
        assertBool "compliant" (crCompliant report)
        assertEqual "exitCode" 0 (crExitCode report)
    ]

  , testGroup "buildGenerateReport"
    [ testCase "builds report for successful generation" $ do
        let report = buildGenerateReport OperationalCompatibility [] Nothing
                       (Just "output.pem") True fixedTime
        assertBool "compliant" (crCompliant report)
        assertEqual "command" "generate" (crCommand report)
        assertEqual "outputFile" (Just "output.pem") (crOutputFile report)
    ]
  ]

-- | Minimal report for testing
minimalReport :: ComplianceReport
minimalReport = ComplianceReport
  { crTool = "tcg-platform-cert-util"
  , crVersion = "0.1.0"
  , crCommand = "lint"
  , crTimestamp = fixedTime
  , crMode = OperationalCompatibility
  , crCertType = Nothing
  , crSubject = Nothing
  , crLayers = emptyLayers
  , crCompliant = True
  , crOutputFile = Nothing
  , crExitCode = 0
  }
