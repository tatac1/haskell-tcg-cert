{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

-- |
-- Module      : Data.X509.TCG.Util.JsonReport
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- JSON report formatting for compliance check results.
--
-- When @--json@ is specified, all output goes through 'renderJsonReport'
-- instead of text display. No text messages are mixed with JSON.

module Data.X509.TCG.Util.JsonReport
  ( -- * Report Types
    ComplianceReport (..)
  , SubjectInfo (..)
  , ReportLayers (..)
  , LintLayerResult (..)
  , LintCheckEntry (..)
  , LintSummary (..)
    -- * Rendering
  , renderJsonReport
    -- * Report Builders
  , buildLintReport
  , buildGenerateReport
  , buildComplianceReport
    -- * Helpers
  , emptyLayers
  , lintResultToEntry
  , complianceResultToValue
  ) where

import Data.Text (Text)
import Data.Time (UTCTime)
import Data.Aeson
import qualified Data.ByteString.Lazy as LBS
import GHC.Generics (Generic)

import Data.X509.TCG.Compliance.Types
    ( ComplianceMode(..)
    , requirementLevelText, checkIdToText
    , complianceModeText
    )
import Data.X509.TCG.Compliance.Suggestion (formatSuggestion)
import Data.X509.TCG.Compliance.Result
    ( ComplianceResult(..), CategoryResult(..)
    )
import Data.X509.TCG.Util.ConfigLint

-- | Top-level compliance report
data ComplianceReport = ComplianceReport
  { crTool       :: !Text
  , crVersion    :: !Text
  , crCommand    :: !Text
  , crTimestamp  :: !UTCTime
  , crMode       :: !ComplianceMode
  , crCertType   :: !(Maybe Text)
  , crSubject    :: !(Maybe SubjectInfo)
  , crLayers     :: !ReportLayers
  , crCompliant  :: !Bool
  , crOutputFile :: !(Maybe FilePath)
  , crExitCode   :: !Int
  } deriving (Show)

-- | Subject identification
data SubjectInfo = SubjectInfo
  { siManufacturer :: !Text
  , siModel        :: !Text
  , siSerial       :: !Text
  } deriving (Show, Generic)

-- | Report layers
data ReportLayers = ReportLayers
  { rlConfigLint  :: !(Maybe LintLayerResult)
  , rlCompliance  :: !(Maybe Value)  -- full compliance result (Task 8)
  } deriving (Show)

-- | Lint layer result for JSON
data LintLayerResult = LintLayerResult
  { llExecuted :: !Bool
  , llResults  :: ![LintCheckEntry]
  , llSummary  :: !LintSummary
  } deriving (Show, Generic)

-- | Single lint check entry for JSON
data LintCheckEntry = LintCheckEntry
  { lceCheckId    :: !Text
  , lceCheckType  :: !Text    -- "preflight" or "configOnly"
  , lceLevel      :: !Text
  , lceStatus     :: !Text    -- "Pass", "Fail", "Warn"
  , lceMessage    :: !Text
  , lceSuggestion :: !(Maybe Text)
  } deriving (Show, Generic)

-- | Lint summary counts
data LintSummary = LintSummary
  { lsPass :: !Int
  , lsFail :: !Int
  , lsWarn :: !Int
  } deriving (Show, Generic)

-- ============================================================
-- ToJSON instances
-- ============================================================

instance ToJSON ComplianceReport where
  toJSON r = object
    [ "tool"       .= crTool r
    , "version"    .= crVersion r
    , "command"    .= crCommand r
    , "timestamp"  .= crTimestamp r
    , "mode"       .= complianceModeText (crMode r)
    , "certType"   .= crCertType r
    , "subject"    .= crSubject r
    , "layers"     .= crLayers r
    , "compliant"  .= crCompliant r
    , "outputFile" .= crOutputFile r
    , "exitCode"   .= crExitCode r
    ]

instance ToJSON SubjectInfo where
  toJSON s = object
    [ "manufacturer" .= siManufacturer s
    , "model"        .= siModel s
    , "serial"       .= siSerial s
    ]

instance ToJSON ReportLayers where
  toJSON l = object
    [ "configLint"  .= rlConfigLint l
    , "compliance"  .= rlCompliance l
    ]

instance ToJSON LintLayerResult where
  toJSON l = object
    [ "executed" .= llExecuted l
    , "results"  .= llResults l
    , "summary"  .= llSummary l
    ]

instance ToJSON LintCheckEntry where
  toJSON e = object
    [ "checkId"    .= lceCheckId e
    , "checkType"  .= lceCheckType e
    , "level"      .= lceLevel e
    , "status"     .= lceStatus e
    , "message"    .= lceMessage e
    , "suggestion" .= lceSuggestion e
    ]

instance ToJSON LintSummary where
  toJSON s = object
    [ "pass" .= lsPass s
    , "fail" .= lsFail s
    , "warn" .= lsWarn s
    ]

-- ============================================================
-- Rendering
-- ============================================================

-- | Render a report to compact JSON bytes.
renderJsonReport :: ComplianceReport -> LBS.ByteString
renderJsonReport = encode

-- ============================================================
-- Report Builders
-- ============================================================

-- | Build a report from lint results (for lint command).
buildLintReport :: Text -> ComplianceMode -> [ConfigLintResult] -> UTCTime -> ComplianceReport
buildLintReport command mode lintResults timestamp =
  let entries = map lintResultToEntry lintResults
      summary = summarizeLint lintResults
      hasFailures = lsFail summary > 0
      hasWarnings = lsWarn summary > 0
      compliant = case mode of
        StrictV11 -> not hasFailures && not hasWarnings
        OperationalCompatibility -> not hasFailures
      exitCode = case mode of
        StrictV11 -> if hasFailures || hasWarnings then 1 else 0
        OperationalCompatibility -> if hasFailures then 1
                                    else if hasWarnings then 2
                                    else 0
  in ComplianceReport
    { crTool = "tcg-platform-cert-util"
    , crVersion = "0.1.0"
    , crCommand = command
    , crTimestamp = timestamp
    , crMode = mode
    , crCertType = Nothing
    , crSubject = Nothing
    , crLayers = ReportLayers
        { rlConfigLint = Just LintLayerResult
            { llExecuted = True
            , llResults = entries
            , llSummary = summary
            }
        , rlCompliance = Nothing
        }
    , crCompliant = compliant
    , crOutputFile = Nothing
    , crExitCode = exitCode
    }

-- | Build a report for generate command.
buildGenerateReport :: ComplianceMode
                    -> [ConfigLintResult]      -- ^ Lint results (may be empty if skipped)
                    -> Maybe Value             -- ^ Full compliance results (Task 8)
                    -> Maybe FilePath           -- ^ Output file
                    -> Bool                     -- ^ Overall compliant
                    -> UTCTime
                    -> ComplianceReport
buildGenerateReport mode lintResults mCompResult mOutputFile compliant timestamp =
  let entries = map lintResultToEntry lintResults
      summary = summarizeLint lintResults
      lintLayer = if null lintResults
        then Nothing
        else Just LintLayerResult
            { llExecuted = True
            , llResults = entries
            , llSummary = summary
            }
  in ComplianceReport
    { crTool = "tcg-platform-cert-util"
    , crVersion = "0.1.0"
    , crCommand = "generate"
    , crTimestamp = timestamp
    , crMode = mode
    , crCertType = Nothing
    , crSubject = Nothing
    , crLayers = ReportLayers
        { rlConfigLint = lintLayer
        , rlCompliance = mCompResult
        }
    , crCompliant = compliant
    , crOutputFile = mOutputFile
    , crExitCode = if compliant then 0 else 1
    }

-- ============================================================
-- Helpers
-- ============================================================

-- | Empty layers (no lint, no compliance).
emptyLayers :: ReportLayers
emptyLayers = ReportLayers Nothing Nothing

-- | Convert a ConfigLintResult to a JSON-ready entry.
lintResultToEntry :: ConfigLintResult -> LintCheckEntry
lintResultToEntry r = LintCheckEntry
  { lceCheckId = case clrCheckId r of
      PreflightCheck cid -> checkIdToText cid
      ConfigOnly t -> t
  , lceCheckType = case clrCheckId r of
      PreflightCheck _ -> "preflight"
      ConfigOnly _ -> "configOnly"
  , lceLevel = requirementLevelText (clrLevel r)
  , lceStatus = case clrStatus r of
      LintPass -> "Pass"
      LintFail -> "Fail"
      LintWarn -> "Warn"
  , lceMessage = clrMessage r
  , lceSuggestion = fmap formatSuggestion (clrSuggestion r)
  }

-- | Summarize lint results into counts.
summarizeLint :: [ConfigLintResult] -> LintSummary
summarizeLint results = LintSummary
  { lsPass = length [r | r <- results, clrStatus r == LintPass]
  , lsFail = length [r | r <- results, clrStatus r == LintFail]
  , lsWarn = length [r | r <- results, clrStatus r == LintWarn]
  }

-- | Build a report from compliance results (for compliance command).
buildComplianceReport :: Text -> ComplianceMode -> ComplianceResult -> UTCTime -> ComplianceReport
buildComplianceReport command mode compResult timestamp =
  let compliant = resCompliant compResult
  in ComplianceReport
    { crTool = "tcg-platform-cert-util"
    , crVersion = "0.1.0"
    , crCommand = command
    , crTimestamp = timestamp
    , crMode = mode
    , crCertType = Nothing
    , crSubject = Nothing
    , crLayers = ReportLayers
        { rlConfigLint = Nothing
        , rlCompliance = Just (complianceResultToValue compResult)
        }
    , crCompliant = compliant
    , crOutputFile = Nothing
    , crExitCode = if compliant then 0 else 1
    }

-- | Convert a ComplianceResult to an aeson Value for JSON output.
complianceResultToValue :: ComplianceResult -> Value
complianceResultToValue cr = object
  [ "subject"            .= resSubject cr
  , "serialNumber"       .= resSerialNumber cr
  , "certType"           .= show (resCertType cr)
  , "mode"               .= complianceModeText (resComplianceMode cr)
  , "compliant"          .= resCompliant cr
  , "totalPassed"        .= resTotalPassed cr
  , "totalFailedRequired"     .= resTotalFailedRequired cr
  , "totalFailedRecommended"  .= resTotalFailedRecommended cr
  , "totalSkipped"       .= resTotalSkipped cr
  , "totalErrors"        .= resTotalErrors cr
  , "categories"         .= map categoryToValue (resCategories cr)
  ]

categoryToValue :: CategoryResult -> Value
categoryToValue cat = object
  [ "name"              .= show (catName cat)
  , "passed"            .= catPassed cat
  , "failed"            .= catFailed cat
  , "failedRequired"    .= catFailedRequired cat
  , "failedRecommended" .= catFailedRecommended cat
  , "skipped"           .= catSkipped cat
  , "errors"            .= catErrors cat
  ]
