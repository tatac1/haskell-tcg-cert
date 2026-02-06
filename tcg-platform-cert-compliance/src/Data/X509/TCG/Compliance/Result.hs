{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Result
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Check result types and smart constructors for the compliance framework.
--
-- This module provides the data types for representing compliance check
-- results at multiple levels of aggregation:
--
-- * 'CheckResult' - Individual check results with status and references
-- * 'CategoryResult' - Category-level aggregation (STR, VAL, etc.)
-- * 'ComplianceResult' - Overall compliance determination
--
-- Smart constructors ('mkPass', 'mkFail', etc.) automatically capture
-- timestamps for audit trail purposes.

module Data.X509.TCG.Compliance.Result
  ( -- * Check Status
    CheckStatus (..)

    -- * Individual Check Result
  , CheckResult (..)

    -- * Smart Constructors
  , mkPass
  , mkFail
  , mkSkip
  , mkError
  , mkPassWithDetails
  , mkFailWithDetails

    -- * Category Result
  , CategoryResult (..)
  , summarizeCategory

    -- * Overall Compliance Result
  , ComplianceResult (..)
  , isCompliant
  , summarize
  ) where

import Data.Text (Text)
import Data.Time (UTCTime, getCurrentTime)

import Data.X509.TCG.Compliance.Types (CheckCategory, CheckId, CertificateType, ComplianceMode, isRequired)
import Data.X509.TCG.Compliance.Reference

-- | Status of an individual check
data CheckStatus
  = Pass                  -- ^ Check passed
  | Fail Text             -- ^ Check failed with reason
  | Skip Text             -- ^ Check skipped (not applicable)
  | Error Text            -- ^ Error during check execution
  deriving (Show, Eq)

-- | Result of a single compliance check
data CheckResult = CheckResult
  { crId          :: CheckId        -- ^ Check identifier
  , crDescription :: Text           -- ^ Human-readable description
  , crStatus      :: CheckStatus    -- ^ Pass/Fail/Skip/Error
  , crReference   :: SpecReference  -- ^ Specification reference
  , crDetails     :: Maybe Text     -- ^ Additional details
  , crTimestamp   :: UTCTime        -- ^ When the check was performed
  } deriving (Show, Eq)

-- | Create a passing check result.
--
-- Note: Returns IO because it captures the current timestamp.
mkPass :: CheckId -> Text -> SpecReference -> IO CheckResult
mkPass cid desc ref = do
  now <- getCurrentTime
  return $ CheckResult cid desc Pass ref Nothing now

-- | Create a failing check result with a reason.
--
-- Note: Returns IO because it captures the current timestamp.
mkFail :: CheckId -> Text -> SpecReference -> Text -> IO CheckResult
mkFail cid desc ref reason = do
  now <- getCurrentTime
  return $ CheckResult cid desc (Fail reason) ref Nothing now

-- | Create a skipped check result with a reason.
--
-- Note: Returns IO because it captures the current timestamp.
mkSkip :: CheckId -> Text -> SpecReference -> Text -> IO CheckResult
mkSkip cid desc ref reason = do
  now <- getCurrentTime
  return $ CheckResult cid desc (Skip reason) ref Nothing now

-- | Create an error check result.
--
-- Note: Returns IO because it captures the current timestamp.
mkError :: CheckId -> Text -> SpecReference -> Text -> IO CheckResult
mkError cid desc ref err = do
  now <- getCurrentTime
  return $ CheckResult cid desc (Error err) ref Nothing now

-- | Create a passing check result with additional details.
mkPassWithDetails :: CheckId -> Text -> SpecReference -> Text -> IO CheckResult
mkPassWithDetails cid desc ref details = do
  now <- getCurrentTime
  return $ CheckResult cid desc Pass ref (Just details) now

-- | Create a failing check result with additional details.
mkFailWithDetails :: CheckId -> Text -> SpecReference -> Text -> Text -> IO CheckResult
mkFailWithDetails cid desc ref reason details = do
  now <- getCurrentTime
  return $ CheckResult cid desc (Fail reason) ref (Just details) now

-- | Category-level result aggregation
data CategoryResult = CategoryResult
  { catName       :: CheckCategory
  , catChecks     :: [CheckResult]
  , catPassed     :: Int
  , catFailed     :: Int
  , catFailedRequired :: Int
  , catFailedRecommended :: Int
  , catSkipped    :: Int
  , catErrors     :: Int
  } deriving (Show, Eq)

-- | Summarize check results for a category.
summarizeCategory :: CheckCategory -> [CheckResult] -> CategoryResult
summarizeCategory cat checks = CategoryResult
  { catName    = cat
  , catChecks  = checks
  , catPassed  = length [c | c <- checks, isPassStatus (crStatus c)]
  , catFailed  = length [c | c <- checks, isFailStatus (crStatus c)]
  , catFailedRequired = length [c | c <- checks, isRequiredFail c]
  , catFailedRecommended = length [c | c <- checks, isRecommendedFail c]
  , catSkipped = length [c | c <- checks, isSkipStatus (crStatus c)]
  , catErrors  = length [c | c <- checks, isErrorStatus (crStatus c)]
  }
  where
    isPassStatus Pass = True
    isPassStatus _    = False
    isFailStatus (Fail _) = True
    isFailStatus _        = False
    isSkipStatus (Skip _) = True
    isSkipStatus _        = False
    isErrorStatus (Error _) = True
    isErrorStatus _         = False
    isRequiredFail c = isFailStatus (crStatus c) && isRequired (srLevel (crReference c))
    isRecommendedFail c = isFailStatus (crStatus c) && not (isRequired (srLevel (crReference c)))

-- | Complete compliance test result
data ComplianceResult = ComplianceResult
  { resSubject       :: Text            -- ^ Subject identifier
  , resSerialNumber  :: Integer         -- ^ Certificate serial number
  , resCertType      :: CertificateType -- ^ Base or Delta certificate
  , resComplianceMode :: ComplianceMode -- ^ Compliance profile used for evaluation
  , resCategories    :: [CategoryResult] -- ^ Results by category
  , resTotalPassed   :: Int             -- ^ Total passed checks
  , resTotalFailed   :: Int             -- ^ Total failed checks
  , resTotalFailedRequired :: Int       -- ^ Total failed MUST/MUST NOT checks
  , resTotalFailedRecommended :: Int    -- ^ Total failed SHOULD/MAY checks
  , resTotalSkipped  :: Int             -- ^ Total skipped checks
  , resTotalErrors   :: Int             -- ^ Total errors
  , resCompliant     :: Bool            -- ^ Overall compliance status
  , resTestTime      :: UTCTime         -- ^ When the test was performed
  } deriving (Show, Eq)

-- | Check if overall result is compliant.
--
-- Compliant means no MUST/SHALL failures (failures = 0 and errors = 0).
isCompliant :: ComplianceResult -> Bool
isCompliant = resCompliant

-- | Generate summary statistics from category results.
--
-- Returns: (passed, failed, skipped, errors, compliant)
-- Compliant is True if there are no REQUIRED failures and no errors.
summarize :: [CategoryResult] -> (Int, Int, Int, Int, Int, Int, Bool)
summarize cats =
  let passed  = sum (map catPassed cats)
      failed  = sum (map catFailed cats)
      failedRequired = sum (map catFailedRequired cats)
      failedRecommended = sum (map catFailedRecommended cats)
      skipped = sum (map catSkipped cats)
      errors  = sum (map catErrors cats)
      compliant = failedRequired == 0 && errors == 0
  in (passed, failed, failedRequired, failedRecommended, skipped, errors, compliant)
