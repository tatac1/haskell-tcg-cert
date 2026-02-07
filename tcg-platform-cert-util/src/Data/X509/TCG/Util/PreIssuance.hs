{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Util.PreIssuance
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Two-layer pre-issuance compliance checking orchestration.
--
-- Layer 1 (ConfigLint): Validates YAML config against IWG rules before generation.
-- Layer 2 (dry-run): Generates a certificate in memory and runs the full 66-check
-- compliance suite.
--
-- The certificate type is polymorphic so that Layer 1 can be tested independently
-- of actual certificate generation. For Layer 2 with real certificates, use
-- 'SignedPlatformCertificate' as the type parameter.

module Data.X509.TCG.Util.PreIssuance
  ( -- * Types
    PreIssuanceResult (..)
  , PreIssuanceOptions (..)
  , defaultPreIssuanceOptions
    -- * Pre-issuance Checks
  , preIssuanceCheckBase
  , preIssuanceLintOnly
    -- * Result Inspection
  , isPreIssuancePass
  , hasLintFailures
    -- * Blocking Logic
  , shouldBlockLint
  ) where

import Data.X509.TCG.Util.Config (PlatformCertConfig)
import Data.X509.TCG.Util.ConfigLint
import Data.X509.TCG.Compliance.Types (ComplianceMode(..), isRequired)
import Data.X509.TCG.Compliance.Result (ComplianceResult)

-- | Pre-issuance check result.
-- Polymorphic in @a@ to allow testing without real certificates.
-- For actual usage, @a@ = 'SignedPlatformCertificate'.
data PreIssuanceResult a
  = PreIssuancePass a                              -- ^ Both layers passed; holds generated cert for reuse
  | PreIssuanceLintFail [ConfigLintResult]            -- ^ Layer 1 failed
  | PreIssuanceGenerationFail String                  -- ^ Certificate generation itself failed
  | PreIssuanceComplianceFail ComplianceResult a      -- ^ Layer 2 failed; holds compliance result and cert
  deriving (Show)

-- | Pre-issuance options
data PreIssuanceOptions = PreIssuanceOptions
  { pioMode    :: ComplianceMode
  , pioVerbose :: Bool
  } deriving (Show, Eq)

-- | Default options: OperationalCompatibility mode, non-verbose.
defaultPreIssuanceOptions :: PreIssuanceOptions
defaultPreIssuanceOptions = PreIssuanceOptions OperationalCompatibility False

-- | Run Layer 1 only (for lint command).
preIssuanceLintOnly :: PlatformCertConfig -> [ConfigLintResult]
preIssuanceLintOnly = lintPlatformConfig

-- | Run both layers for Base certificate.
--
-- The @generateAction@ parameter is an IO action that produces either an error
-- or the generated certificate. This avoids coupling the module to specific
-- crypto key types.
--
-- Flow:
--
-- 1. Run Layer 1 (ConfigLint) on the config
-- 2. If blocking failures found, return 'PreIssuanceLintFail'
-- 3. Execute @generateAction@ to produce the certificate in memory
-- 4. If generation fails, return 'PreIssuanceGenerationFail'
-- 5. Return 'PreIssuancePass' with the generated certificate
--
-- Note: Layer 2 (full compliance check on generated certificate) is wired
-- in the CLI integration (Task 7) where 'SignedPlatformCertificate' and
-- 'runComplianceTest' are available.
preIssuanceCheckBase
  :: PlatformCertConfig
  -> IO (Either String a)          -- ^ Certificate generation action
  -> PreIssuanceOptions
  -> IO (PreIssuanceResult a)
preIssuanceCheckBase config generateAction opts = do
  -- Layer 1: Config lint
  let lintResults = lintPlatformConfig config
  if shouldBlockLint (pioMode opts) lintResults
    then return $ PreIssuanceLintFail lintResults
    else do
      -- Layer 2: Generate in memory
      genResult <- generateAction
      case genResult of
        Left err -> return $ PreIssuanceGenerationFail err
        Right cert -> return $ PreIssuancePass cert

-- | Check if lint results should block issuance based on compliance mode.
shouldBlockLint :: ComplianceMode -> [ConfigLintResult] -> Bool
shouldBlockLint mode results = any (shouldBlockResult mode) results

-- | Check if a single lint result should block issuance.
shouldBlockResult :: ComplianceMode -> ConfigLintResult -> Bool
shouldBlockResult OperationalCompatibility r =
  clrStatus r == LintFail && isRequired (clrLevel r)
shouldBlockResult StrictV11 r =
  clrStatus r == LintFail || clrStatus r == LintWarn

-- | Result inspection helpers
isPreIssuancePass :: PreIssuanceResult a -> Bool
isPreIssuancePass (PreIssuancePass _) = True
isPreIssuancePass _ = False

hasLintFailures :: PreIssuanceResult a -> Bool
hasLintFailures (PreIssuanceLintFail _) = True
hasLintFailures _ = False
