{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Check
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Check runner infrastructure for the compliance testing framework.
--
-- This module provides the main entry points for running compliance tests:
--
-- * 'runComplianceTest' - Run all applicable checks on a certificate
-- * 'runCategoryChecks' - Run checks for a specific category
--
-- = Example Usage
--
-- @
-- import Data.X509.TCG.Compliance
--
-- result <- runComplianceTest cert defaultComplianceOptions
-- if resCompliant result
--   then putStrLn "Certificate is compliant"
--   else putStrLn $ "Non-compliant: " ++ show (resTotalFailed result) ++ " failures"
-- @

module Data.X509.TCG.Compliance.Check
  ( -- * Compliance Check Type
    ComplianceCheck

    -- * Configuration
  , ComplianceOptions (..)
  , defaultComplianceOptions

    -- * Running Checks
  , runComplianceTest
  , runCategoryChecks
  , runChecks

    -- * Utilities
  , filterByApplicability
  , lookupRef
  ) where

import Data.Maybe (fromMaybe)
import Data.Time (getCurrentTime)

import Data.X509.TCG.Platform (SignedPlatformCertificate, getPlatformCertificate)
import Data.X509.TCG.Platform (PlatformCertificateInfo(..))

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Internal (ComplianceCheck, lookupRef)

-- Import actual check implementations
import qualified Data.X509.TCG.Compliance.Structural as STR
import qualified Data.X509.TCG.Compliance.Value as VAL
import qualified Data.X509.TCG.Compliance.Extension as EXT
import qualified Data.X509.TCG.Compliance.Security as SEC
import qualified Data.X509.TCG.Compliance.Errata as ERR
import qualified Data.X509.TCG.Compliance.Chain as CHN
import qualified Data.X509.TCG.Compliance.Registry as REG
import qualified Data.X509.TCG.Compliance.Delta as DLT

-- | Options for running compliance tests
data ComplianceOptions = ComplianceOptions
  { coCategories    :: Maybe [CheckCategory]  -- ^ Categories to run (Nothing = all)
  , coStopOnFailure :: Bool                   -- ^ Stop at first failure
  , coIncludeSkips  :: Bool                   -- ^ Include skipped checks in output
  , coVerbose       :: Bool                   -- ^ Verbose output
  , coBaseCert      :: Maybe SignedPlatformCertificate  -- ^ Base cert for Delta comparison
  , coMode          :: ComplianceMode          -- ^ Compliance mode/profile
  }

-- Note: Cannot derive Show/Eq because SignedPlatformCertificate may not have these instances

-- | Default compliance options: run all categories, don't stop on failure.
-- The default profile is operational compatibility.
defaultComplianceOptions :: ComplianceOptions
defaultComplianceOptions = ComplianceOptions
  { coCategories    = Nothing
  , coStopOnFailure = False
  , coIncludeSkips  = True
  , coVerbose       = False
  , coBaseCert      = Nothing
  , coMode          = OperationalCompatibility
  }

-- | Run all compliance tests on a certificate
--
-- This is the main entry point for compliance testing. It:
-- 1. Detects the certificate type (Base or Delta)
-- 2. Runs all applicable checks based on certificate type
-- 3. Aggregates results into a ComplianceResult
runComplianceTest :: SignedPlatformCertificate
                  -> ComplianceOptions
                  -> IO ComplianceResult
runComplianceTest cert opts = do
  let certType = detectCertificateType cert
      pci = getPlatformCertificate cert
      serialNum = pciSerialNumber pci
      -- Subject identification (placeholder - extract from holder)
      subject = "Platform Certificate"
      categories = fromMaybe allCategories (coCategories opts)

  -- Run checks for each category
  categoryResults <- mapM (runCategoryChecks cert certType defaultReferenceDB opts) categories

  -- Calculate totals
  let (passed, failed, failedReq, failedRec, skipped, errors, compliant) = summarize categoryResults

  -- Get test timestamp
  now <- getCurrentTime

  return ComplianceResult
    { resSubject      = subject
    , resSerialNumber = serialNum
    , resCertType     = certType
    , resComplianceMode = coMode opts
    , resCategories   = categoryResults
    , resTotalPassed  = passed
    , resTotalFailed  = failed
    , resTotalFailedRequired = failedReq
    , resTotalFailedRecommended = failedRec
    , resTotalSkipped = skipped
    , resTotalErrors  = errors
    , resCompliant    = compliant
    , resTestTime     = now
    }

-- | Run all checks for a specific category
runCategoryChecks :: SignedPlatformCertificate
                  -> CertificateType
                  -> ReferenceDB
                  -> ComplianceOptions
                  -> CheckCategory
                  -> IO CategoryResult
runCategoryChecks cert certType refDB opts category = do
  -- Get the checks for this category
  -- For Delta category, use base-cert-aware checks if base cert is provided
  let checks0 = case (category, coBaseCert opts) of
        (Delta, Just baseCert) -> deltaChecksWithBase (coMode opts) baseCert
        _ -> getChecksForCategory opts category
      checks = applyStrictDeltaBaseRequirement opts category checks0
      -- Filter checks by applicability
      applicableChecks = filterByApplicability certType checks

  -- Run all applicable checks
  results <- runChecks cert refDB applicableChecks

  return $ summarizeCategory category results

-- | Run a list of checks and collect results
runChecks :: SignedPlatformCertificate
          -> ReferenceDB
          -> [(CheckId, ComplianceCheck)]
          -> IO [CheckResult]
runChecks cert refDB checks = sequence [check cert refDB | (_, check) <- checks]

-- | Filter checks by applicability to certificate type
filterByApplicability :: CertificateType
                      -> [(CheckId, ComplianceCheck)]
                      -> [(CheckId, ComplianceCheck)]
filterByApplicability certType = filter (isApplicableCheck certType . fst)

-- | Check if a check applies to a certificate type
isApplicableCheck :: CertificateType -> CheckId -> Bool
isApplicableCheck certType cid =
  let app = getApplicability cid
  in isApplicable app certType

-- | Get applicability for a check
-- Delta-specific checks only apply to Delta certificates
-- Most checks apply to both Base and Delta certificates
-- Note: IWG Table 1 & Table 2 show Certificate Type Label and Certificate Specification
--       are MUST for BOTH Base and Delta certificates
getApplicability :: CheckId -> Applicability
getApplicability (CheckId Delta _) = AppDelta
getApplicability _                 = AppBoth

-- | Get all checks for a category
-- This returns placeholder checks - the actual implementations are in
-- Structural.hs, Value.hs, etc.
getChecksForCategory :: ComplianceOptions -> CheckCategory -> [(CheckId, ComplianceCheck)]
getChecksForCategory opts category = case category of
  Structural -> structuralChecks
  Value      -> valueChecks (coMode opts)
  Delta      -> deltaChecks (coMode opts)
  Chain      -> chainChecks
  Registry   -> registryChecks (coMode opts)
  Extension  -> extensionChecks
  Security   -> securityChecks
  Errata     -> errataChecks

-- | Structural checks (STR-001 to STR-013)
-- Real implementations from Structural.hs
structuralChecks :: [(CheckId, ComplianceCheck)]
structuralChecks =
  [ (CheckId Structural 1,  STR.checkVersion)
  , (CheckId Structural 2,  STR.checkHolder)
  , (CheckId Structural 3,  STR.checkIssuer)
  , (CheckId Structural 4,  STR.checkSignatureAlg)
  , (CheckId Structural 5,  STR.checkSerialNumber)
  , (CheckId Structural 6,  STR.checkValidityPeriod)
  , (CheckId Structural 7,  STR.checkAttributes)
  , (CheckId Structural 8,  STR.checkExtensionOIDs)
  , (CheckId Structural 9,  STR.checkCriticalExts)
  , (CheckId Structural 10, STR.checkPlatformUri)
  , (CheckId Structural 11, STR.checkTcgPlatformSpecification)
  , (CheckId Structural 12, STR.checkTcgCredentialType)
  , (CheckId Structural 13, STR.checkTcgCredentialSpecification)
  ]

-- | Value checks (VAL-001 to VAL-017)
-- Real implementations from Value.hs
valueChecks :: ComplianceMode -> [(CheckId, ComplianceCheck)]
valueChecks mode =
  [ (CheckId Value 1,  VAL.checkManufacturerStr)
  , (CheckId Value 2,  VAL.checkPlatformModel)
  , (CheckId Value 3,  VAL.checkPlatformVersion)
  , (CheckId Value 4,  VAL.checkPlatformSerial)
  , (CheckId Value 5,  VAL.checkManufacturerId)
  , (CheckId Value 6,  VAL.checkTpmSecAssertions)
  , (CheckId Value 7,  VAL.checkTpmSecVersion)
  , (CheckId Value 8,  VAL.checkFipsLevel)
  , (CheckId Value 9,  VAL.checkIso9000Certified)
  , (CheckId Value 10, VAL.checkEalLevel)
  , (CheckId Value 11, VAL.checkComponentId)
  , (CheckId Value 12, VAL.checkClassRegistry)
  , (CheckId Value 13, VAL.checkClassValue)
  , (CheckId Value 14, VAL.checkAttrCertId)
  , (CheckId Value 15, VAL.checkComponentIdV2WithMode mode)
  , (CheckId Value 16, VAL.checkCertId)
  , (CheckId Value 17, VAL.checkSofRange)
  ]

-- | Delta checks (DLT-001 to DLT-012)
-- Real implementations from Delta.hs
deltaChecks :: ComplianceMode -> [(CheckId, ComplianceCheck)]
deltaChecks mode =
  [ (CheckId Delta 1,  DLT.checkDeltaHasPlatformConfig)
  , (CheckId Delta 2,  DLT.checkDeltaHasCredentialType)
  , (CheckId Delta 3,  DLT.checkDeltaSerialPositive)
  , (CheckId Delta 4,  DLT.checkHolderRefsBase)
  , (CheckId Delta 5,  DLT.checkValidityMatchesBaseWithMode mode)
  , (CheckId Delta 6,  DLT.checkAttributeStatusValues)
  , (CheckId Delta 7,  DLT.checkStatusFieldDeltaOnly)
  , (CheckId Delta 8,  DLT.checkComponentsHaveStatus)
  , (CheckId Delta 9,  DLT.checkManufacturerMatchesBase)
  , (CheckId Delta 10, DLT.checkModelMatchesBase)
  , (CheckId Delta 11, DLT.checkVersionMatchesBase)
  , (CheckId Delta 12, DLT.checkSerialMatchesBase)
  ]

-- | Delta checks with base certificate (for comparison checks)
deltaChecksWithBase :: ComplianceMode
                    -> SignedPlatformCertificate  -- ^ Base certificate
                    -> [(CheckId, ComplianceCheck)]
deltaChecksWithBase mode baseCert =
  [ (CheckId Delta 1,  wrapWithBase DLT.checkDeltaHasPlatformConfigWithCert)
  , (CheckId Delta 2,  DLT.checkDeltaHasCredentialType)
  , (CheckId Delta 3,  DLT.checkDeltaSerialPositive)
  , (CheckId Delta 4,  wrapWithBase DLT.checkHolderRefsBaseWithCert)
  , (CheckId Delta 5,  wrapWithBase (DLT.checkValidityMatchesBaseWithCertWithMode mode))
  , (CheckId Delta 6,  DLT.checkAttributeStatusValues)
  , (CheckId Delta 7,  DLT.checkStatusFieldDeltaOnly)
  , (CheckId Delta 8,  DLT.checkComponentsHaveStatus)
  , (CheckId Delta 9,  wrapWithBase DLT.checkManufacturerMatchesBaseWithCert)
  , (CheckId Delta 10, wrapWithBase DLT.checkModelMatchesBaseWithCert)
  , (CheckId Delta 11, wrapWithBase DLT.checkVersionMatchesBaseWithCert)
  , (CheckId Delta 12, wrapWithBase DLT.checkSerialMatchesBaseWithCert)
  ]
  where
    -- Wrap a WithBase check function to match ComplianceCheck signature
    wrapWithBase :: (SignedPlatformCertificate -> SignedPlatformCertificate -> ReferenceDB -> IO CheckResult)
                 -> ComplianceCheck
    wrapWithBase checkFn deltaCert refDB = checkFn deltaCert baseCert refDB

-- | Chain checks (CHN-001 to CHN-005)
-- Real implementations from Chain.hs
chainChecks :: [(CheckId, ComplianceCheck)]
chainChecks =
  [ (CheckId Chain 1, CHN.checkAuthorityKeyId)
  , (CheckId Chain 2, CHN.checkAuthorityInfoAcc)
  , (CheckId Chain 3, CHN.checkCrlDistribution)
  , (CheckId Chain 4, CHN.checkEkCertBinding)
  , (CheckId Chain 5, CHN.checkTargetingInfo)
  ]

-- | Registry checks (REG-001 to REG-004)
-- Real implementations from Registry.hs
registryChecks :: ComplianceMode -> [(CheckId, ComplianceCheck)]
registryChecks mode =
  [ (CheckId Registry 1, REG.checkTcgRegistryOidWithMode mode)
  , (CheckId Registry 2, REG.checkClassValueStruct)
  , (CheckId Registry 3, REG.checkTcgRegistryValues)
  , (CheckId Registry 4, REG.checkRegistryTranslationScope)
  ]

-- | Extension checks (EXT-001 to EXT-005)
-- Real implementations from Extension.hs
extensionChecks :: [(CheckId, ComplianceCheck)]
extensionChecks =
  [ (CheckId Extension 1, EXT.checkCertificatePolicies)
  , (CheckId Extension 2, EXT.checkSubjectAltNames)
  , (CheckId Extension 3, EXT.checkUserNotice)
  , (CheckId Extension 4, EXT.checkIssuerUniqueId)
  , (CheckId Extension 5, EXT.checkTargetingInfoCritical)
  ]

-- | Security checks (SEC-001 to SEC-005)
-- Real implementations from Security.hs
securityChecks :: [(CheckId, ComplianceCheck)]
securityChecks =
  [ (CheckId Security 1, SEC.checkTbbSecForBaseOnly)
  , (CheckId Security 2, SEC.checkTcgSpecForBaseOnly)
  , (CheckId Security 3, SEC.checkMeasurementRootType)
  , (CheckId Security 4, SEC.checkCCMeasuresConsist)
  , (CheckId Security 5, SEC.checkUriRefHash)
  ]

-- | Errata checks (ERR-001 to ERR-005)
-- Real implementations from Errata.hs
errataChecks :: [(CheckId, ComplianceCheck)]
errataChecks =
  [ (CheckId Errata 1, ERR.checkComponentIdOrder)
  , (CheckId Errata 2, ERR.checkMacAddressFormat)
  , (CheckId Errata 3, ERR.checkPrivateEntNum)
  , (CheckId Errata 4, ERR.checkBaseCertIdEnc)
  , (CheckId Errata 5, ERR.check48BitMacOids)
  ]

-- | In StrictV11 mode, base certificate comparisons are mandatory for Delta checks.
-- If the base certificate is not provided, emit explicit Error results instead of Skip.
applyStrictDeltaBaseRequirement :: ComplianceOptions
                                -> CheckCategory
                                -> [(CheckId, ComplianceCheck)]
                                -> [(CheckId, ComplianceCheck)]
applyStrictDeltaBaseRequirement opts category checks
  | category /= Delta = checks
  | coMode opts /= StrictV11 = checks
  | coBaseCert opts /= Nothing = checks
  | otherwise = map requireBase checks
  where
    requireBase (cid, chk)
      | cid `elem` baseRequiredChecks = (cid, baseRequiredError cid)
      | otherwise = (cid, chk)

    baseRequiredChecks =
      [ CheckId Delta 1
      , CheckId Delta 4
      , CheckId Delta 5
      , CheckId Delta 9
      , CheckId Delta 10
      , CheckId Delta 11
      , CheckId Delta 12
      ]

    baseRequiredError :: CheckId -> ComplianceCheck
    baseRequiredError cid _cert refDB =
      mkError cid "Base certificate required for StrictV11 Delta checks"
        (lookupRef cid refDB)
        "StrictV11 requires base certificate for Delta comparison but none was provided"
