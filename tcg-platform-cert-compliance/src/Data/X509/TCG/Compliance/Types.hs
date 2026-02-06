{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Types
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Core types for TCG Platform Certificate compliance testing.
--
-- This module provides the fundamental type definitions used throughout
-- the compliance testing framework, based on IWG Platform Certificate
-- Profile v1.1 requirements.

module Data.X509.TCG.Compliance.Types
  ( -- * Check Identification
    CheckId (..)
  , CheckCategory (..)
  , checkIdToText
  , parseCheckId
  , categoryPrefix
  , allCategories

    -- * Requirement Levels (RFC 2119)
  , RequirementLevel (..)
  , isRequired
  , requirementLevelText

    -- * Compliance Mode
  , ComplianceMode (..)
  , complianceModeText

    -- * Certificate Classification
  , CertificateType (..)
  , detectCertificateType

    -- * Applicability
  , Applicability (..)
  , isApplicable

    -- * Requirement Level by Certificate Type
  , getRequirementLevel
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import Text.Printf (printf)
import Text.Read (readMaybe)

import Data.X509.TCG.Platform (SignedPlatformCertificate, getPlatformCertificate, pciAttributes)
import Data.X509.TCG.OID (tcg_at_tcgCredentialType, tcg_kp_DeltaAttributeCertificate)
import Data.X509.TCG.Utils (lookupAttributeByOID)
import Data.ASN1.Types (ASN1(..))

-- | Unique identifier for each compliance check
-- Format: Category prefix + sequence number (e.g., STR-001, VAL-017)
data CheckId = CheckId
  { cidCategory :: !CheckCategory
  , cidNumber   :: !Int
  } deriving (Eq, Ord)

instance Show CheckId where
  show (CheckId cat num) = categoryPrefix cat ++ "-" ++ printf "%03d" num

-- | Compliance check categories aligned with IWG specification sections
data CheckCategory
  = Structural    -- ^ STR: RFC 5755 structural requirements
  | Value         -- ^ VAL: Attribute value constraints
  | Delta         -- ^ DLT: Delta certificate invariants
  | Chain         -- ^ CHN: Certificate chain validation
  | Registry      -- ^ REG: Component class registry validation
  | Extension     -- ^ EXT: Extension field validation
  | Security      -- ^ SEC: Security assertions validation
  | Errata        -- ^ ERR: Errata corrections
  deriving (Show, Eq, Ord, Enum, Bounded)

-- | Get the prefix for a check category
categoryPrefix :: CheckCategory -> String
categoryPrefix = \case
  Structural -> "STR"
  Value      -> "VAL"
  Delta      -> "DLT"
  Chain      -> "CHN"
  Registry   -> "REG"
  Extension  -> "EXT"
  Security   -> "SEC"
  Errata     -> "ERR"

-- | All available check categories
allCategories :: [CheckCategory]
allCategories = [minBound .. maxBound]

-- | Convert a CheckId to Text format (e.g., "STR-001")
checkIdToText :: CheckId -> Text
checkIdToText (CheckId cat num) =
  T.pack $ categoryPrefix cat ++ "-" ++ printf "%03d" num

-- | Parse a CheckId from Text format (e.g., "STR-001")
parseCheckId :: Text -> Maybe CheckId
parseCheckId t = do
  let str = T.unpack t
  case break (== '-') str of
    (prefix, '-':numStr) -> do
      cat <- parseCategoryPrefix prefix
      num <- readMaybe numStr
      return $ CheckId cat num
    _ -> Nothing

-- | Parse a category prefix string
parseCategoryPrefix :: String -> Maybe CheckCategory
parseCategoryPrefix = \case
  "STR" -> Just Structural
  "VAL" -> Just Value
  "DLT" -> Just Delta
  "CHN" -> Just Chain
  "REG" -> Just Registry
  "EXT" -> Just Extension
  "SEC" -> Just Security
  "ERR" -> Just Errata
  _     -> Nothing

-- | RFC 2119 requirement levels
data RequirementLevel
  = Must        -- ^ MUST / SHALL / REQUIRED
  | MustNot     -- ^ MUST NOT / SHALL NOT
  | Should      -- ^ SHOULD / RECOMMENDED
  | ShouldNot   -- ^ SHOULD NOT / NOT RECOMMENDED
  | May         -- ^ MAY / OPTIONAL
  deriving (Show, Eq, Ord, Enum, Bounded)

-- | Check if a requirement level is mandatory
isRequired :: RequirementLevel -> Bool
isRequired Must    = True
isRequired MustNot = True
isRequired _       = False

-- | Get text representation of requirement level
requirementLevelText :: RequirementLevel -> Text
requirementLevelText = \case
  Must      -> "MUST"
  MustNot   -> "MUST NOT"
  Should    -> "SHOULD"
  ShouldNot -> "SHOULD NOT"
  May       -> "MAY"

-- | Compliance mode for profile-dependent behavior.
--
-- The default profile is operational compatibility per compliance-test-guide:
-- - OperationalCompatibility: allow tcg/ietf/dmtf/pcie/storage registries and
--   accept prior platformConfiguration OID versions.
-- - StrictV11: enforce v1.1-only behavior.
data ComplianceMode
  = OperationalCompatibility
  | StrictV11
  deriving (Show, Eq)

-- | Human-readable compliance mode label.
complianceModeText :: ComplianceMode -> Text
complianceModeText OperationalCompatibility = "OperationalCompatibility"
complianceModeText StrictV11 = "StrictV11"

-- | Certificate type classification
data CertificateType
  = BasePlatformCert   -- ^ Base Platform Certificate
  | DeltaPlatformCert  -- ^ Delta Platform Certificate
  deriving (Show, Eq)

-- | Detect certificate type from structure
-- A certificate is a Delta Platform Certificate if:
-- 1. The tcg-at-tcgCredentialType attribute (OID 2.23.133.2.25) contains
--    the Delta Platform Certificate OID (2.23.133.8.5)
detectCertificateType :: SignedPlatformCertificate -> CertificateType
detectCertificateType cert
  | hasDeltaCredentialType = DeltaPlatformCert
  | otherwise              = BasePlatformCert
  where
    certInfo = getPlatformCertificate cert
    attrs = pciAttributes certInfo

    -- Check tcg-at-tcgCredentialType attribute for Delta OID
    -- lookupAttributeByOID returns Maybe [AttributeValue] where AttributeValue = ASN1
    -- (concat flattens [[ASN1]] to [ASN1])
    hasDeltaCredentialType = case lookupAttributeByOID tcg_at_tcgCredentialType attrs of
      Nothing -> False
      Just asn1Values -> any isDeltaOID asn1Values

    isDeltaOID :: ASN1 -> Bool
    isDeltaOID (OID oid) = oid == tcg_kp_DeltaAttributeCertificate
    isDeltaOID _ = False

-- | Check applicability to certificate types
data Applicability
  = AppBase       -- ^ Applies to Base certificates only
  | AppDelta      -- ^ Applies to Delta certificates only
  | AppBoth       -- ^ Applies to both Base and Delta
  deriving (Show, Eq)

-- | Check if a requirement applies to a given certificate type
isApplicable :: Applicability -> CertificateType -> Bool
isApplicable AppBoth  _                 = True
isApplicable AppBase  BasePlatformCert  = True
isApplicable AppDelta DeltaPlatformCert = True
isApplicable _        _                 = False

-- | Get requirement level for a check based on certificate type
-- This handles cases where a field is MUST for Base but MAY for Delta
-- per IWG Platform Certificate Profile v1.1 Table 1 & Table 2
--
-- Table 2 (Delta) MAY fields:
--   - Platform Serial Number (VAL-004)
--   - Platform Manufacturer Identifier (VAL-005)
--   - Platform Configuration Uri (STR-010)
--   - Revocation Locator (CHN-003)
--   - EK Certificates (CHN-004)
--   - Platform Configuration (DLT-001 semantics are conditional on presence)
getRequirementLevel :: CheckId -> CertificateType -> RequirementLevel
getRequirementLevel cid certType = case (cid, certType) of
  -- VAL-004: Platform Serial Number
  -- Base/Delta: MAY (conditional)
  (CheckId Value 4, _) -> May

  -- VAL-005: Platform Manufacturer Identifier
  -- Base/Delta: MAY (conditional)
  (CheckId Value 5, _) -> May

  -- STR-010: Platform Configuration Uri
  -- Base/Delta: MAY (if present MUST be valid)
  (CheckId Structural 10, _) -> May

  -- CHN-002: Authority Info Access
  (CheckId Chain 2, _) -> Should

  -- CHN-003: CRL Distribution Points (Revocation Locator)
  -- Base/Delta: MAY (if present MUST be valid)
  (CheckId Chain 3, BasePlatformCert) -> May
  (CheckId Chain 3, DeltaPlatformCert) -> May

  -- DLT-001: platformConfiguration MAY be present in Delta
  -- If present, it MUST represent changes from base certificate.
  (CheckId Delta 1, DeltaPlatformCert) -> May

  -- CHN-004: EK Certificate binding
  -- Base: MUST, Delta: MAY (Table 2)
  (CheckId Chain 4, DeltaPlatformCert) -> May
  (CheckId Chain 4, BasePlatformCert)  -> Must

  -- STR-011: Platform specification
  -- Base: SHOULD include, Delta: MUST NOT include
  (CheckId Structural 11, BasePlatformCert)  -> Should
  (CheckId Structural 11, DeltaPlatformCert) -> MustNot

  -- STR-012: Credential type
  -- Base: SHOULD include, Delta: MUST include
  (CheckId Structural 12, BasePlatformCert)  -> Should
  (CheckId Structural 12, DeltaPlatformCert) -> Must

  -- STR-013: Credential specification
  -- Base: SHOULD include, Delta: MAY include
  (CheckId Structural 13, BasePlatformCert)  -> Should
  (CheckId Structural 13, DeltaPlatformCert) -> May

  -- VAL-006: TBBSecurityAssertions
  -- Base: SHOULD include, Delta: MUST NOT include
  (CheckId Value 6, BasePlatformCert)  -> Should
  (CheckId Value 6, DeltaPlatformCert) -> MustNot

  -- DLT-005: notAfter should not precede base
  (CheckId Delta 5, DeltaPlatformCert) -> ShouldNot

  -- Default: MUST for all other checks
  _ -> Must
