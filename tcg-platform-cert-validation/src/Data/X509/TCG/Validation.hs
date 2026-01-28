{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Validation
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Validation Library
-- Stability   : experimental
-- Portability : unknown
--
-- Validation functions for TCG Platform Certificates.
-- This module provides comprehensive validation of Platform and Delta
-- Platform Certificates according to TCG specifications.
--
-- This module follows the design pattern of crypton-x509-validation,
-- providing a complete validation framework for TCG Platform Certificates.
module Data.X509.TCG.Validation
  ( -- * Main Validation Functions
    validatePlatformCertificate,
    validateDeltaCertificate,
    validateCertificateChain,

    -- * High-level Validation API
    validatePlatformCertificateWithCache,
    validateDefault,

    -- * Attribute and Component Validation
    validateRequiredAttributes,
    validateAttributeCompliance,
    validateComponentHierarchy,
    validateComponentStatus,

    -- * Re-exported Types
    module Data.X509.TCG.Validation.Types,
    module Data.X509.TCG.Validation.Cache,
  )
where

import Data.X509.TCG hiding (validateAttributeCompliance, validateCertificateChain, validateComponentHierarchy, validateDeltaCertificate, validatePlatformCertificate)
import Data.X509.TCG.Validation.Cache
import qualified Data.X509.TCG.Validation.Internal as Internal
import Data.X509.TCG.Validation.Types
import Data.X509AC (Attributes (..))

-- * Main Validation Functions

-- | Validate a Platform Certificate for compliance and consistency
--
-- This function performs comprehensive validation including:
-- * Digital signature verification
-- * Validity period checking
-- * Required attribute presence
-- * Component hierarchy consistency
-- * TCG specification compliance
--
-- Example:
-- @
-- case validatePlatformCertificate cert of
--   [] -> putStrLn "Certificate is valid"
--   errors -> mapM_ (putStrLn . show) errors
-- @
validatePlatformCertificate :: SignedPlatformCertificate -> [ValidationError]
validatePlatformCertificate cert =
  concat
    [ Internal.validateCertificateStructure cert,
      Internal.validateRequiredPlatformAttributes (pciAttributes $ getPlatformCertificate cert),
      Internal.validateComponentConsistency cert,
      Internal.validateSpecificationCompliance cert
    ]

-- | Validate a Delta Platform Certificate
--
-- Delta certificate validation includes all standard validation plus:
-- * Base certificate reference validation
-- * Delta operation consistency
-- * Change sequence validation
validateDeltaCertificate :: SignedDeltaPlatformCertificate -> [ValidationError]
validateDeltaCertificate deltaCert =
  let deltaInfo = getDeltaPlatformCertificate deltaCert
      baseRef = dpciBaseCertificateRef deltaInfo
   in concat
        [ Internal.validateBaseCertificateReference baseRef,
          Internal.validateDeltaAttributesValidation (dpciAttributes deltaInfo),
          Internal.validateDeltaOperations deltaCert
        ]

-- | Validate an entire certificate chain for consistency
--
-- Chain validation ensures that:
-- * All certificates are individually valid
-- * Delta certificates properly reference their base
-- * Configuration changes are applied correctly
-- * No conflicting operations exist
validateCertificateChain ::
  -- | Base certificate
  SignedPlatformCertificate ->
  -- | Delta chain
  [SignedDeltaPlatformCertificate] ->
  [ValidationError]
validateCertificateChain baseCert deltaChain =
  concat
    [ validatePlatformCertificate baseCert,
      concatMap validateDeltaCertificate deltaChain,
      Internal.validateChainConsistency baseCert deltaChain
    ]

-- * High-level Validation API

-- | Validate a Platform Certificate with caching support
--
-- This function provides caching functionality similar to crypton-x509-validation's
-- validate function, allowing for efficient repeated validation of certificates.
validatePlatformCertificateWithCache ::
  -- | Validation cache
  TCGValidationCache ->
  -- | Service/Platform identification
  TCGServiceID ->
  -- | Certificate to validate
  SignedPlatformCertificate ->
  IO [ValidationError]
validatePlatformCertificateWithCache cache serviceId cert = do
  let certEither = Left cert
      fingerprint = getTCGFingerprint certEither

  -- Query cache first
  cacheResult <- tcgCacheQuery cache serviceId fingerprint certEither

  case cacheResult of
    TCGValidationCachePass ->
      return [] -- Certificate passed cache validation
    TCGValidationCacheDenied reason ->
      return [CacheError reason] -- Cache explicitly denied
    TCGValidationCacheUnknown -> do
      -- Perform full validation
      let validationErrors = validatePlatformCertificate cert

      -- Add to cache if validation passed
      if null validationErrors
        then tcgCacheAdd cache serviceId fingerprint certEither
        else return ()

      return validationErrors

-- | Validate using default settings (no caching)
--
-- This function provides a simple validation interface similar to
-- crypton-x509-validation's validateDefault function.
validateDefault :: SignedPlatformCertificate -> [ValidationError]
validateDefault = validatePlatformCertificate

-- * Re-exported Validation Functions

-- | Validate that all required attributes are present and valid
--
-- According to TCG Platform Certificate Profile, certain attributes
-- are mandatory for different certificate types.
validateRequiredAttributes :: Attributes -> [ValidationError]
validateRequiredAttributes = Internal.validateRequiredPlatformAttributes

-- | Validate attribute values for specification compliance
--
-- This function checks that attribute values conform to their
-- expected formats and constraints as defined in the TCG specification.
validateAttributeCompliance :: Attributes -> [ValidationError]
validateAttributeCompliance = Internal.validateAttributeCompliance

-- | Validate component hierarchy for logical consistency
--
-- Component hierarchy validation ensures that:
-- * Parent-child relationships are valid
-- * No circular dependencies exist
-- * Component addresses are unique where specified
validateComponentHierarchy :: [ComponentIdentifierV2] -> [ValidationError]
validateComponentHierarchy = Internal.validateComponentHierarchy

-- | Validate component status information consistency
--
-- Status validation ensures that component states are logically
-- consistent with the operations described in delta certificates.
validateComponentStatus :: [(ComponentIdentifierV2, ComponentStatus)] -> [ValidationError]
validateComponentStatus = Internal.validateComponentStatus