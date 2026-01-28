{-# LANGUAGE DeriveGeneric #-}

-- |
-- Module      : Data.X509.TCG.Validation.Types
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Validation Library
-- Stability   : experimental
-- Portability : unknown
--
-- Validation error types for TCG Platform Certificates.
-- This module defines comprehensive error types for validation failures
-- that can occur during Platform Certificate and Delta Certificate validation.
module Data.X509.TCG.Validation.Types
  ( -- * Validation Error Types
    ValidationError (..),
    FailureReason (..),
    SignatureValidationError (..),
    ValidationResult,
    
    -- * Service Identification
    TCGServiceID,
    PlatformID,
  )
where

import Data.ByteString (ByteString)
import GHC.Generics (Generic)

-- | Platform identification type for TCG certificates
-- Consists of platform identifier and optional service suffix
type PlatformID = String

-- | Service identification for TCG validation context
-- Similar to ServiceID in x509-validation but specialized for Platform Certificates
-- The suffix can be used to distinguish different certificate contexts on the same platform
type TCGServiceID = (PlatformID, ByteString)

-- | Comprehensive validation error type for TCG Platform Certificates
--
-- This type covers all validation errors that can occur during
-- Platform Certificate and Delta Certificate validation process.
data ValidationError
  = -- | Certificate signature validation failed
    SignatureError String
  | -- | Required attribute missing or invalid
    AttributeError String
  | -- | Component hierarchy validation failed
    HierarchyError String
  | -- | Cross-certificate consistency check failed
    ConsistencyError String
  | -- | TCG specification compliance violation
    ComplianceError String
  | -- | Certificate format validation failed
    FormatError String
  | -- | Certificate validity period validation failed
    ValidityError String
  | -- | Issuer validation failed
    IssuerError String
  | -- | Chain validation failed
    ChainError String
  | -- | Cache validation failed
    CacheError String
  deriving (Show, Eq, Generic)

-- | Specific failure reasons for certificate validation
--
-- These are more granular failure reasons that can be mapped
-- to ValidationError types for detailed error reporting.
data FailureReason
  = -- | Digital signature verification failed
    InvalidSignature
  | -- | Certificate validity period expired
    ExpiredCertificate
  | -- | Certificate is not yet valid
    InFutureCertificate
  | -- | Issuer information invalid or cannot be verified
    InvalidIssuer
  | -- | Unknown Certificate Authority
    UnknownCA
  | -- | Certificate chain is empty
    EmptyChain
  | -- | Self-signed certificate in non-trusted context
    SelfSigned
  | -- | Required attribute not present
    MissingRequiredAttribute
  | -- | Attribute value does not conform to specification
    InvalidAttributeValue
  | -- | Component information inconsistent
    InconsistentComponentData
  | -- | Component hierarchy structure invalid
    InvalidHierarchyStructure
  | -- | Duplicate component addresses found
    DuplicateComponentAddresses
  | -- | Delta certificate references invalid base certificate
    InvalidBaseCertificateReference
  | -- | Delta operations are inconsistent or invalid
    InvalidDeltaOperations
  | -- | Certificate chain consistency check failed
    ChainInconsistency
  | -- | Platform configuration is invalid
    InvalidPlatformConfiguration
  | -- | TPM information is invalid
    InvalidTPMInformation
  | -- | Certificate version is not supported
    UnsupportedCertificateVersion
  | -- | Cache explicitly denied this certificate
    CacheDenied String
  | -- | Unknown critical extension in certificate
    UnknownCriticalExtension
  | -- | Certificate authority constraints violation
    CAConstraintsViolation
  | -- | Component class validation failed
    InvalidComponentClass
  | -- | Certificate serial number is invalid
    InvalidSerialNumber
  deriving (Show, Eq, Generic)

-- | Signature validation error types for low-level signature operations
data SignatureValidationError
  = -- | Signature verification failed cryptographically
    SignatureVerificationFailed String
  | -- | Signature algorithm not supported
    UnsupportedSignatureAlgorithm String  
  | -- | Signature algorithm too weak for security policy
    WeakSignatureAlgorithm String
  | -- | Missing trusted root for signature verification
    MissingTrustedRoot String
  deriving (Show, Eq, Generic)

-- | Result type for validation operations
type ValidationResult = Either [SignatureValidationError] ()