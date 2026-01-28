{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Validation
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Library
-- Stability   : experimental
-- Portability : unknown
--
-- Basic validation functions for TCG Platform Certificates.
-- 
-- NOTE: This module has been deprecated in favor of the separate
-- tcg-platform-cert-validation package. For full validation functionality,
-- use Data.X509.TCG.Validation from tcg-platform-cert-validation instead.
module Data.X509.TCG.Validation
  ( -- * Deprecated - Use tcg-platform-cert-validation instead
    -- | These functions are maintained for backward compatibility only.
    -- For full validation capabilities, use the tcg-platform-cert-validation package.
    
    -- * Basic Error Types (Deprecated)
    ValidationError (..),
    FailureReason (..),
  )
where

-- * Deprecated Error Types

-- | Comprehensive validation error type
-- DEPRECATED: Use ValidationError from Data.X509.TCG.Validation.Types 
-- in tcg-platform-cert-validation package instead.
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
  deriving (Show, Eq)
  
{-# DEPRECATED ValidationError "Use Data.X509.TCG.Validation.Types.ValidationError from tcg-platform-cert-validation package instead" #-}

-- | Specific failure reasons for certificate validation
-- DEPRECATED: Use FailureReason from Data.X509.TCG.Validation.Types
-- in tcg-platform-cert-validation package instead.
data FailureReason
  = -- | Digital signature verification failed
    InvalidSignature
  | -- | Certificate validity period expired
    ExpiredCertificate
  | -- | Issuer information invalid
    InvalidIssuer
  | -- | Required attribute not present
    MissingRequiredAttribute
  | -- | Attribute value does not conform to specification
    InvalidAttributeValue
  | -- | Component information inconsistent
    InconsistentComponentData
  deriving (Show, Eq)
  
{-# DEPRECATED FailureReason "Use Data.X509.TCG.Validation.Types.FailureReason from tcg-platform-cert-validation package instead" #-}

-- All validation functions have been moved to tcg-platform-cert-validation package.
-- This file now only contains deprecated type definitions for backward compatibility.
