{-# LANGUAGE DeriveGeneric #-}

-- |
-- Module      : Data.X509.TCG.Types
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Library
-- Stability   : experimental
-- Portability : unknown
--
-- Common types and error handling for TCG Platform Certificates.
-- This module provides shared type definitions and consistent error
-- handling patterns used throughout the TCG library.

module Data.X509.TCG.Types
  ( -- * Error Types
    TCGError(..),
    ValidationError(..),
    ParseError(..),
    
    -- * Result Types
    TCGResult,
    ValidationResult,
    
    -- * Utility Functions
    formatError,
    combineErrors,
    validateAll,
    
    -- * Common Type Aliases
    OIDString,
    SerialNumber,
  ) where

import GHC.Generics (Generic)

-- * Error Types

-- | Comprehensive error type for TCG Platform Certificate operations
--
-- This type provides a unified error handling approach across all
-- TCG library functions, making error handling consistent and predictable.
data TCGError
  = -- | ASN.1 parsing or encoding failed
    TCGParseError String
    
  | -- | Certificate validation failed  
    TCGValidationError [ValidationError]
    
  | -- | Platform configuration operation failed
    TCGConfigurationError String
    
  | -- | Component operation failed
    TCGComponentError String
    
  | -- | Attribute processing failed
    TCGAttributeError String
    
  | -- | Feature not yet implemented
    TCGNotImplemented String
    
  | -- | Internal library error (should not occur in normal operation)
    TCGInternalError String
    
  deriving (Show, Eq, Generic)

-- | Specific validation errors for certificate validation
--
-- These errors provide detailed information about what aspect
-- of certificate validation failed.
data ValidationError
  = -- | Digital signature verification failed
    SignatureValidationError String
    
  | -- | Certificate has expired or is not yet valid
    ValidityPeriodError String
    
  | -- | Required attribute is missing
    MissingRequiredAttribute String
    
  | -- | Attribute value is invalid or malformed
    InvalidAttributeValue String String  -- ^ attribute name, error description
    
  | -- | Component hierarchy is inconsistent
    ComponentHierarchyError String
    
  | -- | Certificate chain validation failed
    ChainValidationError String
    
  | -- | TCG specification compliance violation
    ComplianceError String
    
  deriving (Show, Eq, Generic)

-- | Specific parsing errors for ASN.1 operations
--
-- These errors provide detailed context about parsing failures.
data ParseError
  = -- | ASN.1 structure is malformed
    MalformedASN1 String
    
  | -- | Required ASN.1 field is missing
    MissingRequiredField String
    
  | -- | ASN.1 field has unexpected type
    UnexpectedFieldType String String  -- ^ field name, expected type
    
  | -- | ASN.1 sequence has incorrect length
    IncorrectSequenceLength String Int Int  -- ^ context, expected, actual
    
  deriving (Show, Eq, Generic)

-- * Result Types

-- | Standard result type for TCG operations
type TCGResult a = Either TCGError a

-- | Standard result type for validation operations
type ValidationResult = Either [ValidationError] ()

-- * Utility Functions

-- | Format error messages for user-friendly display
--
-- This function converts any TCGError into a readable string suitable
-- for logging, debugging, or user presentation.
--
-- Example:
-- @
-- case tcgOperation of
--   Left err -> putStrLn $ "Error: " ++ formatError err
--   Right result -> processResult result
-- @
formatError :: TCGError -> String
formatError err = case err of
  TCGParseError msg -> 
    "Parse error: " ++ msg
  TCGValidationError validationErrors ->
    "Validation failed:\n" ++ unlines (map formatValidationError validationErrors)
  TCGConfigurationError msg ->
    "Configuration error: " ++ msg
  TCGComponentError msg ->
    "Component error: " ++ msg
  TCGAttributeError msg ->
    "Attribute error: " ++ msg
  TCGNotImplemented feature ->
    "Feature not implemented: " ++ feature
  TCGInternalError msg ->
    "Internal error: " ++ msg ++ " (please report this bug)"

-- | Format validation error for display
formatValidationError :: ValidationError -> String
formatValidationError err = case err of
  SignatureValidationError msg ->
    "  - Signature validation: " ++ msg
  ValidityPeriodError msg ->
    "  - Validity period: " ++ msg
  MissingRequiredAttribute attr ->
    "  - Missing required attribute: " ++ attr
  InvalidAttributeValue attr msg ->
    "  - Invalid attribute '" ++ attr ++ "': " ++ msg
  ComponentHierarchyError msg ->
    "  - Component hierarchy: " ++ msg
  ChainValidationError msg ->
    "  - Certificate chain: " ++ msg
  ComplianceError msg ->
    "  - Specification compliance: " ++ msg

-- | Combine multiple TCG errors into a single error
--
-- This function is useful when collecting errors from multiple operations
-- and presenting them as a unified result.
combineErrors :: [TCGError] -> TCGError
combineErrors [] = TCGInternalError "No errors to combine"
combineErrors [err] = err
combineErrors errs = 
  TCGValidationError $ concatMap extractValidationErrors errs
  where
    extractValidationErrors :: TCGError -> [ValidationError]
    extractValidationErrors (TCGValidationError validationErrs) = validationErrs
    extractValidationErrors otherErr = [ComplianceError $ formatError otherErr]

-- | Validate multiple items and collect all errors
--
-- This function applies a validation function to a list of items
-- and collects all validation errors, providing comprehensive feedback.
--
-- Example:
-- @
-- case validateAll validateCertificate certificates of
--   Right () -> putStrLn "All certificates are valid"
--   Left errors -> mapM_ (putStrLn . formatError) errors
-- @
validateAll :: (a -> TCGResult ()) -> [a] -> TCGResult ()
validateAll validator items = 
  case concatMap getErrors (map validator items) of
    [] -> Right ()
    errors -> Left (combineErrors errors)
  where
    getErrors (Right ()) = []
    getErrors (Left err) = [err]

-- * Common Type Aliases

-- | OID represented as a string for convenience
type OIDString = String

-- | Certificate serial number type
type SerialNumber = Integer