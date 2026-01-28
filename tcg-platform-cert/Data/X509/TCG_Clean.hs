
-- |
-- Module      : Data.X509.TCG
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Library
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Platform Certificate Library - Main API Module
--
-- This module provides the complete API for working with TCG Platform Certificates
-- and Delta Platform Certificates as defined in the TCG Platform Certificate Profile.
--
-- = Quick Start
--
-- For basic platform certificate operations:
--
-- @
-- import Data.X509.TCG
--
-- -- Extract platform configuration
-- case getPlatformConfiguration cert of
--   Just config -> processPlatformInfo config
--   Nothing -> handleError "No platform configuration"
--
-- -- Validate certificate
-- case validatePlatformCertificate cert of
--   [] -> putStrLn "Certificate is valid"
--   errors -> mapM_ print errors
-- @
--
-- = Module Organization
--
-- This library is organized into focused modules:
--
-- * "Data.X509.TCG.Platform" - Platform Certificate types and operations
-- * "Data.X509.TCG.Delta" - Delta Platform Certificate support  
-- * "Data.X509.TCG.Component" - Component identification and hierarchy
-- * "Data.X509.TCG.Attributes" - TCG attribute parsing and validation
-- * "Data.X509.TCG.OID" - TCG OID definitions
-- * "Data.X509.TCG.Operations" - High-level certificate operations
-- * "Data.X509.TCG.Validation" - Certificate validation functions
-- * "Data.X509.TCG.Utils" - Utility functions and helpers
-- * "Data.X509.TCG.Types" - Common types and error handling

module Data.X509.TCG
  ( -- * Platform Certificate Types
    -- ** Basic Certificate Types
    PlatformCertificateInfo(..),
    SignedPlatformCertificate,
    
    -- ** Platform Configuration
    PlatformConfiguration(..),
    PlatformConfigurationV2(..),
    PlatformInfo(..),
    
    -- ** TPM Information
    TPMInfo(..),
    TPMVersion(..),
    TPMSpecification(..),
    
    -- * Delta Platform Certificate Types
    DeltaPlatformCertificateInfo(..),
    SignedDeltaPlatformCertificate,
    PlatformConfigurationDelta(..),
    BasePlatformCertificateRef(..),
    
    -- * Component Types
    ComponentIdentifier(..),
    ComponentIdentifierV2(..),
    ComponentClass(..),
    ComponentStatus(..),
    ComponentAddress(..),
    
    -- * Attribute Types  
    TCGAttribute(..),
    
    -- * High-Level Operations
    -- ** Certificate Creation
    createPlatformCertificate,
    createDeltaPlatformCertificate,
    
    -- ** Certificate Validation
    validatePlatformCertificate,
    validateDeltaCertificate,
    validateCertificateChain,
    
    -- ** Configuration Management
    getCurrentPlatformConfiguration,
    applyDeltaCertificate,
    computeConfigurationChain,
    
    -- ** Component Operations
    getComponentIdentifiers,
    getComponentIdentifiersV2,
    findComponentByClass,
    findComponentByAddress,
    buildComponentHierarchy,
    
    -- ** Certificate Chain Operations
    buildCertificateChain,
    findBaseCertificate,
    
    -- * Validation Functions
    -- ** Certificate Validation
    ValidationError(..),
    FailureReason(..),
    validateAttributeCompliance,
    validateComponentHierarchy,
    validateComponentStatus,
    
    -- * Attribute Processing
    -- ** Attribute Parsing
    parseTCGAttribute,
    encodeTCGAttribute,
    
    -- ** Attribute Lookup
    lookupTCGAttribute,
    extractTCGAttributes,
    
    -- ** Attribute Validation
    validateTCGAttributes,
    isRequiredAttribute,
    isCriticalAttribute,
    
    -- * Utility Functions
    -- ** Certificate Type Utilities
    isPlatformCertificate,
    isDeltaCertificate,
    
    -- ** Component Utilities
    ComponentTree(..),
    buildComponentTree,
    
    -- ** Conversion Utilities
    upgradeComponentToV2,
    downgradeComponentFromV2,
    
    -- ** Error Handling
    TCGError(..),
    TCGResult,
    ValidationResult,
    formatError,
    combineErrors,
    validateAll,
    
    -- * OID Definitions
    -- ** Platform Attribute OIDs
    tcg_at_platformConfiguration,
    tcg_at_platformConfiguration_v2,
    tcg_at_componentIdentifier,
    tcg_at_componentIdentifier_v2,
    tcg_at_platformManufacturer,
    tcg_at_platformModel,
    tcg_at_platformSerial,
    tcg_at_platformVersion,
    
    -- ** TPM Attribute OIDs
    tcg_at_tpmModel,
    tcg_at_tpmVersion,
    tcg_at_tpmSpecification,
    
    -- ** Component Class OIDs
    tcg_class_motherboard,
    tcg_class_cpu,
    tcg_class_memory,
    
    -- * Re-exported from Base Libraries
    -- ** ASN.1 Types (commonly used)
    OID,
    ASN1(..),
    
    -- ** X.509 Types (commonly used)
    Attributes,
    Attribute(..),
  ) where

-- Platform Certificate core functionality
import Data.X509.TCG.Platform
import Data.X509.TCG.Delta

-- Component identification and management  
import Data.X509.TCG.Component

-- Attribute processing
import Data.X509.TCG.Attributes

-- OID definitions
import Data.X509.TCG.OID

-- High-level operations (new modular approach)
import Data.X509.TCG.Operations

-- Validation functions (new modular approach)
import Data.X509.TCG.Validation

-- Utility functions (new modular approach)
import Data.X509.TCG.Utils

-- Common types and error handling (new)
import Data.X509.TCG.Types

-- Re-exports from base libraries for convenience
import Data.ASN1.Types (OID, ASN1(..))
import Data.X509.Attribute (Attributes, Attribute(..))

{-
Note: This refactored module provides a clean, well-organized API
while maintaining backward compatibility. The implementation has been
distributed across focused modules for better maintainability:

* Operations module - High-level certificate operations
* Validation module - Comprehensive validation functions  
* Utils module - Common utilities and helpers
* Types module - Consistent error handling and common types

The registry-based attribute parsing and bidirectional component mappings
improve code maintainability and extensibility.
-}