{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Platform Certificate Compliance Testing Framework.
--
-- This module provides a comprehensive compliance testing framework for
-- TCG Platform Certificates per IWG Platform Certificate Profile v1.1.
--
-- = Overview
--
-- The compliance test framework validates Platform Certificates against
-- the IWG Platform Certificate Profile specification. It provides:
--
-- * 66 compliance checks with specification traceability
-- * Support for both Base and Delta Platform Certificates
-- * SBV-based formal verification of constraints
-- * Multiple output formats (Text, JSON, XML)
--
-- = Example Usage
--
-- @
-- import Data.X509.TCG.Compliance
-- import Data.X509.TCG.Platform
--
-- main :: IO ()
-- main = do
--   cert <- loadCertificate "platform.pem"
--   result <- runComplianceTest cert defaultComplianceOptions
--   print $ resCompliant result
-- @

module Data.X509.TCG.Compliance
  ( -- * Check Types
    module Data.X509.TCG.Compliance.Types

    -- * Specification References
  , module Data.X509.TCG.Compliance.Reference

    -- * Result Types
  , module Data.X509.TCG.Compliance.Result

    -- * Check Execution
  , module Data.X509.TCG.Compliance.Check

    -- * Individual Check Modules
  , module Data.X509.TCG.Compliance.Structural
  , module Data.X509.TCG.Compliance.Value
  , module Data.X509.TCG.Compliance.Delta
  , module Data.X509.TCG.Compliance.Extension
  , module Data.X509.TCG.Compliance.Security
  , module Data.X509.TCG.Compliance.Errata
  , module Data.X509.TCG.Compliance.Chain
  , module Data.X509.TCG.Compliance.Registry

    -- * Suggestions
  , module Data.X509.TCG.Compliance.Suggestion

    -- * Chain Compliance
  , module Data.X509.TCG.Compliance.ChainCompliance
  ) where

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Check
import Data.X509.TCG.Compliance.Structural
import Data.X509.TCG.Compliance.Value
import Data.X509.TCG.Compliance.Delta
import Data.X509.TCG.Compliance.Extension
import Data.X509.TCG.Compliance.Security
import Data.X509.TCG.Compliance.Errata
import Data.X509.TCG.Compliance.Chain
import Data.X509.TCG.Compliance.Registry
import Data.X509.TCG.Compliance.Suggestion
import Data.X509.TCG.Compliance.ChainCompliance
