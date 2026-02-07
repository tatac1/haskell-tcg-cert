{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Internal
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Internal types and utilities shared between compliance modules.
-- This module exists to break cyclic dependencies.

module Data.X509.TCG.Compliance.Internal
  ( -- * Compliance Check Type
    ComplianceCheck

    -- * Utilities
  , lookupRef
  ) where

import Data.Maybe (fromMaybe)

import Data.X509.TCG.Platform (SignedPlatformCertificate)

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result (CheckResult)

-- | A compliance check function
-- Takes a certificate and reference database, returns a check result
type ComplianceCheck = SignedPlatformCertificate -> ReferenceDB -> IO CheckResult

-- | Lookup a reference from the database with a default fallback
lookupRef :: CheckId -> ReferenceDB -> SpecReference
lookupRef cid db = fromMaybe defaultRef (lookupReference cid db)
  where
    defaultRef = SpecReference IWGProfile "Unknown" "Unknown" Nothing Must Nothing
