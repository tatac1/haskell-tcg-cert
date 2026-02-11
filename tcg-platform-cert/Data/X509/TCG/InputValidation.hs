{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.InputValidation
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Library
-- Stability   : experimental
-- Portability : unknown
--
-- Input validation functions for TCG Platform Certificate types.
-- These functions reject invalid inputs before they reach the encoding layer,
-- preventing generation of non-compliant certificates.
--
-- Validation covers IWG Platform Certificate Profile v1.1 constraints:
-- field ranges (EAL 1-7, FIPS 1-4, etc.), STRMAX (255 bytes),
-- structural consistency (CC/FIPS version pairing), and URIMAX (1024 bytes).
module Data.X509.TCG.InputValidation
  ( validateTBBSecurityAssertions
  , validateComponentConfigV2
  , validateExtendedTCGAttributes
  ) where

import Control.Monad (when, forM_)
import qualified Data.ByteString as B
import Data.X509.TCG
  ( TBBSecurityAssertions(..)
  , ComponentConfigV2(..)
  , ExtendedTCGAttributes(..)
  , PlatformConfigUri(..)
  )

-- | Maximum string length per IWG Profile v1.1
strmax :: Int
strmax = 255

-- | Maximum URI length per IWG Profile v1.1
urimax :: Int
urimax = 1024

-- | Validate TBBSecurityAssertions field constraints.
--
-- Checks:
--
-- * @tbbVersion@: must be 0 or 1 (RFC 5755 AttCertVersion)
-- * @tbbEvalAssuranceLevel@: 1-7 if present (IWG §3.1.1), requires @tbbCCVersion@
-- * @tbbEvalStatus@: 0-2 if present (designedToMeet=0, inProgress=1, completed=2)
-- * @tbbStrengthOfFunction@: 0-2 if present (basic=0, medium=1, high=2)
-- * @tbbFIPSSecurityLevel@: 1-4 if present (IWG §3.1.1), requires @tbbFIPSVersion@
-- * @tbbRTMType@: 0-5 if present (static=0 .. virtual=5, SEC-003)
-- * String fields: 1-255 bytes when present (STRMAX)
validateTBBSecurityAssertions :: TBBSecurityAssertions -> Either String ()
validateTBBSecurityAssertions tbb = do
  -- Version: 0 (v1, default) or 1
  when (tbbVersion tbb < 0 || tbbVersion tbb > 1) $
    Left $ "TBBSecurityAssertions version must be 0 or 1, got: " ++ show (tbbVersion tbb)

  -- Common Criteria EAL: 1-7, requires ccVersion
  case tbbEvalAssuranceLevel tbb of
    Nothing -> return ()
    Just eal -> do
      when (eal < 1 || eal > 7) $
        Left $ "EvalAssuranceLevel must be in range 1-7, got: " ++ show eal
      case tbbCCVersion tbb of
        Nothing -> Left "ccVersion is required when evalAssuranceLevel is set"
        Just v -> when (B.null v || B.length v > strmax) $
          Left $ "ccVersion must be 1-" ++ show strmax ++ " bytes"

  -- EvalStatus: 0-2 (IWG Task 7)
  case tbbEvalStatus tbb of
    Nothing -> return ()
    Just s -> when (s < 0 || s > 2) $
      Left $ "EvalStatus must be in range 0-2, got: " ++ show s

  -- StrengthOfFunction: 0-2
  case tbbStrengthOfFunction tbb of
    Nothing -> return ()
    Just sof -> when (sof < 0 || sof > 2) $
      Left $ "StrengthOfFunction must be in range 0-2, got: " ++ show sof

  -- FIPS Security Level: 1-4, requires fipsVersion
  case tbbFIPSSecurityLevel tbb of
    Nothing -> return ()
    Just level -> do
      when (level < 1 || level > 4) $
        Left $ "FIPSSecurityLevel must be in range 1-4, got: " ++ show level
      case tbbFIPSVersion tbb of
        Nothing -> Left "fipsVersion is required when fipsSecurityLevel is set"
        Just v -> when (B.null v || B.length v > strmax) $
          Left $ "fipsVersion must be 1-" ++ show strmax ++ " bytes"

  -- RTM Type: 0-5 (static=0, dynamic=1, nonHosted=2, hybrid=3, physical=4, virtual=5)
  case tbbRTMType tbb of
    Nothing -> return ()
    Just rtm -> when (rtm < 0 || rtm > 5) $
      Left $ "RTMType must be in range 0-5, got: " ++ show rtm

-- | Validate ComponentConfigV2 field constraints.
--
-- Checks:
--
-- * @ccv2Class@: exactly 4 bytes (VAL-013)
-- * @ccv2Manufacturer@: 1-255 bytes (VAL-001, STRMAX)
-- * @ccv2Model@: 1-255 bytes (VAL-002, STRMAX)
-- * @ccv2Serial@: 1-255 bytes if present (STRMAX)
-- * @ccv2Revision@: 1-255 bytes if present (STRMAX)
validateComponentConfigV2 :: ComponentConfigV2 -> Either String ()
validateComponentConfigV2 comp = do
  -- Class: exactly 4 bytes
  let classLen = B.length (ccv2Class comp)
  when (classLen /= 4) $
    Left $ "componentClassValue must be exactly 4 bytes, got: " ++ show classLen

  -- Manufacturer: 1-255 bytes
  when (B.null (ccv2Manufacturer comp)) $
    Left "Component manufacturer cannot be empty"
  when (B.length (ccv2Manufacturer comp) > strmax) $
    Left $ "Component manufacturer exceeds STRMAX (" ++ show strmax ++ " bytes)"

  -- Model: 1-255 bytes
  when (B.null (ccv2Model comp)) $
    Left "Component model cannot be empty"
  when (B.length (ccv2Model comp) > strmax) $
    Left $ "Component model exceeds STRMAX (" ++ show strmax ++ " bytes)"

  -- Serial: 1-255 bytes if present
  case ccv2Serial comp of
    Just s -> when (B.null s || B.length s > strmax) $
      Left $ "Component serial must be 1-" ++ show strmax ++ " bytes when present"
    Nothing -> return ()

  -- Revision: 1-255 bytes if present
  case ccv2Revision comp of
    Just r -> when (B.null r || B.length r > strmax) $
      Left $ "Component revision must be 1-" ++ show strmax ++ " bytes when present"
    Nothing -> return ()

-- | Validate ExtendedTCGAttributes field constraints.
--
-- Delegates to 'validateTBBSecurityAssertions' and 'validateComponentConfigV2'
-- for nested types, and checks URI/hash pair consistency.
validateExtendedTCGAttributes :: ExtendedTCGAttributes -> Either String ()
validateExtendedTCGAttributes eta = do
  -- Validate TBB Security Assertions if present
  case etaSecurityAssertions eta of
    Just tbb -> validateTBBSecurityAssertions tbb
    Nothing -> return ()

  -- Validate each ComponentConfigV2 if present
  case etaComponentsV2 eta of
    Just comps -> forM_ (zip [1 :: Int ..] comps) $ \(i, comp) ->
      case validateComponentConfigV2 comp of
        Left err -> Left $ "Component " ++ show i ++ ": " ++ err
        Right () -> return ()
    Nothing -> return ()

  -- Validate Platform Config URI if present
  case etaPlatformConfigUri eta of
    Just uri -> do
      let uriLen = B.length (pcUri uri)
      when (uriLen < 1 || uriLen > urimax) $
        Left $ "platformConfigUri must be 1-" ++ show urimax ++ " bytes, got: " ++ show uriLen
      -- Hash pair consistency: both present or both absent
      case (pcHashAlgorithm uri, pcHashValue uri) of
        (Just _, Nothing) -> Left "hashAlgorithm is set but hashValue is missing"
        (Nothing, Just _) -> Left "hashValue is set but hashAlgorithm is missing"
        _ -> return ()
    Nothing -> return ()

  -- Validate version tuples if present (non-negative)
  case etaCredentialSpecVersion eta of
    Just (major, minor, rev) -> do
      when (major < 0 || minor < 0 || rev < 0) $
        Left "credentialSpecVersion components must be non-negative"
    Nothing -> return ()

  case etaPlatformSpecVersion eta of
    Just (major, minor, rev) -> do
      when (major < 0 || minor < 0 || rev < 0) $
        Left "platformSpecVersion components must be non-negative"
    Nothing -> return ()
