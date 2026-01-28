{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# OPTIONS_GHC -fno-warn-unused-top-binds #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- |
-- Arbitrary instances for QuickCheck property-based testing.
-- This module provides Arbitrary instances for all types used in validation testing.

module Tests.Arbitrary () where

import Test.QuickCheck
import Test.QuickCheck.Instances ()

import qualified Data.ByteString as B
import Data.ByteString (ByteString)

import Data.X509.TCG.Validation.Types
import Data.X509.TCG.Validation.Cache

-- * Arbitrary instances for ValidationError

instance Arbitrary ValidationError where
  arbitrary = oneof
    [ SignatureError <$> arbitrary
    , AttributeError <$> arbitrary  
    , HierarchyError <$> arbitrary
    , ConsistencyError <$> arbitrary
    , ComplianceError <$> arbitrary
    , FormatError <$> arbitrary
    , ValidityError <$> arbitrary
    , IssuerError <$> arbitrary
    , ChainError <$> arbitrary
    , CacheError <$> arbitrary
    ]

  shrink (SignatureError s) = [SignatureError s' | s' <- shrink s]
  shrink (AttributeError s) = [AttributeError s' | s' <- shrink s]
  shrink (HierarchyError s) = [HierarchyError s' | s' <- shrink s]
  shrink (ConsistencyError s) = [ConsistencyError s' | s' <- shrink s]
  shrink (ComplianceError s) = [ComplianceError s' | s' <- shrink s]
  shrink (FormatError s) = [FormatError s' | s' <- shrink s]
  shrink (ValidityError s) = [ValidityError s' | s' <- shrink s]
  shrink (IssuerError s) = [IssuerError s' | s' <- shrink s]
  shrink (ChainError s) = [ChainError s' | s' <- shrink s]
  shrink (CacheError s) = [CacheError s' | s' <- shrink s]

-- * Arbitrary instances for FailureReason  

instance Arbitrary FailureReason where
  arbitrary = oneof
    [ pure InvalidSignature
    , pure ExpiredCertificate
    , pure InFutureCertificate
    , pure InvalidIssuer
    , pure UnknownCA
    , pure EmptyChain
    , pure SelfSigned
    , pure MissingRequiredAttribute
    , pure InvalidAttributeValue
    , pure InconsistentComponentData
    , pure InvalidHierarchyStructure
    , pure DuplicateComponentAddresses
    , pure InvalidBaseCertificateReference
    , pure InvalidDeltaOperations
    , pure ChainInconsistency
    , pure InvalidPlatformConfiguration
    , pure InvalidTPMInformation
    , pure UnsupportedCertificateVersion
    , CacheDenied <$> arbitrary
    , pure UnknownCriticalExtension
    , pure CAConstraintsViolation
    , pure InvalidComponentClass
    , pure InvalidSerialNumber
    ]

  shrink (CacheDenied s) = [CacheDenied s' | s' <- shrink s]
  shrink _ = []

-- * Arbitrary instances for Cache types

instance Arbitrary TCGFingerprint where
  arbitrary = do
    -- Generate a reasonable fingerprint-like byte string (32 bytes for SHA256)
    size <- choose (8, 64) 
    bytes <- vectorOf size arbitrary
    return $ TCGFingerprint $ B.pack bytes
    
  shrink (TCGFingerprint bs) = 
    [TCGFingerprint bs' | bs' <- shrinkByteString bs, not (B.null bs')]

instance Arbitrary TCGValidationCacheResult where
  arbitrary = oneof
    [ pure TCGValidationCachePass
    , TCGValidationCacheDenied <$> arbitrary
    , pure TCGValidationCacheUnknown
    ]
    
  shrink (TCGValidationCacheDenied s) = [TCGValidationCacheDenied s' | s' <- shrink s]
  shrink _ = []

-- * Arbitrary instances for service identification

-- Note: TCGServiceID is a type alias for (PlatformID, ByteString)
-- The tuple instance from QuickCheck already provides Arbitrary, so no custom instance needed

-- * Helper generators

-- | Generate a realistic platform ID
genPlatformId :: Gen PlatformID
genPlatformId = oneof
  [ return "test-platform"
  , return "enterprise-workstation" 
  , return "embedded-device"
  , return "server-node"
  , elements ["platform-" ++ show n | n <- [1..100::Int]]
  , do
      prefix <- elements ["device", "system", "platform", "node"]
      suffix <- choose (1, 9999::Int)
      return $ prefix ++ "-" ++ show suffix
  ]

-- | Generate a service suffix
genServiceSuffix :: Gen ByteString
genServiceSuffix = oneof
  [ return ""
  , return ":443"
  , return ":8080"
  , return ":service"
  , do
      port <- choose (1, 65535::Int)
      let portStr = ":" ++ show port
      return $ B.pack $ map (fromIntegral . fromEnum) portStr
  , elements [":tcp", ":udp", ":ssl", ":tls"]
  ]

-- | Generate valid attribute byte strings (non-empty, reasonable length)
genValidAttributeString :: Gen ByteString
genValidAttributeString = do
  len <- choose (1, 200) -- Stay under 256 byte limit
  chars <- vectorOf len $ elements (['A'..'Z'] ++ ['a'..'z'] ++ ['0'..'9'] ++ "-_.")
  return $ B.pack $ map (fromIntegral . fromEnum) chars

-- | Generate potentially invalid attribute byte strings (for negative testing)
genInvalidAttributeString :: Gen ByteString  
genInvalidAttributeString = oneof
  [ return B.empty -- Empty string
  , do -- Too long string
      len <- choose (257, 500) 
      chars <- vectorOf len (arbitrary :: Gen Int)
      return $ B.pack $ map (fromIntegral . (`mod` 256)) chars
  , genValidAttributeString -- Sometimes return valid for mixed testing
  ]

-- | Shrink ByteString while maintaining some structure
shrinkByteString :: ByteString -> [ByteString]
shrinkByteString bs
  | B.null bs = []
  | B.length bs == 1 = [B.empty]
  | otherwise = 
      [ B.take (B.length bs `div` 2) bs
      , B.drop (B.length bs `div` 2) bs
      ] ++ [B.init bs, B.tail bs]

-- * Generators for testing specific scenarios

-- | Generate a list of unique fingerprints for cache testing
genUniqueFingerprints :: Int -> Gen [TCGFingerprint]
genUniqueFingerprints n = do
  fps <- vectorOf n arbitrary
  return $ take n $ nubFingerprints fps
  where
    nubFingerprints [] = []
    nubFingerprints (x:xs) = x : nubFingerprints (filter (/= x) xs)

-- | Generate cache exception lists for testing
genCacheExceptions :: Gen [(TCGServiceID, TCGFingerprint)]
genCacheExceptions = do
  size <- choose (0, 10)
  serviceIds <- vectorOf size arbitrary
  fingerprints <- vectorOf size arbitrary
  return $ zip serviceIds fingerprints

-- * Instances for basic types used in validation
-- Note: ByteString instance is provided by quickcheck-instances package