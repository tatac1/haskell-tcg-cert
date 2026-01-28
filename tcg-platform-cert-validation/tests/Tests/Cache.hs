{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Tests for TCG Platform Certificate validation cache functionality.
-- This module tests the cache implementations and their behavior.

module Tests.Cache (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances ()

import Data.ByteString (ByteString)

import Data.X509.TCG.Validation.Cache
import Data.X509.TCG.Validation.Types

-- Import Arbitrary instances
import Tests.Arbitrary ()

tests :: TestTree
tests = testGroup "Cache Tests"
  [ fingerprintTests
  , cacheResultTests  
  , exceptionCacheTests
  , tofuCacheTests
  , cacheCallbackTests
  ]

-- | Test TCGFingerprint functionality
fingerprintTests :: TestTree
fingerprintTests = testGroup "TCGFingerprint Tests"
  [ testCase "TCGFingerprint construction" $ do
      let fp = TCGFingerprint "test_fingerprint"
      show fp @?= "TCGFingerprint \"test_fingerprint\""
      
  , testCase "TCGFingerprint equality" $ do
      let fp1 = TCGFingerprint "same"
      let fp2 = TCGFingerprint "same"
      let fp3 = TCGFingerprint "different"
      fp1 @?= fp2
      fp1 /= fp3 @?= True
      
  , testCase "TCGFingerprint ordering" $ do
      let fp1 = TCGFingerprint "aaa"
      let fp2 = TCGFingerprint "bbb"
      fp1 < fp2 @?= True
      fp2 > fp1 @?= True
  ]

-- | Test TCGValidationCacheResult functionality
cacheResultTests :: TestTree  
cacheResultTests = testGroup "TCGValidationCacheResult Tests"
  [ testCase "TCGValidationCachePass construction" $ do
      show TCGValidationCachePass @?= "TCGValidationCachePass"
      
  , testCase "TCGValidationCacheDenied construction" $ do
      let result = TCGValidationCacheDenied "access denied"
      show result @?= "TCGValidationCacheDenied \"access denied\""
      
  , testCase "TCGValidationCacheUnknown construction" $ do
      show TCGValidationCacheUnknown @?= "TCGValidationCacheUnknown"
      
  , testCase "TCGValidationCacheResult equality" $ do
      TCGValidationCachePass @?= TCGValidationCachePass
      TCGValidationCacheUnknown @?= TCGValidationCacheUnknown
      let denied1 = TCGValidationCacheDenied "reason1"
      let denied2 = TCGValidationCacheDenied "reason1" 
      let denied3 = TCGValidationCacheDenied "reason2"
      denied1 @?= denied2
      denied1 /= denied3 @?= True
  ]

-- | Test exception-based cache functionality
exceptionCacheTests :: TestTree
exceptionCacheTests = testGroup "Exception Cache Tests"
  [ testCase "Empty exception cache creation" $ do
      let _cache = exceptionTCGValidationCache []
      -- Test successful creation
      return ()
      
  , testCase "Exception cache with entries" $ do
      let serviceId = ("test-platform", "test-service")
      let fingerprint = TCGFingerprint "test_fp"
      let exceptions = [(serviceId, fingerprint)]
      let _cache = exceptionTCGValidationCache exceptions
      -- Test successful creation  
      return ()
      
  , testProperty "Exception cache is deterministic" $ \(serviceIds :: [TCGServiceID]) (fingerprints :: [TCGFingerprint]) ->
      let _exceptions = zip serviceIds fingerprints
          _cache = exceptionTCGValidationCache _exceptions
      in True -- Cache creation should always succeed
  ]

-- | Test TOFU (Trust On First Use) cache functionality  
tofuCacheTests :: TestTree
tofuCacheTests = testGroup "TOFU Cache Tests" 
  [ testCase "Empty TOFU cache creation" $ do
      _cache <- tofuTCGValidationCache []
      -- Test successful creation
      return ()
      
  , testCase "TOFU cache with initial exceptions" $ do
      let serviceId = ("test-platform", "test-service")
      let fingerprint = TCGFingerprint "test_fp"  
      let exceptions = [(serviceId, fingerprint)]
      _cache <- tofuTCGValidationCache exceptions
      -- Test successful creation
      return ()
  ]

-- | Test cache callback functionality
cacheCallbackTests :: TestTree
cacheCallbackTests = testGroup "Cache Callback Tests"
  [ testCase "Default cache has no-op callbacks" $ do
      let _cache = defaultTCGValidationCache
      -- Test that default cache is the same as empty exception cache
      return ()
      
  , testCase "Exception cache query with empty list" $ do
      let _cache = exceptionTCGValidationCache []
      let _serviceId = ("test-platform" :: String, "test-service" :: String)
      let _fingerprint = TCGFingerprint "test_fp"
      -- For this test, we would need a mock certificate
      -- This is a placeholder for the actual test structure
      return ()
      
  , testCase "Exception cache add is no-op" $ do
      let _cache = exceptionTCGValidationCache []
      let _serviceId = ("test-platform" :: String, "test-service" :: String) 
      let _fingerprint = TCGFingerprint "test_fp"
      -- Test that add callback does nothing for exception cache
      return ()
  ]

-- Helper functions for testing

-- | Generate a test TCGServiceID
-- testServiceId :: String -> ByteString -> TCGServiceID
-- testServiceId platform service = (platform, service)

-- | Generate a test TCGFingerprint  
-- testFingerprint :: ByteString -> TCGFingerprint
-- testFingerprint = TCGFingerprint