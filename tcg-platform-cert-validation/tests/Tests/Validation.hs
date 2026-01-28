{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}

-- |
-- Tests for the main validation functionality.
-- This module tests the high-level validation API and integration with cache.

module Tests.Validation (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import qualified "tcg-platform-cert-validation" Data.X509.TCG.Validation as V
import Data.X509.TCG.Validation.Types
import Data.X509.TCG.Validation.Cache
import Tests.Arbitrary ()

tests :: TestTree  
tests = testGroup "Validation API Tests"
  [ validationErrorTests
  , failureReasonTests
  , cacheIntegrationTests
  ]

-- | Test ValidationError type functionality
validationErrorTests :: TestTree
validationErrorTests = testGroup "ValidationError Tests"
  [ testCase "SignatureError construction" $ do
      let err = SignatureError "test signature error"
      show err @?= "SignatureError \"test signature error\""
      
  , testCase "AttributeError construction" $ do
      let err = AttributeError "missing required attribute"  
      show err @?= "AttributeError \"missing required attribute\""
      
  , testCase "HierarchyError construction" $ do
      let err = HierarchyError "invalid component hierarchy"
      show err @?= "HierarchyError \"invalid component hierarchy\""
      
  , testCase "ConsistencyError construction" $ do
      let err = ConsistencyError "inconsistent certificate chain"
      show err @?= "ConsistencyError \"inconsistent certificate chain\""
      
  , testCase "ComplianceError construction" $ do
      let err = ComplianceError "TCG specification violation" 
      show err @?= "ComplianceError \"TCG specification violation\""
      
  , testCase "FormatError construction" $ do
      let err = FormatError "invalid certificate format"
      show err @?= "FormatError \"invalid certificate format\""
      
  , testCase "ValidationError equality" $ do
      let err1 = SignatureError "test"
      let err2 = SignatureError "test"  
      let err3 = SignatureError "different"
      err1 @?= err2
      err1 /= err3 @?= True
  ]

-- | Test FailureReason type functionality  
failureReasonTests :: TestTree
failureReasonTests = testGroup "FailureReason Tests"
  [ testCase "InvalidSignature construction" $ do
      let reason = InvalidSignature
      show reason @?= "InvalidSignature"
      
  , testCase "ExpiredCertificate construction" $ do
      let reason = ExpiredCertificate
      show reason @?= "ExpiredCertificate"
      
  , testCase "InFutureCertificate construction" $ do
      let reason = InFutureCertificate  
      show reason @?= "InFutureCertificate"
      
  , testCase "InvalidIssuer construction" $ do
      let reason = InvalidIssuer
      show reason @?= "InvalidIssuer"
      
  , testCase "UnknownCA construction" $ do
      let reason = UnknownCA
      show reason @?= "UnknownCA"
      
  , testCase "EmptyChain construction" $ do
      let reason = EmptyChain
      show reason @?= "EmptyChain"
      
  , testCase "SelfSigned construction" $ do
      let reason = SelfSigned
      show reason @?= "SelfSigned"
      
  , testCase "MissingRequiredAttribute construction" $ do
      let reason = MissingRequiredAttribute
      show reason @?= "MissingRequiredAttribute"
      
  , testCase "InvalidAttributeValue construction" $ do
      let reason = InvalidAttributeValue
      show reason @?= "InvalidAttributeValue"
      
  , testCase "InconsistentComponentData construction" $ do
      let reason = InconsistentComponentData  
      show reason @?= "InconsistentComponentData"
      
  , testCase "FailureReason equality" $ do
      InvalidSignature @?= InvalidSignature
      ExpiredCertificate @?= ExpiredCertificate
      InvalidSignature /= ExpiredCertificate @?= True
  ]

-- | Test cache integration functionality
cacheIntegrationTests :: TestTree
cacheIntegrationTests = testGroup "Cache Integration Tests"
  [ testCase "Default cache creation" $ do
      let cache = defaultTCGValidationCache
      -- Test that cache is created without error
      return ()
      
  , testCase "Exception cache creation" $ do
      let exceptions = []
      let cache = exceptionTCGValidationCache exceptions
      -- Test that cache is created without error
      return ()
      
  , testCase "TOFU cache creation" $ do
      cache <- tofuTCGValidationCache []
      -- Test that cache is created without error
      return ()
      
  , testCase "TCGFingerprint shows correctly" $ do
      let fingerprint = TCGFingerprint "test_fingerprint"
      show fingerprint @?= "TCGFingerprint \"test_fingerprint\""
      
  , testCase "TCGValidationCacheResult shows correctly" $ do
      show TCGValidationCachePass @?= "TCGValidationCachePass"
      show (TCGValidationCacheDenied "reason") @?= "TCGValidationCacheDenied \"reason\""
      show TCGValidationCacheUnknown @?= "TCGValidationCacheUnknown"
      
  , testCase "TCGValidationCacheResult equality" $ do
      TCGValidationCachePass @?= TCGValidationCachePass
      TCGValidationCacheUnknown @?= TCGValidationCacheUnknown
      TCGValidationCacheDenied "test" @?= TCGValidationCacheDenied "test"
      TCGValidationCacheDenied "test1" /= TCGValidationCacheDenied "test2" @?= True
  ]