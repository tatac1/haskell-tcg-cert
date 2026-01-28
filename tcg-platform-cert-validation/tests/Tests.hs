-- |
-- Main test driver for tcg-platform-cert-validation package.
-- This module coordinates all the test suites using Tasty framework.

module Main where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Data.X509.TCG.Validation.Types

import qualified Tests.Validation
import qualified Tests.Cache  
import qualified Tests.Properties
import qualified Tests.Internal
import qualified Tests.SBV
import Tests.Arbitrary ()

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "TCG Platform Certificate Validation Tests"
  [ unitTests
  , validationTests
  , cacheTests
  , internalTests
  , propertyTests
  , sbvTests
  ]

-- | Basic unit tests for core functionality
unitTests :: TestTree
unitTests = testGroup "Unit Tests"
  [ testCase "ValidationError shows correctly" $ do
      let err = SignatureError "test error"
      show err @?= "SignatureError \"test error\""
      
  , testCase "FailureReason shows correctly" $ do  
      let reason = InvalidSignature
      show reason @?= "InvalidSignature"
  ]

-- | Import test groups from other modules
validationTests :: TestTree
validationTests = Tests.Validation.tests

cacheTests :: TestTree  
cacheTests = Tests.Cache.tests

internalTests :: TestTree
internalTests = Tests.Internal.tests

propertyTests :: TestTree
propertyTests = Tests.Properties.tests

sbvTests :: TestTree
sbvTests = Tests.SBV.tests