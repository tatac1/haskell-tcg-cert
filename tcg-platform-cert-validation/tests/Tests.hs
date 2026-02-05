-- |
-- Main test driver for tcg-platform-cert-validation package.
-- This module coordinates all the test suites using Tasty framework.

module Main where

import Test.Tasty
import qualified Tests.Properties
import qualified Tests.Internal
import qualified Tests.SBV
import Tests.Arbitrary ()

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "TCG Platform Certificate Validation Tests"
  [ internalTests
  , propertyTests
  , sbvTests
  ]

internalTests :: TestTree
internalTests = Tests.Internal.tests

propertyTests :: TestTree
propertyTests = Tests.Properties.tests

sbvTests :: TestTree
sbvTests = Tests.SBV.tests
