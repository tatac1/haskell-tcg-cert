-- |
-- Main test driver for tcg-platform-cert-util package.
-- This module coordinates all the test suites using Tasty framework.

module Main where

import Test.Tasty

import qualified ConfigTests
import qualified ASN1Tests  
import qualified DisplayTests
import qualified IntegrationTests
import qualified CryptoAlgorithmTests
import qualified ValidationTests
import qualified SBVTests
import qualified ConfigLintTests
import qualified PreIssuanceTests
import qualified JsonReportTests
import qualified IanaPenTests

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "TCG Platform Certificate Utility Tests"
  [ unitTests
  , configTests
  , asn1Tests
  , displayTests
  , integrationTests
  , cryptoAlgorithmTests
  , validationTests
  , sbvTests
  , configLintTests
  , preIssuanceTests
  , jsonReportTests
  , ianaPenTests
  ]

-- | Basic unit tests for core functionality
unitTests :: TestTree
unitTests = testGroup "Unit Tests"
  [ testGroup "Module Integration"
    [ -- Basic integration tests would go here
    ]
  ]

-- | Configuration management tests
configTests :: TestTree
configTests = ConfigTests.tests

-- | ASN.1 utility tests
asn1Tests :: TestTree
asn1Tests = ASN1Tests.tests

-- | Display functionality tests
displayTests :: TestTree
displayTests = DisplayTests.tests

-- | Integration tests
integrationTests :: TestTree
integrationTests = IntegrationTests.tests

-- | Cryptographic algorithm tests
cryptoAlgorithmTests :: TestTree
cryptoAlgorithmTests = CryptoAlgorithmTests.tests

-- | Validation tests
validationTests :: TestTree
validationTests = ValidationTests.tests

-- | SBV formal verification tests
sbvTests :: TestTree
sbvTests = SBVTests.tests

configLintTests :: TestTree
configLintTests = ConfigLintTests.tests

preIssuanceTests :: TestTree
preIssuanceTests = PreIssuanceTests.tests

jsonReportTests :: TestTree
jsonReportTests = JsonReportTests.tests

ianaPenTests :: TestTree
ianaPenTests = IanaPenTests.tests