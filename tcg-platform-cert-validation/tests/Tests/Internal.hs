{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Tests for internal validation functions.
-- This module tests the internal validation logic that was moved from tcg-platform-cert.

module Tests.Internal (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import qualified Data.ByteString as B
import Data.List (isInfixOf)
-- import Data.ASN1.Types

import Data.X509.TCG.Validation.Types
import Data.X509.TCG.Validation.Internal
import Data.X509AC (Attributes(..))

tests :: TestTree
tests = testGroup "Internal Validation Tests"
  [ helperFunctionTests
  , attributeValidationTests  
  , componentValidationTests
  , oidTests
  ]

-- | Test helper functions
helperFunctionTests :: TestTree
helperFunctionTests = testGroup "Helper Function Tests"
  [ testCase "nub removes duplicates" $ do
      nub [1, 2, 2, 3, 1] @?= ([1, 2, 3] :: [Int])
      nub ([] :: [Int]) @?= []
      nub [1] @?= ([1] :: [Int])
      
  , testCase "list difference (\\\\)" $ do
      [1, 2, 3] \\ [2] @?= ([1, 3] :: [Int])
      [1, 2, 3] \\ [4, 5] @?= ([1, 2, 3] :: [Int])
      [] \\ [1, 2] @?= ([] :: [Int])
      [1, 2] \\ [] @?= ([1, 2] :: [Int])
      
  , testCase "getRequiredAttributeOIDs returns expected OIDs" $ do
      let oids = getRequiredAttributeOIDs
      length oids @?= 4 -- Should include the required platform OIDs
  ]

-- | Test attribute validation functions
attributeValidationTests :: TestTree
attributeValidationTests = testGroup "Attribute Validation Tests"
  [ testCase "validatePlatformManufacturerAttr - empty fails" $ do
      let errors = validatePlatformManufacturerAttr B.empty
      length errors @?= 1
      case head errors of
        AttributeError msg -> "empty" `isInfixOf` msg @?= True
        _ -> assertFailure "Expected AttributeError"
        
  , testCase "validatePlatformManufacturerAttr - valid passes" $ do
      let errors = validatePlatformManufacturerAttr "ValidManufacturer"
      errors @?= []
      
  , testCase "validatePlatformManufacturerAttr - too long fails" $ do
      let longName = B.replicate 300 65 -- 300 'A's, exceeds 256 limit
      let errors = validatePlatformManufacturerAttr longName
      length errors @?= 1
      case head errors of
        AttributeError msg -> "maximum length" `isInfixOf` msg @?= True
        _ -> assertFailure "Expected AttributeError for length"
        
  , testCase "validatePlatformModelAttr - empty fails" $ do
      let errors = validatePlatformModelAttr B.empty
      length errors @?= 1
      
  , testCase "validatePlatformModelAttr - valid passes" $ do
      let errors = validatePlatformModelAttr "ValidModel"
      errors @?= []
      
  , testCase "validatePlatformSerialAttr - empty fails" $ do
      let errors = validatePlatformSerialAttr B.empty  
      length errors @?= 1
      
  , testCase "validatePlatformSerialAttr - valid passes" $ do
      let errors = validatePlatformSerialAttr "SN123456"
      errors @?= []
      
  , testCase "validatePlatformVersionAttr - empty fails" $ do
      let errors = validatePlatformVersionAttr B.empty
      length errors @?= 1
      
  , testCase "validatePlatformVersionAttr - valid passes" $ do
      let errors = validatePlatformVersionAttr "1.0.0"
      errors @?= []
      
  , testCase "validateTPMModelAttr - empty fails" $ do
      let errors = validateTPMModelAttr B.empty
      length errors @?= 1
      
  , testCase "validateTPMModelAttr - valid passes" $ do
      let errors = validateTPMModelAttr "TPM2.0"
      errors @?= []
      
  , testProperty "Valid attribute strings pass validation" $ \(validStr :: String) ->
      let bs = B.pack $ take 200 $ filter (/= 0) $ map (fromIntegral . fromEnum) validStr -- Limit length and remove nulls
      in B.length bs > 0 ==> 
         null (validatePlatformManufacturerAttr bs) &&
         null (validatePlatformModelAttr bs) &&
         null (validatePlatformSerialAttr bs) &&
         null (validatePlatformVersionAttr bs) &&
         null (validateTPMModelAttr bs)
  ]

-- | Test component validation functions  
componentValidationTests :: TestTree
componentValidationTests = testGroup "Component Validation Tests"
  [ testCase "validateUniqueAddresses - empty list passes" $ do
      let errors = validateUniqueAddresses []
      errors @?= []
      
  , testCase "validateCertificationLevelAttr - valid levels pass" $ do
      validateCertificationLevelAttr 1 @?= []
      validateCertificationLevelAttr 4 @?= []
      validateCertificationLevelAttr 7 @?= []
      
  , testCase "validateCertificationLevelAttr - invalid levels fail" $ do
      length (validateCertificationLevelAttr 0) @?= 1
      length (validateCertificationLevelAttr 8) @?= 1
      length (validateCertificationLevelAttr (-1)) @?= 1
      
  , testCase "validateRTMTypeAttr - valid types pass" $ do
      validateRTMTypeAttr 1 @?= [] -- BIOS
      validateRTMTypeAttr 2 @?= [] -- UEFI  
      validateRTMTypeAttr 3 @?= [] -- Other
      
  , testCase "validateRTMTypeAttr - invalid types fail" $ do
      length (validateRTMTypeAttr 0) @?= 1
      length (validateRTMTypeAttr 4) @?= 1
      length (validateRTMTypeAttr (-1)) @?= 1
      
  , testCase "validatePlatformQualifiersAttr - empty list fails" $ do
      let errors = validatePlatformQualifiersAttr []
      length errors @?= 1
      
  , testCase "validatePlatformQualifiersAttr - valid list passes" $ do
      let qualifiers = ["qualifier1", "qualifier2"]
      validatePlatformQualifiersAttr qualifiers @?= []
      
  , testCase "validatePlatformQualifiersAttr - list with empty strings fails" $ do
      let qualifiers = ["valid", "", "also_valid"]
      let errors = validatePlatformQualifiersAttr qualifiers
      length errors @?= 1
  ]

-- | Test OID-related functionality
oidTests :: TestTree  
oidTests = testGroup "OID Tests"
  [ testCase "Required platform attribute OIDs are defined" $ do
      let oids = getRequiredAttributeOIDs
      length oids `elem` [3, 4, 5] @?= True -- Allow some flexibility in count
      
  , testCase "extractPresentOIDs works with empty attributes" $ do
      let emptyAttrs = Attributes []
      extractPresentOIDs emptyAttrs @?= []
  ]

-- Property tests for validation functions
-- validationPropertyTests :: TestTree
-- validationPropertyTests = testGroup "Validation Property Tests"
{-  [ testProperty "Empty byte strings fail basic validations" $ \() ->
      let emptyBS = B.empty
      in length (validatePlatformManufacturerAttr emptyBS) >= 1 &&
         length (validatePlatformModelAttr emptyBS) >= 1 &&
         length (validatePlatformSerialAttr emptyBS) >= 1 &&
         length (validatePlatformVersionAttr emptyBS) >= 1 &&
         length (validateTPMModelAttr emptyBS) >= 1
         
  , testProperty "Certification levels outside 1-7 fail" $ \level ->
      (level < 1 || level > 7) ==>
      length (validateCertificationLevelAttr level) >= 1
      
  , testProperty "RTM types outside 1-3 fail" $ \rtmType ->
      (rtmType < 1 || rtmType > 3) ==>
      length (validateRTMTypeAttr rtmType) >= 1
  ] -}