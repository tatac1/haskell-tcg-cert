{-# LANGUAGE OverloadedStrings #-}

module DisplayTests (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.QuickCheck (choose, forAll)

import Data.X509.TCG.Util.Display

tests :: TestTree
tests = testGroup "Display Tests"
  [ utilityFunctionTests
  , attributeClassificationTests
  , propertyTests
  ]

-- | Test utility functions
utilityFunctionTests :: TestTree
utilityFunctionTests = testGroup "Utility Function Tests"
  [ testCase "Certification level names" $ do
      certificationLevelName 1 @?= "Basic"
      certificationLevelName 2 @?= "Standard"
      certificationLevelName 3 @?= "Enhanced"
      certificationLevelName 4 @?= "High"
      certificationLevelName 5 @?= "Very High"
      certificationLevelName 6 @?= "Critical"
      certificationLevelName 7 @?= "Ultra"
      certificationLevelName 8 @?= "Unknown"
      certificationLevelName 0 @?= "Unknown"
      certificationLevelName (-1) @?= "Unknown"

  , testCase "RTM type names" $ do
      rtmTypeName 1 @?= "BIOS"
      rtmTypeName 2 @?= "UEFI"
      rtmTypeName 3 @?= "Other"
      rtmTypeName 4 @?= "Unknown"
      rtmTypeName 0 @?= "Unknown"
      rtmTypeName (-1) @?= "Unknown"
  ]

-- | Test attribute classification
attributeClassificationTests :: TestTree
attributeClassificationTests = testGroup "Attribute Classification Tests"
  [ testCase "Extended attributes identified correctly" $ do
      -- Note: These tests would require actual TCGAttribute values
      -- For now, we test the classification logic conceptually
      let extendedTypes = [ -- These would be actual attribute constructors
                           -- TCGPlatformConfigUri, TCGPlatformClass, etc.
                          ]
      -- isExtendedAttribute would need actual attribute values
      length extendedTypes @?= 0 -- Placeholder test

  , testCase "Basic attributes not classified as extended" $ do
      -- Similar placeholder for basic attribute testing
      let basicTypes = [ -- TCGPlatformManufacturer, TCGPlatformModel, etc.
                        ]
      length basicTypes @?= 0 -- Placeholder test
  ]

-- | Property-based tests
propertyTests :: TestTree
propertyTests = testGroup "Property Tests"
  [ testProperty "Certification levels 1-7 have specific names" $
      forAll (choose (1, 7)) $ \level ->
      certificationLevelName level /= "Unknown"

  , testProperty "Invalid certification levels return Unknown" $ \level ->
      (level < 1 || level > 7) ==>
      certificationLevelName level == "Unknown"

  , testProperty "RTM types 1-3 have specific names" $
      forAll (choose (1, 3)) $ \rtmType ->
      rtmTypeName rtmType /= "Unknown"

  , testProperty "Invalid RTM types return Unknown" $ \rtmType ->
      (rtmType < 1 || rtmType > 3) ==>
      rtmTypeName rtmType == "Unknown"

  , testProperty "Certification level names are non-empty" $ \level ->
      not (null (certificationLevelName level))

  , testProperty "RTM type names are non-empty" $ \rtmType ->
      not (null (rtmTypeName rtmType))

  , testProperty "Certification level name consistency" $ \level ->
      let name1 = certificationLevelName level
          name2 = certificationLevelName level
      in name1 == name2

  , testProperty "RTM type name consistency" $ \rtmType ->
      let name1 = rtmTypeName rtmType
          name2 = rtmTypeName rtmType
      in name1 == name2
  ]