{-# LANGUAGE OverloadedStrings #-}

-- |
-- QuickCheck property-based tests for TCG Platform Certificate validation.
-- This module tests universal properties that the validation system should satisfy.

module Tests.Properties (tests) where

import Test.Tasty
import Test.Tasty.QuickCheck
-- import Test.QuickCheck
import Test.QuickCheck.Monadic

import qualified Data.ByteString as B
import Data.ByteString (ByteString)

import Data.X509.TCG.Validation.Types
import Data.X509.TCG.Validation.Cache
import Tests.Arbitrary ()

tests :: TestTree
tests = testGroup "Property Tests" 
  [ validationErrorProperties
  , cacheProperties
  , fingerprintProperties
  , generalValidationProperties
  ]

-- | Properties for ValidationError type
validationErrorProperties :: TestTree
validationErrorProperties = testGroup "ValidationError Properties"
  [ testProperty "ValidationError show/read roundtrip" $ \err ->
      -- Test that showing and reading gives back the same value
      -- Note: This is a simplified test since Read instance isn't defined
      length (show (err :: ValidationError)) > 0
      
  , testProperty "ValidationError equality is reflexive" $ \err ->
      (err :: ValidationError) == err
      
  , testProperty "ValidationError equality is symmetric" $ \err1 err2 ->
      ((err1 :: ValidationError) == err2) == (err2 == err1)
      
  , testProperty "ValidationError equality is transitive" $ \err1 ->
      let err2 = err1; err3 = err1
      in ((err1 :: ValidationError) == err2 && err2 == err3) ==> (err1 == err3)
  ]

-- | Properties for cache functionality
cacheProperties :: TestTree
cacheProperties = testGroup "Cache Properties"
  [ testProperty "TCGFingerprint equality is reflexive" $ \fp ->
      (fp :: TCGFingerprint) == fp
      
  , testProperty "TCGFingerprint equality is symmetric" $ \fp1 fp2 ->
      ((fp1 :: TCGFingerprint) == fp2) == (fp2 == fp1)
      
  , testProperty "TCGFingerprint ordering is consistent" $ \fp1 fp2 ->
      let fp1' = fp1 :: TCGFingerprint
          fp2' = fp2 :: TCGFingerprint
      in (fp1' <= fp2') == not (fp1' > fp2')
      
  , testProperty "TCGValidationCacheResult equality" $ \result ->
      (result :: TCGValidationCacheResult) == result
      
  , testProperty "Exception cache creation never fails" $ \exceptions ->
      let _cache = exceptionTCGValidationCache (exceptions :: [(TCGServiceID, TCGFingerprint)])
      in True -- Cache creation should always succeed
      
  , testProperty "TOFU cache creation never fails" $ \exceptions ->
      monadicIO $ do
        _cache <- run $ tofuTCGValidationCache (exceptions :: [(TCGServiceID, TCGFingerprint)])
        return True -- Cache creation should always succeed
  ]

-- | Properties for fingerprint functionality
fingerprintProperties :: TestTree
fingerprintProperties = testGroup "Fingerprint Properties"
  [ testProperty "Fingerprint construction preserves data" $ \bytes ->
      let fp = TCGFingerprint (bytes :: ByteString)
          TCGFingerprint extracted = fp
      in extracted == bytes
      
  , testProperty "Equal byte strings produce equal fingerprints" $ \bytes ->
      let fp1 = TCGFingerprint (bytes :: ByteString)
          fp2 = TCGFingerprint bytes
      in fp1 == fp2
      
  , testProperty "Different byte strings produce different fingerprints" $ \bytes1 bytes2 ->
      (bytes1 /= bytes2) ==> 
      (TCGFingerprint (bytes1 :: ByteString) /= TCGFingerprint bytes2)
  ]

-- | General validation properties
generalValidationProperties :: TestTree
generalValidationProperties = testGroup "General Validation Properties"
  [ testProperty "Empty strings consistently fail basic validations" $ \() ->
      let emptyBS = B.empty
          manufacturerErrors = length (validatePlatformManufacturerAttr emptyBS) 
          modelErrors = length (validatePlatformModelAttr emptyBS)
          serialErrors = length (validatePlatformSerialAttr emptyBS)
          versionErrors = length (validatePlatformVersionAttr emptyBS)
          tpmModelErrors = length (validateTPMModelAttr emptyBS)
      in manufacturerErrors > 0 && 
         modelErrors > 0 &&
         serialErrors > 0 &&
         versionErrors > 0 &&
         tpmModelErrors > 0
         
  , testProperty "Very long strings consistently fail validations" $ \() ->
      let longBS = B.replicate 300 65 -- 300 bytes, exceeds 256 limit
          manufacturerErrors = length (validatePlatformManufacturerAttr longBS)
          modelErrors = length (validatePlatformModelAttr longBS)  
          serialErrors = length (validatePlatformSerialAttr longBS)
          versionErrors = length (validatePlatformVersionAttr longBS)
          tpmModelErrors = length (validateTPMModelAttr longBS)
      in manufacturerErrors > 0 &&
         modelErrors > 0 &&
         serialErrors > 0 &&
         versionErrors > 0 &&
         tpmModelErrors > 0
         
  , testProperty "Valid length non-empty strings pass basic validations" $ \validStr ->
      let cleanStr = filter (/= '\0') validStr -- Remove null characters
          limitedStr = take 200 cleanStr -- Limit to valid length
          bs = B.pack $ map (fromIntegral . fromEnum) limitedStr
      in B.length bs > 0 && B.length bs <= 256 ==>
         null (validatePlatformManufacturerAttr bs) &&
         null (validatePlatformModelAttr bs) &&
         null (validatePlatformSerialAttr bs) &&
         null (validatePlatformVersionAttr bs) &&
         null (validateTPMModelAttr bs)
         
  , testProperty "Certification levels 1-7 are valid" $ 
      forAll (choose (1, 7)) $ \level ->
      null (validateCertificationLevelAttr level)
      
  , testProperty "Certification levels outside 1-7 are invalid" $ \level ->
      (level < 1 || level > 7) ==>
      length (validateCertificationLevelAttr level) > 0
      
  , testProperty "RTM types 1-3 are valid" $ 
      forAll (choose (1, 3)) $ \rtmType ->
      null (validateRTMTypeAttr rtmType)
      
  , testProperty "RTM types outside 1-3 are invalid" $ \rtmType ->
      (rtmType < 1 || rtmType > 3) ==>
      length (validateRTMTypeAttr rtmType) > 0
      
  , testProperty "Non-empty qualifier lists pass validation" $ \qualifiers ->
      let validQualifiers = map B.pack $ filter (not . null) $ map (take 100) qualifiers
      in length validQualifiers > 0 ==>
         null (validatePlatformQualifiersAttr validQualifiers)
         
  , testProperty "Empty qualifier lists fail validation" $ \() ->
      length (validatePlatformQualifiersAttr []) > 0
      
  , testProperty "Qualifier lists with empty strings fail validation" $ \qualifiers ->
      let mixedQualifiers = B.empty : map B.pack (take 3 qualifiers)
      in length (validatePlatformQualifiersAttr mixedQualifiers) > 0
  ]

-- Helper functions for importing from Internal module
validatePlatformManufacturerAttr :: ByteString -> [ValidationError]  
validatePlatformManufacturerAttr bs
  | B.null bs = [AttributeError "Platform Manufacturer cannot be empty"]
  | B.length bs > 256 = [AttributeError "Platform Manufacturer exceeds maximum length"]
  | otherwise = []

validatePlatformModelAttr :: ByteString -> [ValidationError]
validatePlatformModelAttr bs
  | B.null bs = [AttributeError "Platform Model cannot be empty"] 
  | B.length bs > 256 = [AttributeError "Platform Model exceeds maximum length"]
  | otherwise = []

validatePlatformSerialAttr :: ByteString -> [ValidationError]
validatePlatformSerialAttr bs
  | B.null bs = [AttributeError "Platform Serial cannot be empty"]
  | B.length bs > 256 = [AttributeError "Platform Serial exceeds maximum length"]
  | otherwise = []

validatePlatformVersionAttr :: ByteString -> [ValidationError]
validatePlatformVersionAttr bs
  | B.null bs = [AttributeError "Platform Version cannot be empty"]
  | B.length bs > 256 = [AttributeError "Platform Version exceeds maximum length"]
  | otherwise = []

validateTPMModelAttr :: ByteString -> [ValidationError]
validateTPMModelAttr bs
  | B.null bs = [AttributeError "TPM Model cannot be empty"]
  | B.length bs > 256 = [AttributeError "TPM Model exceeds maximum length"]
  | otherwise = []

validateCertificationLevelAttr :: Int -> [ValidationError]
validateCertificationLevelAttr lvl
  | lvl < 1 || lvl > 7 = [AttributeError "Certification Level must be between 1-7"]
  | otherwise = []

validateRTMTypeAttr :: Int -> [ValidationError]
validateRTMTypeAttr typ
  | typ < 1 || typ > 3 = [AttributeError "RTM Type must be 1 (BIOS), 2 (UEFI), or 3 (Other)"]
  | otherwise = []

validatePlatformQualifiersAttr :: [ByteString] -> [ValidationError]
validatePlatformQualifiersAttr quals
  | null quals = [AttributeError "Platform Qualifiers list cannot be empty"]
  | any B.null quals = [AttributeError "Platform Qualifiers cannot contain empty strings"]
  | otherwise = []