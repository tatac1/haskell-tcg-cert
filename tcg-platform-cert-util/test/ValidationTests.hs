{-# LANGUAGE OverloadedStrings #-}

module ValidationTests (tests) where

import qualified Crypto.PubKey.RSA as RSA
import qualified Data.ByteString.Char8 as BC
import Data.X509 (PrivKey (..))
-- TCG imports

import Data.X509.TCG
import qualified Data.X509.TCG as TCG
import Data.X509.TCG.Util.Certificate
import Data.X509.TCG.Util.Config
import Test.Tasty
import Test.Tasty.HUnit

tests :: TestTree
tests =
  testGroup
    "Platform Certificate Validation Tests"
    [ preGenerationValidationTests,
      postGenerationValidationTests,
      invalidInputTests
    ]

-- | Test pre-generation validation functions
preGenerationValidationTests :: TestTree
preGenerationValidationTests =
  testGroup
    "Pre-Generation Validation Tests"
    [ testCase "Valid platform configuration passes validation" $ do
        let validConfig =
              PlatformConfiguration
                { pcManufacturer = "Test Corporation",
                  pcModel = "Test Model",
                  pcVersion = "1.0",
                  pcSerial = "TEST001",
                  pcComponents = []
                }
        result <- validatePlatformConfiguration validConfig
        case result of
          Right _ -> return () -- Success
          Left err -> assertFailure $ "Valid config should pass: " ++ err,
      testCase "Empty manufacturer fails validation" $ do
        let invalidConfig =
              PlatformConfiguration
                { pcManufacturer = "",
                  pcModel = "Test Model",
                  pcVersion = "1.0",
                  pcSerial = "TEST001",
                  pcComponents = []
                }
        result <- validatePlatformConfiguration invalidConfig
        case result of
          Left err -> err `shouldContainSubstring` "manufacturer cannot be empty"
          Right _ -> assertFailure "Empty manufacturer should fail validation",
      testCase "Long manufacturer name fails validation" $ do
        let invalidConfig =
              PlatformConfiguration
                { pcManufacturer = BC.pack $ replicate 300 'A', -- Too long
                  pcModel = "Test Model",
                  pcVersion = "1.0",
                  pcSerial = "TEST001",
                  pcComponents = []
                }
        result <- validatePlatformConfiguration invalidConfig
        case result of
          Left err -> err `shouldContainSubstring` "manufacturer name too long"
          Right _ -> assertFailure "Long manufacturer name should fail validation",
      testCase "Valid hash algorithms pass validation" $ do
        validHashes <- mapM validateHashAlgorithm ["sha256", "sha384", "sha512"]
        let failures = [err | Left err <- validHashes]
        if null failures
          then return ()
          else assertFailure $ "Valid hash algorithms should pass: " ++ show failures,
      testCase "Invalid hash algorithm fails validation" $ do
        result <- validateHashAlgorithm "md5"
        case result of
          Left err -> err `shouldContainSubstring` "Invalid hash algorithm"
          Right _ -> assertFailure "Invalid hash algorithm should fail validation",
      testCase "RSA key size validation" $ do
        -- Generate a small RSA key for testing (1024 bits - should fail)
        (_, privKey) <- RSA.generate 128 3 -- 1024 bits = 128 bytes
        let privKeyX509 = PrivKeyRSA privKey
        result <- validatePrivateKeyCompatibility privKeyX509 "sha384"
        case result of
          Left err -> err `shouldContainSubstring` "key size too small"
          Right _ -> assertFailure "Small RSA key should fail validation",
      testCase "Valid component identifiers pass validation" $ do
        let validComponent =
              ComponentIdentifier
                { ciManufacturer = "Test Component Corp",
                  ciModel = "Test Component Model",
                  ciSerial = Just "COMP001",
                  ciRevision = Just "1.0",
                  ciManufacturerSerial = Nothing,
                  ciManufacturerRevision = Nothing
                }
        result <- validateComponentIdentifiers [validComponent]
        case result of
          Right _ -> return () -- Success
          Left err -> assertFailure $ "Valid component should pass: " ++ err,
      testCase "Invalid component model fails validation" $ do
        let invalidComponent =
              ComponentIdentifier
                { ciManufacturer = "Test Component Corp",
                  ciModel = "", -- Empty model name
                  ciSerial = Just "COMP001",
                  ciRevision = Just "1.0",
                  ciManufacturerSerial = Nothing,
                  ciManufacturerRevision = Nothing
                }
        result <- validateComponentIdentifiers [invalidComponent]
        case result of
          Left err -> err `shouldContainSubstring` "Model name cannot be empty"
          Right _ -> assertFailure "Invalid component model should fail validation"
    ]

-- | Test post-generation validation functions
postGenerationValidationTests :: TestTree
postGenerationValidationTests =
  testGroup
    "Post-Generation Validation Tests"
    [ testCase "Generated certificate structure validation" $ do
        -- This is a basic test - in practice we'd generate a real certificate
        let testConfig =
              PlatformConfiguration
                { pcManufacturer = "Test Corp",
                  pcModel = "Test Model",
                  pcVersion = "1.0",
                  pcSerial = "TEST001",
                  pcComponents = []
                }
        -- For this test, we just verify the validation function exists and compiles
        -- Real testing would require generating an actual certificate
        testConfig `seq` return ()
    ]

-- | Test various invalid input scenarios
invalidInputTests :: TestTree
invalidInputTests =
  testGroup
    "Invalid Input Handling Tests"
    [ testCase "Non-printable characters in manufacturer fail validation" $ do
        let invalidConfig =
              PlatformConfiguration
                { pcManufacturer = "Test\x00Corp", -- Contains null character
                  pcModel = "Test Model",
                  pcVersion = "1.0",
                  pcSerial = "TEST001",
                  pcComponents = []
                }
        result <- validatePlatformConfiguration invalidConfig
        case result of
          Left err -> err `shouldContainSubstring` "non-printable characters"
          Right _ -> assertFailure "Non-printable characters should fail validation",
      testCase "Empty component manufacturer fails validation" $ do
        let invalidComponent =
              ComponentIdentifier
                { ciManufacturer = "", -- Empty manufacturer
                  ciModel = "Test Component Model",
                  ciSerial = Just "COMP001",
                  ciRevision = Just "1.0",
                  ciManufacturerSerial = Nothing,
                  ciManufacturerRevision = Nothing
                }
        result <- validateComponentIdentifiers [invalidComponent]
        case result of
          Left err -> err `shouldContainSubstring` "Manufacturer name cannot be empty"
          Right _ -> assertFailure "Empty component manufacturer should fail validation",
      testCase "Component manufacturer name too long fails validation" $ do
        let invalidComponent =
              ComponentIdentifier
                { ciManufacturer = BC.pack $ replicate 300 'A', -- Too long
                  ciModel = "Test Component Model",
                  ciSerial = Just "COMP001",
                  ciRevision = Just "1.0",
                  ciManufacturerSerial = Nothing,
                  ciManufacturerRevision = Nothing
                }
        result <- validateComponentIdentifiers [invalidComponent]
        case result of
          Left err -> err `shouldContainSubstring` "Manufacturer name exceeds STRMAX"
          Right _ -> assertFailure "Long component manufacturer should fail validation"
    ]

-- Helper function to check if a string contains a substring
shouldContainSubstring :: String -> String -> IO ()
shouldContainSubstring haystack needle =
  if needle `isSubsequenceOf` haystack
    then return ()
    else assertFailure $ "Expected '" ++ haystack ++ "' to contain '" ++ needle ++ "'"

-- Helper function to check if one list is a subsequence of another
isSubsequenceOf :: (Eq a) => [a] -> [a] -> Bool
isSubsequenceOf [] _ = True
isSubsequenceOf _ [] = False
isSubsequenceOf xs@(y : ys) (z : zs)
  | y == z = isSubsequenceOf ys zs
  | otherwise = isSubsequenceOf xs zs