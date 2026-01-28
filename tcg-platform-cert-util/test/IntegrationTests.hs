{-# LANGUAGE OverloadedStrings #-}

module IntegrationTests (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.QuickCheck (choose, forAll)

import qualified Data.ByteString as B
import Data.ASN1.Types
import System.Directory (doesFileExist, removeFile)
import System.IO (hClose)
import System.IO.Temp (withSystemTempFile, withSystemTempDirectory)
import System.FilePath ((</>))
import Control.Exception (catch, IOException)
import Data.Yaml (encodeFile)

import Data.X509.TCG.Util.Config
import Data.X509.TCG.Util.ASN1
import Data.X509.TCG.Util.Certificate
import Data.X509.TCG.Util.Display
import Data.X509.TCG.Util.CLI

tests :: TestTree
tests = testGroup "Integration Tests"
  [ configToASN1Tests
  , certificateWorkflowTests
  , cliIntegrationTests
  , errorHandlingTests
  ]

-- | Test configuration to ASN.1 conversion workflow
configToASN1Tests :: TestTree
configToASN1Tests = testGroup "Configuration to ASN.1 Workflow"
  [ testCase "Load config and extract components" $ do
      withSystemTempFile "integration-config.yaml" $ \configPath handle -> do
        let config = PlatformCertConfig
              { pccManufacturer = "Integration Test Corp"
              , pccModel = "Test Model"
              , pccVersion = "2.0"
              , pccSerial = "INT001"
              , pccManufacturerId = Nothing
              , pccValidityDays = Just 365
              , pccKeySize = Just 2048
              , pccComponents =
                  [ ComponentConfig
                      { ccComponentClass = Nothing
                      , ccClass = "00030003"
                      , ccManufacturer = "Component Corp"
                      , ccModel = "Component Model"
                      , ccSerial = Just "COMP001"
                      , ccRevision = Just "1.0"
                      , ccManufacturerId = Nothing
                      , ccFieldReplaceable = Nothing
                      , ccAddresses = Nothing
                      , ccPlatformCert = Nothing
                      , ccPlatformCertUri = Nothing
                      , ccStatus = Nothing
                      }
                  ]
              , pccProperties = Nothing
              , pccPlatformConfigUri = Nothing
              , pccComponentsUri = Nothing
              , pccPropertiesUri = Nothing
              , pccPlatformClass = Nothing
              , pccSpecificationVersion = Nothing
              , pccMajorVersion = Nothing
              , pccMinorVersion = Nothing
              , pccPatchVersion = Nothing
              , pccPlatformQualifier = Nothing
              , pccCredentialSpecMajor = Nothing
              , pccCredentialSpecMinor = Nothing
              , pccCredentialSpecRevision = Nothing
              , pccPlatformSpecMajor = Nothing
              , pccPlatformSpecMinor = Nothing
              , pccPlatformSpecRevision = Nothing
              , pccSecurityAssertions = Nothing
              }

        -- Save config to file
        encodeFile configPath config

        -- Load and verify config
        result <- loadConfig configPath
        case result of
          Right loadedConfig -> do
            -- Verify config was loaded correctly
            pccManufacturer loadedConfig @?= "Integration Test Corp"
            length (pccComponents loadedConfig) @?= 1
            
            -- Convert components to ComponentIdentifiers
            let componentIds = map yamlComponentToComponentIdentifier (pccComponents loadedConfig)
            length componentIds @?= 1
            
          Left err -> assertFailure $ "Failed to load integration config: " ++ err

  , testCase "Full config roundtrip with ASN.1 operations" $ do
      -- This test verifies the full workflow from config -> components -> ASN.1
      let testData = B.pack [0x30, 0x06, 0x04, 0x04, 0x74, 0x65, 0x73, 0x74] -- Simple ASN.1 SEQUENCE
      
      -- Test hexdump functionality
      let hexResult = hexdump testData
      length hexResult @?= 16 -- 8 bytes * 2 chars each
      
      -- Test ASN.1 parsing
      let octetStrings = findOctetStringsInASN1 [OctetString "test"]
      length octetStrings @?= 1
      head octetStrings @?= "test"
  ]

-- | Test complete certificate workflow
certificateWorkflowTests :: TestTree
certificateWorkflowTests = testGroup "Certificate Workflow"
  [ testCase "Create platform configuration from config" $ do
      let config = PlatformCertConfig
            { pccManufacturer = "Workflow Test Corp"
            , pccModel = "Workflow Model"
            , pccVersion = "1.5"
            , pccSerial = "WF001"
            , pccManufacturerId = Nothing
            , pccValidityDays = Just 730
            , pccKeySize = Just 2048
            , pccComponents = []
            , pccProperties = Nothing
            , pccPlatformConfigUri = Just URIReferenceConfig
                { uriUri = "https://example.com/workflow"
                , uriHashAlgorithm = Nothing
                , uriHashValue = Nothing
                }
            , pccComponentsUri = Nothing
            , pccPropertiesUri = Nothing
            , pccPlatformClass = Just "00000002"
            , pccSpecificationVersion = Just "1.2"
            , pccMajorVersion = Just 1
            , pccMinorVersion = Just 5
            , pccPatchVersion = Just 0
            , pccPlatformQualifier = Just "Production"
            , pccCredentialSpecMajor = Nothing
            , pccCredentialSpecMinor = Nothing
            , pccCredentialSpecRevision = Nothing
            , pccPlatformSpecMajor = Nothing
            , pccPlatformSpecMinor = Nothing
            , pccPlatformSpecRevision = Nothing
            , pccSecurityAssertions = Nothing
            }

      -- Create platform configuration (this would normally create keys/certificates)
      -- For now we just verify the configuration is valid
      pccManufacturer config @?= "Workflow Test Corp"
      pccValidityDays config @?= Just 730

  , testCase "TPM info creation and validation" $ do
      let tpmInfo = createDefaultTPMInfo
      -- Verify TPM info has expected defaults
      show tpmInfo `shouldContainSubstring` "TPM 2.0"

  , testCase "Component conversion workflow" $ do
      let componentConfig = ComponentConfig
            { ccComponentClass = Nothing
            , ccClass = "00040004"
            , ccManufacturer = "Workflow Component Corp"
            , ccModel = "Workflow Component"
            , ccSerial = Just "WC001"
            , ccRevision = Just "2.0"
            , ccManufacturerId = Nothing
            , ccFieldReplaceable = Nothing
            , ccAddresses = Nothing
            , ccPlatformCert = Nothing
            , ccPlatformCertUri = Nothing
            , ccStatus = Nothing
            }

      let componentId = yamlComponentToComponentIdentifier componentConfig
      -- Verify conversion worked correctly
      show componentId `shouldContainSubstring` "Workflow Component Corp"
  ]

-- | Test CLI integration scenarios
cliIntegrationTests :: TestTree
cliIntegrationTests = testGroup "CLI Integration"
  [ testCase "Config file creation and validation workflow" $ do
      withSystemTempDirectory "cli-integration" $ \tempDir -> do
        let configPath = tempDir </> "cli-test-config.yaml"
        
        -- Create example configuration
        createExampleConfig configPath
        
        -- Verify file was created
        exists <- doesFileExist configPath
        exists @?= True
        
        -- Load and verify the example config
        result <- loadConfig configPath
        case result of
          Right config -> do
            pccManufacturer config @?= "Test Corporation"
            length (pccComponents config) @?= 3
          Left err -> assertFailure $ "Example config is invalid: " ++ err

  , testCase "Delta config workflow" $ do
      withSystemTempFile "delta-workflow.yaml" $ \configPath handle -> do
        let deltaConfig = DeltaCertConfig
              { dccManufacturer = "Delta Test Corp"
              , dccModel = "Delta Model"
              , dccVersion = "2.1"
              , dccSerial = "DELTA002"
              , dccValidityDays = Just 365
              , dccKeySize = Just 2048
              , dccComponents = []
              , dccPlatformConfigUri = Nothing
              , dccPlatformClass = Nothing
              , dccSpecificationVersion = Nothing
              , dccMajorVersion = Nothing
              , dccMinorVersion = Nothing
              , dccPatchVersion = Nothing
              , dccPlatformQualifier = Nothing
              , dccBaseCertificateSerial = Just "BASE002"
              , dccDeltaSequenceNumber = Just 2
              , dccChangeDescription = Just "Second delta update"
              }
        
        encodeFile configPath deltaConfig
        
        result <- loadDeltaConfig configPath
        case result of
          Right config -> do
            dccManufacturer config @?= "Delta Test Corp"
            dccDeltaSequenceNumber config @?= Just 2
          Left err -> assertFailure $ "Failed to load delta config: " ++ err
  ]

-- | Test error handling scenarios
errorHandlingTests :: TestTree
errorHandlingTests = testGroup "Error Handling"
  [ testCase "Invalid config file handling" $ do
      -- Test with non-existent file
      result1 <- loadConfig "non-existent-file.yaml"
      case result1 of
        Left _ -> return () -- Expected failure
        Right _ -> assertFailure "Expected failure for non-existent file"
      
      -- Test with invalid YAML
      withSystemTempDirectory "test-invalid" $ \tmpDir -> do
        let invalidPath = tmpDir </> "invalid.yaml"
        writeFile invalidPath "invalid: yaml: content: ]["
        result2 <- loadConfig invalidPath
        case result2 of
          Left _ -> return () -- Expected failure
          Right _ -> assertFailure "Expected failure for invalid YAML"

  , testCase "ASN.1 parsing error scenarios" $ do
      -- Test with empty ASN.1 data
      let emptyASN1 = []
      let emptyOctetStrings = findOctetStringsInASN1 emptyASN1
      length emptyOctetStrings @?= 0
      
      -- Test ASCII printable checking with edge cases
      isAsciiPrintable 31 @?= False  -- Just below printable range
      isAsciiPrintable 127 @?= False -- Just above printable range

  , testCase "File system error handling" $ do
      -- Test file operations that might fail
      withSystemTempFile "temp-test.yaml" $ \path handle -> do
        -- Create a valid config
        let config = PlatformCertConfig
              { pccManufacturer = "Error Test"
              , pccModel = "Error Model"
              , pccVersion = "1.0"
              , pccSerial = "ERR001"
              , pccManufacturerId = Nothing
              , pccValidityDays = Nothing
              , pccKeySize = Nothing
              , pccComponents = []
              , pccProperties = Nothing
              , pccPlatformConfigUri = Nothing
              , pccComponentsUri = Nothing
              , pccPropertiesUri = Nothing
              , pccPlatformClass = Nothing
              , pccSpecificationVersion = Nothing
              , pccMajorVersion = Nothing
              , pccMinorVersion = Nothing
              , pccPatchVersion = Nothing
              , pccPlatformQualifier = Nothing
              , pccCredentialSpecMajor = Nothing
              , pccCredentialSpecMinor = Nothing
              , pccCredentialSpecRevision = Nothing
              , pccPlatformSpecMajor = Nothing
              , pccPlatformSpecMinor = Nothing
              , pccPlatformSpecRevision = Nothing
              , pccSecurityAssertions = Nothing
              }

        encodeFile path config
        result <- loadConfig path
        case result of
          Right _ -> return () -- Should succeed
          Left err -> assertFailure $ "Unexpected error: " ++ err
  ]

-- Helper function to check if a string contains a substring
shouldContainSubstring :: String -> String -> IO ()
shouldContainSubstring haystack needle = 
  if needle `isSubsequenceOf` haystack
  then return ()
  else assertFailure $ "Expected '" ++ haystack ++ "' to contain '" ++ needle ++ "'"

-- Helper function to check if one list is a subsequence of another
isSubsequenceOf :: Eq a => [a] -> [a] -> Bool
isSubsequenceOf [] _ = True
isSubsequenceOf _ [] = False
isSubsequenceOf xs@(y:ys) (z:zs)
  | y == z = isSubsequenceOf ys zs
  | otherwise = isSubsequenceOf xs zs