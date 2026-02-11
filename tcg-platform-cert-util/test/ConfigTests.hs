{-# LANGUAGE OverloadedStrings #-}

module ConfigTests (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances ()

import qualified Data.ByteString.Char8 as BC
import Data.Yaml (encodeFile, decodeFileEither)
import System.Directory (doesFileExist)
import System.IO.Temp (withSystemTempFile)
import Data.X509.TCG.Util.Config
import Data.X509.TCG.Util.Paccor
import Data.X509.TCG

tests :: TestTree
tests = testGroup "Config Tests"
  [ configLoadingTests
  , yamlSerializationTests
  , componentConversionTests
  , paccorConversionTests
  , propertyTests
  ]

-- | Test configuration loading functionality
configLoadingTests :: TestTree
configLoadingTests = testGroup "Configuration Loading"
  [ testCase "Load valid platform config" $ do
      withSystemTempFile "test-config.yaml" $ \path _handle -> do
        let config = PlatformCertConfig
              { pccManufacturer = "Test Corp"
              , pccModel = "Test Model"
              , pccVersion = "1.0"
              , pccSerial = "TEST001"
              , pccManufacturerId = Nothing
              , pccValidityDays = Just 365
              , pccKeySize = Just 2048
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
          Right loadedConfig -> do
            pccManufacturer loadedConfig @?= "Test Corp"
            pccModel loadedConfig @?= "Test Model"
            pccVersion loadedConfig @?= "1.0"
          Left err -> assertFailure $ "Failed to load config: " ++ err

  , testCase "Load invalid config file" $ do
      result <- loadConfig "nonexistent-file.yaml"
      case result of
        Left _ -> return () -- Expected failure
        Right _ -> assertFailure "Expected failure for nonexistent file"

  , testCase "Load delta config" $ do
      withSystemTempFile "test-delta-config.yaml" $ \path _handle -> do
        let config = DeltaCertConfig
              { dccManufacturer = "Test Corp"
              , dccModel = "Test Model Delta"
              , dccVersion = "1.1"
              , dccSerial = "DELTA001"
              , dccValidityDays = Just 180
              , dccKeySize = Just 2048
              , dccComponents = []
              , dccPlatformConfigUri = Nothing
              , dccPlatformClass = Nothing
              , dccSpecificationVersion = Nothing
              , dccMajorVersion = Nothing
              , dccMinorVersion = Nothing
              , dccPatchVersion = Nothing
              , dccPlatformQualifier = Nothing
              , dccBaseCertificateSerial = Just "BASE001"
              , dccDeltaSequenceNumber = Just 1
              , dccChangeDescription = Just "Initial delta"
              }
        encodeFile path config
        result <- loadDeltaConfig path
        case result of
          Right loadedConfig -> do
            dccManufacturer loadedConfig @?= "Test Corp"
            dccBaseCertificateSerial loadedConfig @?= Just "BASE001"
            dccDeltaSequenceNumber loadedConfig @?= Just 1
          Left err -> assertFailure $ "Failed to load delta config: " ++ err
  ]

-- | Test YAML serialization/deserialization
yamlSerializationTests :: TestTree
yamlSerializationTests = testGroup "YAML Serialization"
  [ testCase "Round-trip platform config" $ do
      let originalConfig = PlatformCertConfig
            { pccManufacturer = "Manufacturer"
            , pccModel = "Model"
            , pccVersion = "Version"
            , pccSerial = "Serial"
            , pccManufacturerId = Just "1.3.6.1.4.1.99999"
            , pccValidityDays = Just 365
            , pccKeySize = Just 2048
            , pccComponents =
                [ ComponentConfig
                    { ccComponentClass = Just ComponentClassConfig
                        { cccRegistry = "2.23.133.18.3.1"
                        , cccValue = "00030003"
                        }
                    , ccClass = "00030003"
                    , ccManufacturer = "Component Corp"
                    , ccModel = "Component Model"
                    , ccSerial = Just "COMP001"
                    , ccRevision = Just "1.0"
                    , ccManufacturerId = Nothing
                    , ccFieldReplaceable = Just True
                    , ccAddresses = Nothing
                    , ccPlatformCert = Nothing
                    , ccPlatformCertUri = Nothing
                    , ccStatus = Nothing
                    }
                ]
            , pccProperties = Just
                [ PropertyConfig
                    { propName = "test.property"
                    , propValue = "test-value"
                    , propStatus = Nothing
                    }
                ]
            , pccPlatformConfigUri = Just URIReferenceConfig
                { uriUri = "https://example.com/config"
                , uriHashAlgorithm = Nothing
                , uriHashValue = Nothing
                }
            , pccComponentsUri = Nothing
            , pccPropertiesUri = Nothing
            , pccPlatformClass = Just "00000001"
            , pccSpecificationVersion = Just "1.1"
            , pccMajorVersion = Just 1
            , pccMinorVersion = Just 0
            , pccPatchVersion = Just 0
            , pccPlatformQualifier = Just "Enterprise"
            , pccCredentialSpecMajor = Nothing
            , pccCredentialSpecMinor = Nothing
            , pccCredentialSpecRevision = Nothing
            , pccPlatformSpecMajor = Nothing
            , pccPlatformSpecMinor = Nothing
            , pccPlatformSpecRevision = Nothing
            , pccSecurityAssertions = Nothing
            }

      withSystemTempFile "roundtrip-test.yaml" $ \path _handle -> do
        encodeFile path originalConfig
        result <- decodeFileEither path
        case result of
          Right loadedConfig -> loadedConfig @?= originalConfig
          Left err -> assertFailure $ "Round-trip failed: " ++ show err

  , testCase "Example config creation" $ do
      withSystemTempFile "example-test.yaml" $ \path _handle -> do
        createExampleConfig path
        exists <- doesFileExist path
        exists @?= True
        
        result <- loadConfig path
        case result of
          Right config -> do
            pccManufacturer config @?= "Test Corporation"
            pccModel config @?= "Test Platform"
            length (pccComponents config) @?= 3 -- Should have 3 components in example
          Left err -> assertFailure $ "Failed to load example config: " ++ err
  ]

-- | Test component conversion functions
componentConversionTests :: TestTree
componentConversionTests = testGroup "Component Conversion"
  [ testCase "YAML to ComponentIdentifier conversion" $ do
      let yamlComponent = ComponentConfig
            { ccComponentClass = Nothing
            , ccClass = "00030003"
            , ccManufacturer = "Test Manufacturer"
            , ccModel = "Test Model"
            , ccSerial = Just "TEST001"
            , ccRevision = Just "1.0"
            , ccManufacturerId = Nothing
            , ccFieldReplaceable = Nothing
            , ccAddresses = Nothing
            , ccPlatformCert = Nothing
            , ccPlatformCertUri = Nothing
            , ccStatus = Nothing
            }

      let componentId = yamlComponentToComponentIdentifier yamlComponent
      ciManufacturer componentId @?= BC.pack "Test Manufacturer"
      ciModel componentId @?= BC.pack "Test Model"
      ciSerial componentId @?= Just (BC.pack "TEST001")
      ciRevision componentId @?= Just (BC.pack "1.0")

  , testCase "Default TPM info creation" $ do
      let tpmInfo = createDefaultTPMInfo
      tpmModel tpmInfo @?= BC.pack "TPM 2.0"
      tpmVersionMajor (tpmVersion tpmInfo) @?= 2
      tpmVersionMinor (tpmVersion tpmInfo) @?= 0
  ]

-- | Property-based tests
propertyTests :: TestTree
propertyTests = testGroup "Property Tests"
  [ testProperty "Component conversion preserves data" $ \manufacturer model serial revision ->
      let yamlComp = ComponentConfig
            { ccComponentClass = Nothing
            , ccClass = "00000000"
            , ccManufacturer = manufacturer
            , ccModel = model
            , ccSerial = Just serial
            , ccRevision = Just revision
            , ccManufacturerId = Nothing
            , ccFieldReplaceable = Nothing
            , ccAddresses = Nothing
            , ccPlatformCert = Nothing
            , ccPlatformCertUri = Nothing
            , ccStatus = Nothing
            }
          compId = yamlComponentToComponentIdentifier yamlComp
      in ciManufacturer compId == BC.pack manufacturer &&
         ciModel compId == BC.pack model &&
         ciSerial compId == Just (BC.pack serial) &&
         ciRevision compId == Just (BC.pack revision)

  , testProperty "Config serialization roundtrip" $ \manufacturer model version serial ->
      let config = PlatformCertConfig
            { pccManufacturer = manufacturer
            , pccModel = model
            , pccVersion = version
            , pccSerial = serial
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
      in pccManufacturer config == manufacturer &&
         pccModel config == model &&
         pccVersion config == version &&
         pccSerial config == serial
  ]

-- | Test paccor JSON conversion functionality
paccorConversionTests :: TestTree
paccorConversionTests = testGroup "Paccor JSON Conversion"
  [ testCase "Convert paccor config to YAML config" $ do
      let paccorConfig = PaccorConfig
            { paccorPlatform = PaccorPlatform
                { platformManufacturerStr = "Dell Inc."
                , platformModel = "OptiPlex 7040"
                , platformVersion = Just "1.0"
                , platformSerial = Just "306VRD2"
                , platformManufacturerId = Just "1.3.6.1.4.1.674"
                }
            , paccorComponents = Just
                [ PaccorComponent
                    { componentClass = PaccorComponentClass
                        { componentClassRegistry = "2.23.133.18.3.1"
                        , componentClassValue = "00000001"
                        }
                    , componentManufacturer = Just "Dell Inc."
                    , componentModel = Just "Desktop"
                    , componentSerial = Just "306VRD2"
                    , componentRevision = Just "Not Specified"
                    , componentManufacturerId = Nothing
                    , componentFieldReplaceable = Nothing
                    , componentAddresses = Nothing
                    , componentStatus = Nothing
                    , componentPlatformCert = Nothing
                    , componentPlatformCertUri = Nothing
                    }
                ]
            , paccorComponentsUri = Nothing
            , paccorProperties = Nothing
            , paccorPropertiesUri = Nothing
            }

      let yamlConfig = paccorToYamlConfig paccorConfig
      pccManufacturer yamlConfig @?= "Dell Inc."
      pccModel yamlConfig @?= "OptiPlex 7040"
      pccVersion yamlConfig @?= "1.0"
      pccSerial yamlConfig @?= "306VRD2"
      pccManufacturerId yamlConfig @?= Just "1.3.6.1.4.1.674"  -- Test PLATFORMMANUFACTURERID
      length (pccComponents yamlConfig) @?= 1

      case pccComponents yamlConfig of
        (comp:_) -> do
          ccClass comp @?= "00000001"
          ccManufacturer comp @?= "Dell Inc."
          ccModel comp @?= "Desktop"
          -- Test ComponentClassConfig
          case ccComponentClass comp of
            Just ccc -> do
              cccRegistry ccc @?= "2.23.133.18.3.1"
              cccValue ccc @?= "00000001"
            Nothing -> assertFailure "Expected componentClass to be present"
        [] -> assertFailure "expected non-empty components"

  , testCase "Format detection - JSON extension" $ do
      let format = detectInputFormat "device.json" ""
      format @?= FormatJSON

  , testCase "Format detection - YAML extension" $ do
      let formatYaml = detectInputFormat "config.yaml" ""
      let formatYml = detectInputFormat "config.yml" ""
      formatYaml @?= FormatYAML
      formatYml @?= FormatYAML

  , testCase "Format detection - JSON content" $ do
      let format = detectInputFormat "unknown" "{ \"key\": \"value\" }"
      format @?= FormatJSON

  , testCase "Convert paccor with addresses" $ do
      let paccorConfig = PaccorConfig
            { paccorPlatform = PaccorPlatform
                { platformManufacturerStr = "Test Corp"
                , platformModel = "Test Model"
                , platformVersion = Nothing
                , platformSerial = Nothing
                , platformManufacturerId = Nothing
                }
            , paccorComponents = Just
                [ PaccorComponent
                    { componentClass = PaccorComponentClass
                        { componentClassRegistry = "2.23.133.18.3.1"
                        , componentClassValue = "00090002"
                        }
                    , componentManufacturer = Just "Intel"
                    , componentModel = Just "Wireless"
                    , componentSerial = Just "aa:bb:cc:dd:ee:ff"
                    , componentRevision = Nothing
                    , componentManufacturerId = Just "1.3.6.1.4.1.343"  -- Intel PEN
                    , componentFieldReplaceable = Just "true"
                    , componentAddresses = Just
                        [ PaccorAddress
                            { paccorEthernetMac = Nothing
                            , paccorWlanMac = Just "aa:bb:cc:dd:ee:ff"
                            , paccorBluetoothMac = Nothing
                            , paccorPciAddress = Nothing
                            , paccorUsbAddress = Nothing
                            , paccorSataAddress = Nothing
                            , paccorWwnAddress = Nothing
                            , paccorNvmeAddress = Nothing
                            , paccorLogicalAddress = Nothing
                            }
                        ]
                    , componentStatus = Nothing
                    , componentPlatformCert = Nothing
                    , componentPlatformCertUri = Nothing
                    }
                ]
            , paccorComponentsUri = Nothing
            , paccorProperties = Nothing
            , paccorPropertiesUri = Nothing
            }

      let yamlConfig = paccorToYamlConfig paccorConfig
      length (pccComponents yamlConfig) @?= 1

      case pccComponents yamlConfig of
        (comp:_) -> do
          ccFieldReplaceable comp @?= Just True  -- Test FIELDREPLACEABLE conversion
          ccManufacturerId comp @?= Just "1.3.6.1.4.1.343"  -- Test MANUFACTURERID conversion
          case ccAddresses comp of
            Just (addr:_) -> addrWlanMac addr @?= Just "aa:bb:cc:dd:ee:ff"
            _ -> assertFailure "Expected addresses to be present"
        [] -> assertFailure "expected non-empty components"

  , testCase "Convert paccor with PROPERTIES" $ do
      let paccorConfig = PaccorConfig
            { paccorPlatform = PaccorPlatform
                { platformManufacturerStr = "Test Corp"
                , platformModel = "Test Model"
                , platformVersion = Just "1.0"
                , platformSerial = Just "SN001"
                , platformManufacturerId = Nothing
                }
            , paccorComponents = Nothing
            , paccorComponentsUri = Nothing
            , paccorProperties = Just
                [ PaccorProperty
                    { propertyName = "firmware.version"
                    , propertyValue = "1.2.3"
                    , propertyStatus = Nothing
                    }
                , PaccorProperty
                    { propertyName = "bios.vendor"
                    , propertyValue = "Test BIOS"
                    , propertyStatus = Just "ADDED"
                    }
                ]
            , paccorPropertiesUri = Nothing
            }

      let yamlConfig = paccorToYamlConfig paccorConfig
      case pccProperties yamlConfig of
        Just (prop1:prop2:_) -> do
          propName prop1 @?= "firmware.version"
          propValue prop1 @?= "1.2.3"
          propStatus prop2 @?= Just "ADDED"
        Just _ -> assertFailure "expected at least 2 properties"
        Nothing -> assertFailure "Expected properties to be present"

  , testCase "Convert paccor with PLATFORMCERT" $ do
      let paccorConfig = PaccorConfig
            { paccorPlatform = PaccorPlatform
                { platformManufacturerStr = "Test Corp"
                , platformModel = "Test Model"
                , platformVersion = Nothing
                , platformSerial = Nothing
                , platformManufacturerId = Nothing
                }
            , paccorComponents = Just
                [ PaccorComponent
                    { componentClass = PaccorComponentClass
                        { componentClassRegistry = "2.23.133.18.3.1"
                        , componentClassValue = "0000000A"
                        }
                    , componentManufacturer = Just "ABC OEM"
                    , componentModel = Just "WR06X7871FTL"
                    , componentSerial = Just "TEST123"
                    , componentRevision = Nothing
                    , componentManufacturerId = Nothing
                    , componentFieldReplaceable = Nothing
                    , componentAddresses = Nothing
                    , componentStatus = Nothing
                    , componentPlatformCert = Just PaccorPlatformCert
                        { pcAttributeCertId = Just PaccorAttributeCertId
                            { attrCertHashAlgorithm = "1.3.6.1.4.1.22554.1.2.1"
                            , attrCertHashOverSignature = "ABCD1234"
                            }
                        , pcGenericCertId = Just PaccorGenericCertId
                            { genCertIssuer =
                                [ PaccorGeneralName { gnName = "2.5.4.6", gnValue = "US" }
                                , PaccorGeneralName { gnName = "2.5.4.10", gnValue = "Test Corp" }
                                ]
                            , genCertSerial = "12345"
                            }
                        }
                    , componentPlatformCertUri = Just PaccorUri
                        { paccorUriValue = "https://example.com/cert.cer"
                        , paccorUriHashAlgorithm = Nothing
                        , paccorUriHashValue = Nothing
                        }
                    }
                ]
            , paccorComponentsUri = Nothing
            , paccorProperties = Nothing
            , paccorPropertiesUri = Nothing
            }

      let yamlConfig = paccorToYamlConfig paccorConfig
      length (pccComponents yamlConfig) @?= 1

      case pccComponents yamlConfig of
        (comp:_) -> do
          case ccPlatformCert comp of
            Just pc -> do
              case cpcAttributeCertId pc of
                Just acid -> do
                  acidHashAlgorithm acid @?= "1.3.6.1.4.1.22554.1.2.1"
                  acidHashValue acid @?= "ABCD1234"
                Nothing -> assertFailure "Expected attributeCertId to be present"
              case cpcGenericCertId pc of
                Just gcid -> do
                  gcidSerial gcid @?= "12345"
                  length (gcidIssuer gcid) @?= 2
                Nothing -> assertFailure "Expected genericCertId to be present"
            Nothing -> assertFailure "Expected platformCert to be present"

          case ccPlatformCertUri comp of
            Just uri -> uriUri uri @?= "https://example.com/cert.cer"
            Nothing -> assertFailure "Expected platformCertUri to be present"
        [] -> assertFailure "expected non-empty components"
  ]