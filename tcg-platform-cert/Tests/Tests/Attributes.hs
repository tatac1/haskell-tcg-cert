module Tests.Attributes (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Data.X509.TCG.Attributes
import Data.X509.TCG.OID
import Data.X509.TCG.Platform (TPMVersion(..), TPMSpecification(..))
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as BS

tests :: TestTree  
tests = testGroup "TCG Attributes Tests"
  [ testGroup "Attribute OID Mapping"
    [ testCase "attributeOIDToType mappings" $ do
        attributeOIDToType tcg_at_platformConfiguration @?= "platformConfiguration"
        attributeOIDToType tcg_at_platformConfiguration_v2 @?= "platformConfiguration_v2"
        attributeOIDToType tcg_at_componentIdentifier @?= "componentIdentifier"
        attributeOIDToType tcg_at_componentIdentifier_v2 @?= "componentIdentifier_v2"
    ]
  , testGroup "Required Attributes"
    [ testCase "isRequiredAttribute checks" $ do
        isRequiredAttribute tcg_at_platformConfiguration_v2 @?= True
        isRequiredAttribute tcg_at_componentIdentifier_v2 @?= True
        isRequiredAttribute tcg_paa_platformManufacturer @?= False
    ]
  , testGroup "Critical Attributes"
    [ testCase "isCriticalAttribute checks" $ do
        isCriticalAttribute tcg_ce_relevantCredentials @?= True
        isCriticalAttribute tcg_ce_relevantManifests @?= True
        isCriticalAttribute tcg_at_platformConfiguration_v2 @?= False
    ]
  , testGroup "Attribute Parsing Functions"
    [ testCase "parsePlatformConfigAttr handles invalid input" $ do
        -- Test that parsePlatformConfigAttr function exists and handles invalid input
        let result = parsePlatformConfigAttr []
        case result of
          Left _ -> True @?= True  -- Should fail with empty input
          Right _ -> assertFailure "Expected Left for empty input"
    , testCase "parsePlatformConfigV2Attr handles invalid input" $ do
        -- Test that parsePlatformConfigV2Attr function exists and handles invalid input
        let result = parsePlatformConfigV2Attr []
        case result of
          Left _ -> True @?= True  -- Should fail with empty input
          Right _ -> assertFailure "Expected Left for empty input"
    , testCase "parseComponentIdAttr handles invalid input" $ do
        -- Test that parseComponentIdAttr function exists and handles invalid input
        let result = parseComponentIdAttr []
        case result of
          Left _ -> True @?= True  -- Should fail with empty input
          Right _ -> assertFailure "Expected Left for empty input"
    , testCase "parseComponentIdV2Attr handles invalid input" $ do
        -- Test that parseComponentIdV2Attr function exists and handles invalid input
        let result = parseComponentIdV2Attr []
        case result of
          Left _ -> True @?= True  -- Should fail with empty input
          Right _ -> assertFailure "Expected Left for empty input"
    , testCase "parseTPMVersionAttr handles invalid input" $ do
        -- Test that parseTPMVersionAttr function exists and handles invalid input
        let result = parseTPMVersionAttr []
        case result of
          Left _ -> True @?= True  -- Should fail with empty input
          Right _ -> assertFailure "Expected Left for empty input"
    , testCase "parseTPMVersionAttr parses valid TPM version" $ do
        -- Create a valid TPM version and encode it
        let tpmVersion = TPMVersion 1 2 3 4
            asn1List = toASN1 tpmVersion []
            encodedBytes = L.toStrict $ encodeASN1 DER asn1List
            result = parseTPMVersionAttr [[OctetString encodedBytes]]
        case result of
          Right (TCGTPMVersion (TPMVersionAttr parsedVersion)) -> 
            parsedVersion @?= tpmVersion
          Left err -> assertFailure $ "Expected successful parse, got error: " ++ err
          Right _ -> assertFailure "Expected TCGTPMVersion constructor"
    , testCase "parseTPMSpecAttr handles invalid input" $ do
        -- Test that parseTPMSpecAttr function exists and handles invalid input
        let result = parseTPMSpecAttr []
        case result of
          Left _ -> True @?= True  -- Should fail with empty input
          Right _ -> assertFailure "Expected Left for empty input"
    , testCase "parseTPMSpecAttr parses valid TPM specification" $ do
        -- Create a valid TPM specification and encode it
        let tpmSpec = TPMSpecification (BS.pack [0x54, 0x50, 0x4D]) 2 116  -- "TPM" family, level 2, revision 116
            asn1List = toASN1 tpmSpec []
            encodedBytes = L.toStrict $ encodeASN1 DER asn1List
            result = parseTPMSpecAttr [[OctetString encodedBytes]]
        case result of
          Right (TCGTPMSpecification (TPMSpecificationAttr parsedSpec)) -> 
            parsedSpec @?= tpmSpec
          Left err -> assertFailure $ "Expected successful parse, got error: " ++ err
          Right _ -> assertFailure "Expected TCGTPMSpecification constructor"
    , testCase "parseRelevantCredAttr handles invalid input" $ do
        -- Test that parseRelevantCredAttr function exists and handles invalid input
        let result = parseRelevantCredAttr []
        case result of
          Left _ -> True @?= True  -- Should fail with empty input
          Right _ -> assertFailure "Expected Left for empty input"
    , testCase "parseRelevantCredAttr parses valid credentials" $ do
        -- Create a valid RelevantCredentials structure manually as ASN.1
        let cred1 = BS.pack [0x01, 0x02, 0x03]
            cred2 = BS.pack [0x04, 0x05, 0x06]
            critical = True
            -- Structure: SEQUENCE { SEQUENCE { OctetString cred1, OctetString cred2 }, BOOLEAN critical }
            asn1List = [Start Sequence, Start Sequence, OctetString cred1, OctetString cred2, End Sequence, Boolean critical, End Sequence]
            encodedBytes = L.toStrict $ encodeASN1 DER asn1List
            result = parseRelevantCredAttr [[OctetString encodedBytes]]
        case result of
          Right (TCGRelevantCredentials (RelevantCredentialsAttr credentials criticality)) -> do
            credentials @?= [cred1, cred2]
            criticality @?= critical
          Left err -> assertFailure $ "Expected successful parse, got error: " ++ err
          Right _ -> assertFailure "Expected TCGRelevantCredentials constructor"
    ]
  ]
