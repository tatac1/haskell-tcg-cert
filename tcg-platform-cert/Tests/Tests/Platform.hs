module Tests.Platform (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import qualified Data.ByteString.Char8 as B
import Data.ASN1.Types
import Data.X509.TCG.Platform
import Tests.Arbitrary()

tests :: TestTree
tests = testGroup "Platform Certificate Tests"
  [ testGroup "PlatformInfo"
    [ testCase "PlatformInfo creation" $ do
        let info = PlatformInfo (B.pack "TestMfg") (B.pack "TestModel") (B.pack "12345") (B.pack "1.0")
        piManufacturer info @?= B.pack "TestMfg"
        piModel info @?= B.pack "TestModel" 
        piSerial info @?= B.pack "12345"
        piVersion info @?= B.pack "1.0"
    ]
  , testGroup "TPMInfo"
    [ testCase "TPMInfo creation" $ do
        let version = TPMVersion 2 0 1 59
            spec = TPMSpecification (B.pack "2.0") 116 1
            info = TPMInfo (B.pack "TestTPM") version spec
        tpmModel info @?= B.pack "TestTPM"
    ]
  , testGroup "PlatformConfiguration"
    [ testCase "PlatformConfiguration creation" $ do
        let config = PlatformConfiguration (B.pack "TestMfg") (B.pack "TestModel") (B.pack "1.0") (B.pack "12345") []
        pcManufacturer config @?= B.pack "TestMfg"
        pcModel config @?= B.pack "TestModel"
        pcVersion config @?= B.pack "1.0"
        pcSerial config @?= B.pack "12345"
        pcComponents config @?= []
    ]
  , testGroup "ASN.1 Parsing Functions"
    [ testCase "parseTPMVersion with invalid data" $ do
        let result = parseTPMVersion (B.pack "invalid")
        result @?= Nothing
    , testCase "parseTPMSpecification with invalid data" $ do
        let result = parseTPMSpecification (B.pack "invalid") 
        result @?= Nothing
    , testCase "parsePlatformConfiguration with invalid data" $ do
        let result = parsePlatformConfiguration (OctetString (B.pack "invalid"))
        result @?= Nothing
    ]
  , testGroup "Specification Compliance"
    [ testCase "TPMVersion structure matches spec section 3.1.11" $ do
        let version = TPMVersion 2 0 1 59
            asn1 = toASN1 version []
            expected = [Start Sequence, IntVal 2, IntVal 0, IntVal 1, IntVal 59, End Sequence]
        asn1 @?= expected
    , testCase "TPMSpecification structure matches spec section 3.1.12" $ do
        let spec = TPMSpecification (B.pack "2.0") 116 1
            asn1 = toASN1 spec []
            expected = [Start Sequence, OctetString (B.pack "2.0"), IntVal 116, IntVal 1, End Sequence]
        asn1 @?= expected
    , testCase "ComponentStatus enum values match specification" $ do
        let statuses = [ComponentAdded, ComponentModified, ComponentRemoved]
            expected = [IntVal 0, IntVal 1, IntVal 2]
            actual = map (\s -> case toASN1 s [] of
              (x:_) -> x
              [] -> error "toASN1 returned empty list") statuses
        actual @?= expected
    , testCase "ComponentStatus rejects non-standard enum value" $ do
        case (fromASN1 [IntVal 3] :: Either String (ComponentStatus, [ASN1])) of
          Left _ -> pure ()
          Right _ -> assertFailure "Expected ComponentStatus to reject enum value 3"
    ]
  , testGroup "Property-based Tests"
    [ testProperty "TPMVersion ASN.1 roundtrip" $ \version ->
        let asn1 = toASN1 (version :: TPMVersion) []
        in case fromASN1 asn1 of
             Right (parsed, []) -> parsed == version
             _ -> False
    , testProperty "TPMSpecification ASN.1 roundtrip" $ \spec ->
        let asn1 = toASN1 (spec :: TPMSpecification) []
        in case fromASN1 asn1 of
             Right (parsed, []) -> parsed == spec
             _ -> False
    ]
  ]
