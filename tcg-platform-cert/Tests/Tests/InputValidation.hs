{-# LANGUAGE OverloadedStrings #-}

-- |
-- Input validation rejection and acceptance tests.
-- Verifies that invalid inputs are rejected (Left) and valid inputs are accepted (Right).

module Tests.InputValidation (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import qualified Data.ByteString as B
import Data.Either (isRight, isLeft)
import Data.X509.TCG
  ( TBBSecurityAssertions(..)
  , ComponentConfigV2(..)
  , ExtendedTCGAttributes(..)
  , PlatformConfigUri(..)
  , defaultExtendedTCGAttributes
  )
import Data.X509.TCG.InputValidation
  ( validateTBBSecurityAssertions
  , validateComponentConfigV2
  , validateExtendedTCGAttributes
  )
import Tests.Arbitrary ()  -- Arbitrary instances

tests :: TestTree
tests = testGroup "Input Validation"
  [ tbbValidationTests
  , componentValidationTests
  , extendedAttrsValidationTests
  , validationPropertyTests
  ]

-- * Test Helpers

-- | Base TBB with minimal valid fields (version=0, all Nothing)
baseTBB :: TBBSecurityAssertions
baseTBB = TBBSecurityAssertions
  { tbbVersion = 0
  , tbbCCVersion = Nothing
  , tbbEvalAssuranceLevel = Nothing
  , tbbEvalStatus = Nothing
  , tbbPlus = Nothing
  , tbbStrengthOfFunction = Nothing
  , tbbProtectionProfileOID = Nothing
  , tbbProtectionProfileURI = Nothing
  , tbbSecurityTargetOID = Nothing
  , tbbSecurityTargetURI = Nothing
  , tbbFIPSVersion = Nothing
  , tbbFIPSSecurityLevel = Nothing
  , tbbFIPSPlus = Nothing
  , tbbRTMType = Nothing
  , tbbISO9000Certified = Nothing
  , tbbISO9000URI = Nothing
  }

-- | Base component with minimal valid fields
baseComp :: ComponentConfigV2
baseComp = ComponentConfigV2
  { ccv2Class = B.pack [0x00, 0x01, 0x00, 0x02]
  , ccv2Manufacturer = "TestMfg"
  , ccv2Model = "TestModel"
  , ccv2Serial = Nothing
  , ccv2Revision = Nothing
  , ccv2ManufacturerId = Nothing
  , ccv2FieldReplaceable = Nothing
  , ccv2Addresses = Nothing
  , ccv2PlatformCert = Nothing
  , ccv2PlatformCertUri = Nothing
  , ccv2Status = Nothing
  }

-- | Helper to assert Left result
assertLeft :: String -> Either String a -> Assertion
assertLeft msg result = case result of
  Left _ -> return ()
  Right _ -> assertFailure $ msg ++ ": expected Left but got Right"

-- | Helper to assert Left with specific substring in error message
assertLeftContains :: String -> String -> Either String a -> Assertion
assertLeftContains msg substr result = case result of
  Left err -> assertBool (msg ++ ": error should contain '" ++ substr ++ "' but got: " ++ err)
                         (substr `isInfixOf'` err)
  Right _ -> assertFailure $ msg ++ ": expected Left but got Right"
  where
    isInfixOf' needle haystack = any (needle `isPrefixOf'`) (tails' haystack)
    isPrefixOf' [] _ = True
    isPrefixOf' _ [] = False
    isPrefixOf' (x:xs) (y:ys) = x == y && isPrefixOf' xs ys
    tails' [] = [[]]
    tails' s@(_:xs) = s : tails' xs

-- * TBBSecurityAssertions Validation Tests

tbbValidationTests :: TestTree
tbbValidationTests = testGroup "TBBSecurityAssertions Validation"
  [ testGroup "Rejection (Left expected)"
    [ testCase "EAL = 0 (below range)" $
        assertLeftContains "EAL=0" "EvalAssuranceLevel" $
          validateTBBSecurityAssertions baseTBB
            { tbbEvalAssuranceLevel = Just 0, tbbCCVersion = Just "3.1" }

    , testCase "EAL = 8 (above range)" $
        assertLeftContains "EAL=8" "EvalAssuranceLevel" $
          validateTBBSecurityAssertions baseTBB
            { tbbEvalAssuranceLevel = Just 8, tbbCCVersion = Just "3.1" }

    , testCase "EAL = -1 (negative)" $
        assertLeftContains "EAL=-1" "EvalAssuranceLevel" $
          validateTBBSecurityAssertions baseTBB
            { tbbEvalAssuranceLevel = Just (-1), tbbCCVersion = Just "3.1" }

    , testCase "FIPS = 0 (below range)" $
        assertLeftContains "FIPS=0" "FIPSSecurityLevel" $
          validateTBBSecurityAssertions baseTBB
            { tbbFIPSSecurityLevel = Just 0, tbbFIPSVersion = Just "140-2" }

    , testCase "FIPS = 5 (above range)" $
        assertLeftContains "FIPS=5" "FIPSSecurityLevel" $
          validateTBBSecurityAssertions baseTBB
            { tbbFIPSSecurityLevel = Just 5, tbbFIPSVersion = Just "140-2" }

    , testCase "SOF = -1 (below range)" $
        assertLeftContains "SOF=-1" "StrengthOfFunction" $
          validateTBBSecurityAssertions baseTBB
            { tbbStrengthOfFunction = Just (-1) }

    , testCase "SOF = 3 (above range)" $
        assertLeftContains "SOF=3" "StrengthOfFunction" $
          validateTBBSecurityAssertions baseTBB
            { tbbStrengthOfFunction = Just 3 }

    , testCase "RTM = -1 (below range)" $
        assertLeftContains "RTM=-1" "RTMType" $
          validateTBBSecurityAssertions baseTBB
            { tbbRTMType = Just (-1) }

    , testCase "RTM = 6 (above range)" $
        assertLeftContains "RTM=6" "RTMType" $
          validateTBBSecurityAssertions baseTBB
            { tbbRTMType = Just 6 }

    , testCase "EvalStatus = 3 (above range)" $
        assertLeftContains "EvalStatus=3" "EvalStatus" $
          validateTBBSecurityAssertions baseTBB
            { tbbEvalStatus = Just 3 }

    , testCase "EvalStatus = -1 (negative)" $
        assertLeftContains "EvalStatus=-1" "EvalStatus" $
          validateTBBSecurityAssertions baseTBB
            { tbbEvalStatus = Just (-1) }

    , testCase "Version = 2 (invalid)" $
        assertLeftContains "version=2" "version" $
          validateTBBSecurityAssertions baseTBB { tbbVersion = 2 }

    , testCase "Version = -1 (negative)" $
        assertLeftContains "version=-1" "version" $
          validateTBBSecurityAssertions baseTBB { tbbVersion = -1 }

    , testCase "EAL set without ccVersion (consistency)" $
        assertLeftContains "EAL w/o ccVersion" "ccVersion" $
          validateTBBSecurityAssertions baseTBB
            { tbbEvalAssuranceLevel = Just 4, tbbCCVersion = Nothing }

    , testCase "EAL set with empty ccVersion" $
        assertLeftContains "EAL w/ empty ccVersion" "ccVersion" $
          validateTBBSecurityAssertions baseTBB
            { tbbEvalAssuranceLevel = Just 4, tbbCCVersion = Just B.empty }

    , testCase "FIPS level set without fipsVersion (consistency)" $
        assertLeftContains "FIPS w/o fipsVersion" "fipsVersion" $
          validateTBBSecurityAssertions baseTBB
            { tbbFIPSSecurityLevel = Just 2, tbbFIPSVersion = Nothing }

    , testCase "FIPS level set with empty fipsVersion" $
        assertLeftContains "FIPS w/ empty fipsVersion" "fipsVersion" $
          validateTBBSecurityAssertions baseTBB
            { tbbFIPSSecurityLevel = Just 2, tbbFIPSVersion = Just B.empty }
    ]

  , testGroup "Acceptance (Right expected)"
    [ testCase "Minimal valid (version=0, all Nothing)" $
        baseTBB `shouldPassTBB` ()

    , testCase "Full valid" $
        baseTBB
          { tbbVersion = 0
          , tbbEvalAssuranceLevel = Just 4
          , tbbCCVersion = Just "3.1"
          , tbbEvalStatus = Just 2
          , tbbPlus = Just True
          , tbbStrengthOfFunction = Just 1
          , tbbFIPSSecurityLevel = Just 2
          , tbbFIPSVersion = Just "140-2"
          , tbbFIPSPlus = Just False
          , tbbRTMType = Just 3
          , tbbISO9000Certified = Just True
          } `shouldPassTBB` ()

    , testCase "EAL boundary low (1)" $
        baseTBB { tbbEvalAssuranceLevel = Just 1, tbbCCVersion = Just "3.1" }
          `shouldPassTBB` ()

    , testCase "EAL boundary high (7)" $
        baseTBB { tbbEvalAssuranceLevel = Just 7, tbbCCVersion = Just "3.1" }
          `shouldPassTBB` ()

    , testCase "FIPS boundary low (1)" $
        baseTBB { tbbFIPSSecurityLevel = Just 1, tbbFIPSVersion = Just "140-2" }
          `shouldPassTBB` ()

    , testCase "FIPS boundary high (4)" $
        baseTBB { tbbFIPSSecurityLevel = Just 4, tbbFIPSVersion = Just "140-2" }
          `shouldPassTBB` ()

    , testCase "SOF boundary low (0)" $
        baseTBB { tbbStrengthOfFunction = Just 0 } `shouldPassTBB` ()

    , testCase "SOF boundary high (2)" $
        baseTBB { tbbStrengthOfFunction = Just 2 } `shouldPassTBB` ()

    , testCase "RTM boundary low (0)" $
        baseTBB { tbbRTMType = Just 0 } `shouldPassTBB` ()

    , testCase "RTM boundary high (5)" $
        baseTBB { tbbRTMType = Just 5 } `shouldPassTBB` ()

    , testCase "EvalStatus boundary low (0)" $
        baseTBB { tbbEvalStatus = Just 0 } `shouldPassTBB` ()

    , testCase "EvalStatus boundary high (2)" $
        baseTBB { tbbEvalStatus = Just 2 } `shouldPassTBB` ()
    ]
  ]
  where
    shouldPassTBB tbb _ =
      validateTBBSecurityAssertions tbb @?= Right ()

-- * ComponentConfigV2 Validation Tests

componentValidationTests :: TestTree
componentValidationTests = testGroup "ComponentConfigV2 Validation"
  [ testGroup "Rejection (Left expected)"
    [ testCase "Class empty (0 bytes)" $
        assertLeftContains "class=0" "componentClassValue" $
          validateComponentConfigV2 baseComp { ccv2Class = B.empty }

    , testCase "Class 3 bytes (too short)" $
        assertLeftContains "class=3" "componentClassValue" $
          validateComponentConfigV2 baseComp { ccv2Class = B.pack [0, 1, 2] }

    , testCase "Class 5 bytes (too long)" $
        assertLeftContains "class=5" "componentClassValue" $
          validateComponentConfigV2 baseComp { ccv2Class = B.pack [0, 1, 2, 3, 4] }

    , testCase "Manufacturer empty" $
        assertLeftContains "mfg empty" "manufacturer" $
          validateComponentConfigV2 baseComp { ccv2Manufacturer = B.empty }

    , testCase "Manufacturer exceeds STRMAX (256 bytes)" $
        assertLeftContains "mfg STRMAX" "STRMAX" $
          validateComponentConfigV2 baseComp { ccv2Manufacturer = B.replicate 256 0x41 }

    , testCase "Model empty" $
        assertLeftContains "model empty" "model" $
          validateComponentConfigV2 baseComp { ccv2Model = B.empty }

    , testCase "Model exceeds STRMAX (256 bytes)" $
        assertLeftContains "model STRMAX" "STRMAX" $
          validateComponentConfigV2 baseComp { ccv2Model = B.replicate 256 0x41 }

    , testCase "Serial exceeds STRMAX (256 bytes)" $
        assertLeftContains "serial STRMAX" "serial" $
          validateComponentConfigV2 baseComp { ccv2Serial = Just (B.replicate 256 0x41) }

    , testCase "Serial empty when present" $
        assertLeftContains "serial empty" "serial" $
          validateComponentConfigV2 baseComp { ccv2Serial = Just B.empty }

    , testCase "Revision exceeds STRMAX (256 bytes)" $
        assertLeftContains "revision STRMAX" "revision" $
          validateComponentConfigV2 baseComp { ccv2Revision = Just (B.replicate 256 0x41) }

    , testCase "Revision empty when present" $
        assertLeftContains "revision empty" "revision" $
          validateComponentConfigV2 baseComp { ccv2Revision = Just B.empty }
    ]

  , testGroup "Acceptance (Right expected)"
    [ testCase "Minimal valid" $
        validateComponentConfigV2 baseComp @?= Right ()

    , testCase "Manufacturer 1 byte (boundary)" $
        validateComponentConfigV2 baseComp { ccv2Manufacturer = "A" } @?= Right ()

    , testCase "Manufacturer 255 bytes (boundary)" $
        validateComponentConfigV2 baseComp { ccv2Manufacturer = B.replicate 255 0x41 }
          @?= Right ()

    , testCase "With optional serial and revision" $
        validateComponentConfigV2 baseComp
          { ccv2Serial = Just "SN001", ccv2Revision = Just "1.0" }
          @?= Right ()
    ]
  ]

-- * ExtendedTCGAttributes Validation Tests

extendedAttrsValidationTests :: TestTree
extendedAttrsValidationTests = testGroup "ExtendedTCGAttributes Validation"
  [ testGroup "Rejection (Left expected)"
    [ testCase "Invalid TBB propagates error" $
        assertLeftContains "TBB propagation" "EvalAssuranceLevel" $
          validateExtendedTCGAttributes defaultExtendedTCGAttributes
            { etaSecurityAssertions = Just baseTBB
                { tbbEvalAssuranceLevel = Just 99, tbbCCVersion = Just "3.1" }
            }

    , testCase "Invalid component propagates error" $
        assertLeftContains "Component propagation" "componentClassValue" $
          validateExtendedTCGAttributes defaultExtendedTCGAttributes
            { etaComponentsV2 = Just [baseComp { ccv2Class = B.empty }]
            }

    , testCase "URI exceeds URIMAX (1025 bytes)" $
        assertLeftContains "URI URIMAX" "platformConfigUri" $
          validateExtendedTCGAttributes defaultExtendedTCGAttributes
            { etaPlatformConfigUri = Just $ PlatformConfigUri
                (B.replicate 1025 0x41) Nothing Nothing
            }

    , testCase "URI empty (0 bytes)" $
        assertLeftContains "URI empty" "platformConfigUri" $
          validateExtendedTCGAttributes defaultExtendedTCGAttributes
            { etaPlatformConfigUri = Just $ PlatformConfigUri
                B.empty Nothing Nothing
            }

    , testCase "Hash pair: algorithm set, value missing" $
        assertLeftContains "hash pair" "hashValue" $
          validateExtendedTCGAttributes defaultExtendedTCGAttributes
            { etaPlatformConfigUri = Just $ PlatformConfigUri
                "https://example.com" (Just "sha256") Nothing
            }

    , testCase "Hash pair: value set, algorithm missing" $
        assertLeftContains "hash pair" "hashAlgorithm" $
          validateExtendedTCGAttributes defaultExtendedTCGAttributes
            { etaPlatformConfigUri = Just $ PlatformConfigUri
                "https://example.com" Nothing (Just "deadbeef")
            }

    , testCase "Negative credential spec version" $
        assertLeftContains "cred spec negative" "credentialSpecVersion" $
          validateExtendedTCGAttributes defaultExtendedTCGAttributes
            { etaCredentialSpecVersion = Just (-1, 0, 0) }

    , testCase "Negative platform spec version" $
        assertLeftContains "plat spec negative" "platformSpecVersion" $
          validateExtendedTCGAttributes defaultExtendedTCGAttributes
            { etaPlatformSpecVersion = Just (1, -1, 0) }
    ]

  , testGroup "Acceptance (Right expected)"
    [ testCase "Default (all Nothing)" $
        validateExtendedTCGAttributes defaultExtendedTCGAttributes @?= Right ()

    , testCase "Full valid" $
        validateExtendedTCGAttributes defaultExtendedTCGAttributes
          { etaSecurityAssertions = Just baseTBB
          , etaComponentsV2 = Just [baseComp]
          , etaPlatformConfigUri = Just $ PlatformConfigUri
              "https://example.com" (Just "sha256") (Just "abcd1234")
          , etaCredentialSpecVersion = Just (2, 0, 0)
          , etaPlatformSpecVersion = Just (1, 1, 0)
          } @?= Right ()

    , testCase "URI at URIMAX boundary (1024 bytes)" $
        validateExtendedTCGAttributes defaultExtendedTCGAttributes
          { etaPlatformConfigUri = Just $ PlatformConfigUri
              (B.replicate 1024 0x41) Nothing Nothing
          } @?= Right ()
    ]
  ]

-- * QuickCheck Property Tests

validationPropertyTests :: TestTree
validationPropertyTests = testGroup "Validation Properties"
  [ testProperty "Valid Arbitrary TBBSecurityAssertions always passes" $
      \tbb -> isRight (validateTBBSecurityAssertions tbb)

  , testProperty "Valid Arbitrary ComponentConfigV2 always passes" $
      \comp -> isRight (validateComponentConfigV2 comp)

  , testProperty "Out-of-range EAL always fails" $
      forAll (choose (8, 100)) $ \eal ->
        isLeft $ validateTBBSecurityAssertions baseTBB
          { tbbEvalAssuranceLevel = Just eal, tbbCCVersion = Just "3.1" }

  , testProperty "Out-of-range FIPS always fails" $
      forAll (choose (5, 100)) $ \fips ->
        isLeft $ validateTBBSecurityAssertions baseTBB
          { tbbFIPSSecurityLevel = Just fips, tbbFIPSVersion = Just "140-2" }

  , testProperty "Out-of-range RTM always fails" $
      forAll (choose (6, 100)) $ \rtm ->
        isLeft $ validateTBBSecurityAssertions baseTBB
          { tbbRTMType = Just rtm }
  ]
