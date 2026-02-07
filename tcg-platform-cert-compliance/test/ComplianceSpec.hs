{-# LANGUAGE OverloadedStrings #-}

-- | Compliance check unit tests
module ComplianceSpec (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Check (defaultComplianceOptions, coMode)

tests :: TestTree
tests = testGroup "Compliance Checks"
  [ testCase "CheckId show format" $ do
      let cid = CheckId Structural 1
      show cid @?= "STR-001"

  , testCase "CheckId parse" $ do
      parseCheckId "STR-001" @?= Just (CheckId Structural 1)
      parseCheckId "VAL-017" @?= Just (CheckId Value 17)
      parseCheckId "INVALID" @?= Nothing

  , testCase "RequirementLevel isRequired" $ do
      isRequired Must @?= True
      isRequired MustNot @?= True
      isRequired Should @?= False
      isRequired May @?= False

  , testCase "Reference lookup" $ do
      let mref = lookupReference (CheckId Structural 1) defaultReferenceDB
      case mref of
        Just ref -> srSection ref @?= "3.2.1"
        Nothing -> assertFailure "STR-001 not found in reference DB"

  , testCase "Category summarize" $ do
      let (passed, failed, failedReq, failedRec, _skipped, _errors, compliant) = summarize []
      passed @?= 0
      failed @?= 0
      failedReq @?= 0
      failedRec @?= 0
      compliant @?= True

  , testCase "Default compliance mode is OperationalCompatibility" $ do
      coMode defaultComplianceOptions @?= OperationalCompatibility

  , testCase "Mixed requirement level mapping by certificate type" $ do
      getRequirementLevel (CheckId Structural 11) BasePlatformCert @?= Should
      getRequirementLevel (CheckId Structural 11) DeltaPlatformCert @?= MustNot
      getRequirementLevel (CheckId Structural 12) BasePlatformCert @?= Should
      getRequirementLevel (CheckId Structural 12) DeltaPlatformCert @?= Must
      getRequirementLevel (CheckId Structural 13) BasePlatformCert @?= Should
      getRequirementLevel (CheckId Structural 13) DeltaPlatformCert @?= May
      getRequirementLevel (CheckId Value 6) BasePlatformCert @?= Should
      getRequirementLevel (CheckId Value 6) DeltaPlatformCert @?= MustNot
      getRequirementLevel (CheckId Chain 2) BasePlatformCert @?= Should
      getRequirementLevel (CheckId Chain 2) DeltaPlatformCert @?= Should
      getRequirementLevel (CheckId Chain 3) BasePlatformCert @?= Should
      getRequirementLevel (CheckId Chain 3) DeltaPlatformCert @?= Should
  ]
