{-# LANGUAGE OverloadedStrings #-}

module SuggestionSpec (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Data.Text (Text, isInfixOf)

import Data.X509.TCG.Compliance.Suggestion

tests :: TestTree
tests = testGroup "Suggestion"
  [ testCase "formatSuggestion ValueSuggestion" $ do
      let s = ValueSuggestion "fipsSecurityLevel" "must be in range 1..4. Current value: 5"
      formatSuggestion s @?= "fipsSecurityLevel must be in range 1..4. Current value: 5"

  , testCase "formatSuggestion AddField" $ do
      let s = AddField "credentialSpecMajor" (Just "credentialSpecMajor: 1")
      let result = formatSuggestion s
      assertBool "contains field name" ("credentialSpecMajor" `isInfixOf` result)
      assertBool "contains 'Add'" ("Add" `isInfixOf` result)

  , testCase "formatSuggestion AddField without example" $ do
      let s = AddField "securityAssertions" Nothing
      let result = formatSuggestion s
      assertBool "contains field name" ("securityAssertions" `isInfixOf` result)

  , testCase "formatSuggestion RemoveField" $ do
      let s = RemoveField "securityAssertions" "Delta certificates must not include securityAssertions"
      let result = formatSuggestion s
      assertBool "contains reason" ("Delta" `isInfixOf` result)
      assertBool "contains 'Remove'" ("Remove" `isInfixOf` result)

  , testCase "formatSuggestion FixFormat" $ do
      let s = FixFormat "componentClassValue" "8-digit hexadecimal" (Just "00030003")
      let result = formatSuggestion s
      assertBool "contains format" ("hexadecimal" `isInfixOf` result)
      assertBool "contains field" ("componentClassValue" `isInfixOf` result)

  , testCase "formatSuggestion FixFormat without example" $ do
      let s = FixFormat "componentClassValue" "8-digit hexadecimal" Nothing
      let result = formatSuggestion s
      assertBool "contains format" ("hexadecimal" `isInfixOf` result)

  , testCase "formatSuggestion ReferenceInfo" $ do
      let s = ReferenceInfo "IWG Profile S3.1.1 (L333-L334)"
      formatSuggestion s @?= "Reference: IWG Profile S3.1.1 (L333-L334)"

  , testCase "Suggestion Eq instance" $ do
      let s1 = ValueSuggestion "field" "expected"
          s2 = ValueSuggestion "field" "expected"
          s3 = ValueSuggestion "field" "other"
      assertEqual "same suggestions are equal" s1 s2
      assertBool "different suggestions are not equal" (s1 /= s3)
  ]
