{-# LANGUAGE OverloadedStrings #-}

-- | Main test module for tcg-platform-cert-compliance
module Main (main) where

import Test.Tasty

import qualified ComplianceSpec
import qualified EndToEndSpec
import qualified SBVProofs
import qualified ComplianceGuideSpec
import qualified SuggestionSpec
import qualified ChainComplianceSpec
import qualified ComplianceCheckSpec

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "TCG Platform Cert Compliance Tests"
  [ ComplianceSpec.tests
  , EndToEndSpec.tests
  , SBVProofs.tests
  , ComplianceGuideSpec.tests
  , SuggestionSpec.tests
  , ChainComplianceSpec.tests
  , ComplianceCheckSpec.tests
  ]
