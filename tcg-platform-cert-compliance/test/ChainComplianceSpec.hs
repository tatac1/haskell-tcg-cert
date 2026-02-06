{-# LANGUAGE OverloadedStrings #-}

module ChainComplianceSpec (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Data.X509.TCG.Compliance.ChainCompliance
import Data.X509.TCG.Compliance.Types (ComplianceMode(..), RequirementLevel(..))
import Data.X509.TCG.Compliance.Result (CheckStatus(..))
import Data.X509.TCG.Platform (ComponentStatus(..))

tests :: TestTree
tests = testGroup "ChainCompliance"
  [ testGroup "CHAIN-001: Platform identity consistency"
    [ testCase "matching identity passes" $ do
        let base = ("Acme Corp", "Server X1", "1.0")
            deltas = [("Acme Corp", "Server X1", "1.0")]
            result = checkChainIdentity base deltas
        assertEqual "status" Pass (ccrStatus result)

    , testCase "mismatched manufacturer fails" $ do
        let base = ("Acme Corp", "Server X1", "1.0")
            deltas = [("Other Corp", "Server X1", "1.0")]
            result = checkChainIdentity base deltas
        assertFailStatus result

    , testCase "mismatched model fails" $ do
        let base = ("Acme Corp", "Server X1", "1.0")
            deltas = [("Acme Corp", "Server X2", "1.0")]
            result = checkChainIdentity base deltas
        assertFailStatus result
    ]

  , testGroup "CHAIN-002: Serial number ordering"
    [ testCase "ascending serials pass" $ do
        let serials = [100, 200, 300]
            result = checkChainOrdering serials
        assertEqual "status" Pass (ccrStatus result)

    , testCase "duplicate serials fail" $ do
        let serials = [100, 100, 300]
            result = checkChainOrdering serials
        assertFailStatus result

    , testCase "single serial passes" $ do
        let serials = [42]
            result = checkChainOrdering serials
        assertEqual "status" Pass (ccrStatus result)
    ]

  , testGroup "CHAIN-003: State transitions"
    [ testCase "ADDED for new component is valid" $ do
        let baseComps = [("Mfr", "ModelA", Just "S1")]
            deltaComps = [[(("NewMfr", "NewModel", Just "S2"), ComponentAdded)]]
            result = checkStateTransitions baseComps deltaComps OperationalCompatibility
        assertEqual "status" Pass (ccrStatus result)

    , testCase "MODIFIED for existing component is valid" $ do
        let baseComps = [("Mfr", "ModelA", Just "S1")]
            deltaComps = [[(("Mfr", "ModelA", Just "S1"), ComponentModified)]]
            result = checkStateTransitions baseComps deltaComps OperationalCompatibility
        assertEqual "status" Pass (ccrStatus result)

    , testCase "REMOVED for existing component is valid" $ do
        let baseComps = [("Mfr", "ModelA", Just "S1")]
            deltaComps = [[(("Mfr", "ModelA", Just "S1"), ComponentRemoved)]]
            result = checkStateTransitions baseComps deltaComps OperationalCompatibility
        assertEqual "status" Pass (ccrStatus result)

    , testCase "MODIFIED for non-existent component is invalid" $ do
        let baseComps = [("Mfr", "ModelA", Just "S1")]
            deltaComps = [[(("Other", "OtherModel", Just "S99"), ComponentModified)]]
            result = checkStateTransitions baseComps deltaComps OperationalCompatibility
        assertFailStatus result

    , testCase "REMOVED for non-existent component is invalid" $ do
        let baseComps = [("Mfr", "ModelA", Just "S1")]
            deltaComps = [[(("Other", "OtherModel", Just "S99"), ComponentRemoved)]]
            result = checkStateTransitions baseComps deltaComps OperationalCompatibility
        assertFailStatus result

    , testCase "duplicate ADDED is invalid" $ do
        let baseComps = [] :: [CompId]
            deltaComps =
              [ [(("NewMfr", "NewModel", Just "S1"), ComponentAdded)]
              , [(("NewMfr", "NewModel", Just "S1"), ComponentAdded)]
              ]
            result = checkStateTransitions baseComps deltaComps OperationalCompatibility
        assertFailStatus result
    ]

  , testGroup "CHAIN-004: Holder reference chain validation"
    [ testCase "valid holder references pass" $ do
        let baseSerial = 100
            deltaHolders = [(200, 100), (300, 200)]  -- Delta 200 refs Base 100, Delta 300 refs Delta 200
            result = checkHolderChain baseSerial deltaHolders
        assertEqual "status" Pass (ccrStatus result)

    , testCase "invalid holder reference fails" $ do
        let baseSerial = 100
            deltaHolders = [(200, 999)]  -- Delta 200 refs unknown serial 999
            result = checkHolderChain baseSerial deltaHolders
        assertFailStatus result

    , testCase "empty delta list passes" $ do
        let baseSerial = 100
            result = checkHolderChain baseSerial []
        assertEqual "status" Pass (ccrStatus result)

    , testCase "holder referencing later delta fails" $ do
        let baseSerial = 100
            deltaHolders = [(200, 300), (300, 100)]  -- Delta 200 refs Delta 300 which comes AFTER
            result = checkHolderChain baseSerial deltaHolders
        assertFailStatus result
    ]

  , testGroup "CHAIN-005: Final platform state"
    [ testCase "computes correct state after ADD" $ do
        let baseComps = [("Mfr", "ModelA", Just "S1")]
            deltaComps = [[(("NewMfr", "NewModel", Just "S2"), ComponentAdded)]]
            state = computeFinalState baseComps deltaComps
        assertEqual "component count" 2 (length (psComponents state))

    , testCase "computes correct state after REMOVE" $ do
        let baseComps = [("Mfr", "ModelA", Just "S1"), ("Mfr2", "ModelB", Just "S2")]
            deltaComps = [[(("Mfr", "ModelA", Just "S1"), ComponentRemoved)]]
            state = computeFinalState baseComps deltaComps
        assertEqual "component count" 1 (length (psComponents state))

    , testCase "computes correct state after multiple deltas" $ do
        let baseComps = [("Mfr", "ModelA", Just "S1")]
            deltaComps =
              [ [(("NewMfr", "NewModel", Just "S2"), ComponentAdded)]    -- Delta 1: add
              , [(("Mfr", "ModelA", Just "S1"), ComponentRemoved)]       -- Delta 2: remove original
              ]
            state = computeFinalState baseComps deltaComps
        assertEqual "component count" 1 (length (psComponents state))
        assertEqual "delta count" 2 (psDeltaCount state)
    ]
  ]

assertFailStatus :: ChainCheckResult -> IO ()
assertFailStatus r = case ccrStatus r of
  Fail _ -> return ()
  other  -> assertFailure $ "Expected Fail, got: " ++ show other
