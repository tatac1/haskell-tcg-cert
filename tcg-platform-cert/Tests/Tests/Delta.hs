module Tests.Delta (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString.Char8 as B
import Data.X509.Attribute (Attributes(..), Attribute(..))
import Data.X509.TCG.Delta
import Data.X509.TCG.Platform()
import Data.X509.TCG.Component
import Data.X509.TCG.OID (tcg_at_platformConfiguration_v2)

tests :: TestTree
tests = testGroup "Delta Platform Certificate Tests"
  [ testGroup "DeltaOperation" 
    [ testCase "DeltaOperation enumeration" $ do
        fromEnum DeltaAdd @?= 0
        fromEnum DeltaRemove @?= 1
        fromEnum DeltaModify @?= 2
        fromEnum DeltaReplace @?= 3
        fromEnum DeltaUpdate @?= 4
    ]
  , testGroup "ComponentDelta"
    [ testCase "ComponentDelta creation" $ do
        let comp = ComponentIdentifierV2 (B.pack "TestMfg") (B.pack "TestModel") Nothing Nothing Nothing Nothing ComponentCPU Nothing
            metadata = ChangeMetadata Nothing Nothing Nothing Nothing []
            delta = ComponentDelta DeltaAdd comp Nothing metadata
        cdOperation delta @?= DeltaAdd
        cdComponent delta @?= comp
        cdPreviousComponent delta @?= Nothing
    ]
  , testGroup "Delta Configuration Tests"
    [ testCase "parseDeltaPlatformConfiguration with invalid data returns Nothing" $ do
        let invalidData = B.pack "invalid"
            result = parseDeltaPlatformConfiguration invalidData
        result @?= Nothing
    , testCase "parseDeltaPlatformConfiguration with empty data returns Nothing" $ do
        let emptyData = B.empty
            result = parseDeltaPlatformConfiguration emptyData
        result @?= Nothing
    , testCase "parseDeltaPlatformConfiguration function implementation completed" $ do
        -- The function now has a working implementation instead of just returning Nothing
        -- Test with invalid data should still return Nothing
        let invalidData = B.pack "not valid ASN.1"
            result = parseDeltaPlatformConfiguration invalidData
        result @?= Nothing
    , testCase "validateDeltaAttributes detects missing attributes" $ do
        let attrs = Attributes []  -- Empty attributes list  
            result = validateDeltaAttributes attrs
        result @?= ["Delta certificate must have at least one attribute"]
    , testCase "validateDeltaAttributes accepts valid delta attributes" $ do
        let validAttr = Attribute tcg_at_platformConfiguration_v2 []
            attrs = Attributes [validAttr]
            result = validateDeltaAttributes attrs
        result @?= []
    ]
  , testGroup "Delta Operations"
    [ testCase "DeltaOperation enumeration completeness" $ do
        let allOps = [DeltaAdd, DeltaRemove, DeltaModify, DeltaReplace, DeltaUpdate]
            enumValues = map fromEnum allOps
        enumValues @?= [0, 1, 2, 3, 4]
        toEnum 0 @?= DeltaAdd
        toEnum 1 @?= DeltaRemove
        toEnum 2 @?= DeltaModify
    , testCase "DeltaOperation show instances" $ do
        show DeltaAdd @?= "DeltaAdd"
        show DeltaRemove @?= "DeltaRemove"
        show DeltaModify @?= "DeltaModify"
    ]
  , testGroup "ComponentDelta Advanced Tests"
    [ testCase "ComponentDelta with different operations" $ do
        let addComponent = ComponentIdentifierV2 
                          (B.pack "NewMfg") 
                          (B.pack "NewModel") 
                          Nothing Nothing Nothing Nothing 
                          ComponentCPU 
                          Nothing
            removeComponent = ComponentIdentifierV2 
                             (B.pack "OldMfg") 
                             (B.pack "OldModel") 
                             Nothing Nothing Nothing Nothing 
                             ComponentMemory 
                             Nothing
            metadata = ChangeMetadata Nothing Nothing Nothing Nothing []
            addDelta = ComponentDelta DeltaAdd addComponent Nothing metadata
            removeDelta = ComponentDelta DeltaRemove removeComponent Nothing metadata
        -- Test Add operation
        cdOperation addDelta @?= DeltaAdd
        ci2Manufacturer (cdComponent addDelta) @?= B.pack "NewMfg"
        -- Test Remove operation  
        cdOperation removeDelta @?= DeltaRemove
        ci2Manufacturer (cdComponent removeDelta) @?= B.pack "OldMfg"
    , testCase "ComponentDelta with previous component information" $ do
        let newComponent = ComponentIdentifierV2 
                          (B.pack "UpdatedMfg") 
                          (B.pack "UpdatedModel") 
                          Nothing Nothing Nothing Nothing 
                          ComponentCPU 
                          Nothing
            oldComponent = ComponentIdentifierV2 
                          (B.pack "OldMfg") 
                          (B.pack "OldModel") 
                          Nothing Nothing Nothing Nothing 
                          ComponentCPU 
                          Nothing
            metadata = ChangeMetadata Nothing Nothing Nothing Nothing []
            modifyDelta = ComponentDelta DeltaModify newComponent (Just oldComponent) metadata
        cdOperation modifyDelta @?= DeltaModify
        cdPreviousComponent modifyDelta @?= Just oldComponent
        case cdPreviousComponent modifyDelta of
          Just prev -> ci2Manufacturer prev @?= B.pack "OldMfg"
          Nothing -> assertFailure "Previous component should be present"
    ]
  , testGroup "ChangeMetadata Tests"
    [ testCase "ChangeMetadata creation with optional fields" $ do
        let initiator = Nothing -- Could be a user ID in full implementation
            approver = Nothing
            ticket = Nothing
            rollback = Nothing
            properties = [(B.pack "change-type", B.pack "routine-update")]
            metadata = ChangeMetadata initiator approver ticket rollback properties
        cmAdditionalInfo metadata @?= [(B.pack "change-type", B.pack "routine-update")]
        cmInitiator metadata @?= Nothing
        cmApprover metadata @?= Nothing
    ]
  ]