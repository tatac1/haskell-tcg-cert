module Tests.Utils (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString.Char8 as B
import Data.X509.Attribute (Attributes(..))
import Data.X509.TCG.Utils
import Data.X509.TCG.Component

tests :: TestTree
tests = testGroup "Utils Tests"
  [ testGroup "Component Conversion Functions"
    [ testCase "upgradeComponentToV2 basic conversion" $ do
        let v1Component = ComponentIdentifier 
                         (B.pack "Intel") 
                         (B.pack "i7-12700") 
                         (Just $ B.pack "SN123")
                         Nothing Nothing Nothing
            v2Component = upgradeComponentToV2 v1Component
        ci2Manufacturer v2Component @?= B.pack "Intel"
        ci2Model v2Component @?= B.pack "i7-12700" 
        ci2Serial v2Component @?= Just (B.pack "SN123")
        -- Should assign default class ComponentOther []
        ci2ComponentClass v2Component @?= ComponentOther []
    , testCase "downgradeComponentFromV2 basic conversion" $ do
        let v2Component = ComponentIdentifierV2 
                         (B.pack "AMD") 
                         (B.pack "Ryzen7") 
                         (Just $ B.pack "SN456")
                         Nothing Nothing Nothing 
                         ComponentCPU 
                         Nothing
            v1Component = downgradeComponentFromV2 v2Component
        ciManufacturer v1Component @?= B.pack "AMD"
        ciModel v1Component @?= B.pack "Ryzen7"
        ciSerial v1Component @?= Just (B.pack "SN456")
    , testCase "upgrade then downgrade preserves basic data" $ do
        let originalV1 = ComponentIdentifier 
                        (B.pack "TestMfg") 
                        (B.pack "TestModel") 
                        (Just $ B.pack "TestSerial")
                        (Just $ B.pack "Rev1.0")
                        Nothing Nothing
            upgraded = upgradeComponentToV2 originalV1
            downgraded = downgradeComponentFromV2 upgraded
        -- Basic fields should be preserved
        ciManufacturer downgraded @?= ciManufacturer originalV1
        ciModel downgraded @?= ciModel originalV1
        ciSerial downgraded @?= ciSerial originalV1
        ciRevision downgraded @?= ciRevision originalV1
    ]
  , testGroup "Error Handling Functions"
    [ testCase "TCGError NotImplemented creation and display" $ do
        let tcgError = NotImplemented "test feature"
            errorStr = formatError tcgError
        errorStr @?= "Not implemented: test feature"
    ]
  , testGroup "Component Tree Utilities"
    [ testCase "ComponentTreeUtils creation with components" $ do
        let cpu = ComponentIdentifierV2 
                  (B.pack "Intel") 
                  (B.pack "i7-12700") 
                  Nothing Nothing Nothing Nothing 
                  ComponentCPU 
                  Nothing
            memory = ComponentIdentifierV2 
                     (B.pack "Corsair") 
                     (B.pack "DDR4") 
                     Nothing Nothing Nothing Nothing 
                     ComponentMemory 
                     Nothing
            components = [cpu, memory]
            tree = ComponentTreeUtils components []
        ctComponents tree @?= components
        ctHierarchy tree @?= []
        length (ctComponents tree) @?= 2
    , testCase "ComponentTreeUtils hierarchy structure" $ do
        let motherboard = ComponentIdentifierV2 
                         (B.pack "ASUS") 
                         (B.pack "ROG") 
                         Nothing Nothing Nothing Nothing 
                         ComponentMotherboard 
                         Nothing
            cpu = ComponentIdentifierV2 
                  (B.pack "AMD") 
                  (B.pack "Ryzen") 
                  Nothing Nothing Nothing Nothing 
                  ComponentCPU 
                  Nothing
            hierarchy = [(motherboard, [cpu])]  -- CPU is child of motherboard
            tree = ComponentTreeUtils [motherboard, cpu] hierarchy
        length (ctHierarchy tree) @?= 1
        case ctHierarchy tree of
          [(parent, children)] -> do
            ci2ComponentClass parent @?= ComponentMotherboard
            length children @?= 1
            case children of
              [child] -> ci2ComponentClass child @?= ComponentCPU
              _ -> assertFailure "Expected exactly one child component"
          _ -> assertFailure "Expected exactly one parent-child relationship"
    ]
  , testGroup "Lookup and Search Utilities"
    [ testCase "lookupAttributeByOID function exists" $ do
        -- Test that the function exists (implementation may vary)
        let testOID = [1, 2, 3, 4, 5]
            emptyAttrs = Attributes []
            result = lookupAttributeByOID testOID emptyAttrs
        -- Should return Nothing for empty attribute list
        result @?= Nothing
    ]
  ]
