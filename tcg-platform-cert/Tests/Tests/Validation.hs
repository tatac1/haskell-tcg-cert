module Tests.Validation (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString.Char8 as B
import Data.X509.TCG.Component

-- Note: Most validation functions have been moved to the separate
-- tcg-platform-cert-validation package. These tests now focus on
-- basic certificate structure validation that remains in the main package.

tests :: TestTree
tests = testGroup "Validation Tests"
  [ testGroup "Basic Certificate Structure Tests"
    [ testCase "Platform certificate structure is valid" $ do
        -- Test that we can create basic platform certificate structures
        let cpu = ComponentIdentifierV2 
                  (B.pack "Intel") 
                  (B.pack "i7-12700") 
                  Nothing Nothing Nothing Nothing 
                  ComponentCPU 
                  Nothing
        ci2Manufacturer cpu @?= B.pack "Intel"
        ci2Model cpu @?= B.pack "i7-12700"
        ci2ComponentClass cpu @?= ComponentCPU
    , testCase "Component identifier fields are accessible" $ do
        let memory = ComponentIdentifierV2
                    (B.pack "Samsung")
                    (B.pack "DDR4-3200")
                    (Just $ B.pack "SN123456")
                    (Just $ B.pack "Rev1.0")
                    Nothing Nothing
                    ComponentMemory
                    Nothing
        ci2Manufacturer memory @?= B.pack "Samsung"
        ci2Model memory @?= B.pack "DDR4-3200" 
        ci2Serial memory @?= Just (B.pack "SN123456")
        ci2Revision memory @?= Just (B.pack "Rev1.0")
        ci2ComponentClass memory @?= ComponentMemory
    ]
  , testGroup "Component Class Validation"
    [ testCase "Component classes are properly defined" $ do
        -- Test that component class enumeration works
        let classes = [ComponentCPU, ComponentMemory, ComponentMotherboard, ComponentNetworkInterface, ComponentGraphicsCard]
        length classes @?= 5
        
        -- Test component class comparison
        ComponentCPU == ComponentCPU @?= True
        ComponentCPU == ComponentMemory @?= False
    ]
  ]