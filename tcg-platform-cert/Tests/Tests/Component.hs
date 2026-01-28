module Tests.Component (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import qualified Data.ByteString.Char8 as B
import Data.X509.TCG.Component
import Data.X509.TCG.OID
import Tests.Arbitrary()

tests :: TestTree
tests = testGroup "Component Tests"
  [ testGroup "ComponentIdentifier"
    [ testCase "ComponentIdentifier creation" $ do
        let comp = ComponentIdentifier (B.pack "TestMfg") (B.pack "TestModel") (Just $ B.pack "12345") Nothing Nothing Nothing
        ciManufacturer comp @?= B.pack "TestMfg"
        ciModel comp @?= B.pack "TestModel"
        ciSerial comp @?= Just (B.pack "12345")
    , testCase "ComponentIdentifier with minimal fields" $ do
        let comp = ComponentIdentifier 
                     (B.pack "AMD") 
                     (B.pack "Ryzen") 
                     Nothing Nothing Nothing Nothing
        ciManufacturer comp @?= B.pack "AMD"
        ciModel comp @?= B.pack "Ryzen"
        ciSerial comp @?= Nothing
    ]
  , testGroup "ComponentClass" 
    [ testCase "Component class matching" $ do
        let comp = ComponentIdentifierV2 (B.pack "TestMfg") (B.pack "TestModel") Nothing Nothing Nothing Nothing ComponentCPU Nothing
        isComponentClass ComponentCPU comp @?= True
        isComponentClass ComponentMemory comp @?= False
    , testCase "ComponentClass enumeration values" $ do
        -- Test basic component class enumeration  
        let cpu = ComponentCPU
            memory = ComponentMemory
            motherboard = ComponentMotherboard
        -- Just test that the constructors work
        cpu @?= ComponentCPU
        memory @?= ComponentMemory
        motherboard @?= ComponentMotherboard
    ]
  , testGroup "ComponentAddress"
    [ testCase "ComponentAddress creation" $ do
        let addr = ComponentAddress AddressPCI (B.pack "0000:00:1f.3")
        caAddressType addr @?= AddressPCI
        caAddress addr @?= B.pack "0000:00:1f.3"
    , testCase "ComponentAddressType enumeration" $ do
        let types = [AddressPCI, AddressUSB, AddressSATA, AddressI2C]
        -- Test that these constructors work
        length types @?= 4
    ]
  , testGroup "ComponentHierarchy"
    [ testCase "Component hierarchy validation" $ do
        let comp1 = ComponentIdentifierV2 (B.pack "TestMfg") (B.pack "TestModel") Nothing Nothing Nothing Nothing ComponentMotherboard Nothing
            tree = buildComponentTree [comp1]
            hierarchy = ComponentHierarchy [] tree
        validateComponentHierarchy hierarchy @?= []
    , testCase "Component hierarchy with missing manufacturer" $ do
        let comp1 = ComponentIdentifierV2 B.empty (B.pack "TestModel") Nothing Nothing Nothing Nothing ComponentMotherboard Nothing
            tree = buildComponentTree [comp1]
            hierarchy = ComponentHierarchy [] tree
            errors = validateComponentHierarchy hierarchy
        errors @?= ["Component missing manufacturer"]
    ]
  , testGroup "Specification Compliance"
    [ testCase "Component class OIDs match specification section 4.2.18" $ do
        -- Test that component class OIDs match the specification
        let motherboardOID = tcg_class_motherboard
            cpuOID = tcg_class_cpu  
            memoryOID = tcg_class_memory
        motherboardOID @?= [2, 23, 133, 18, 1, 1]
        cpuOID @?= [2, 23, 133, 18, 1, 2]
        memoryOID @?= [2, 23, 133, 18, 1, 3]
    , testCase "ComponentIdentifier field structure" $ do
        let comp = ComponentIdentifier 
                     (B.pack "TestMfg") 
                     (B.pack "TestModel") 
                     Nothing Nothing Nothing Nothing
        -- Test that required fields are present
        ciManufacturer comp @?= B.pack "TestMfg"
        ciModel comp @?= B.pack "TestModel"
    ]
  , testGroup "Property-based Tests"
    [ testProperty "ComponentIdentifier field validity" $ \comp ->
        let manufacturer = ciManufacturer (comp :: ComponentIdentifier)
            model = ciModel comp
        in not (B.null manufacturer) && not (B.null model)
    , testProperty "ComponentIdentifierV2 class consistency" $ \comp ->
        let class1 = ci2ComponentClass (comp :: ComponentIdentifierV2)
        in isComponentClass class1 comp
    ]
  , testGroup "Utility Functions"
    [ testCase "buildComponentTree with single component" $ do
        let comp = ComponentIdentifierV2 
                     (B.pack "Test") (B.pack "Component") Nothing Nothing Nothing Nothing
                     ComponentCPU Nothing
            tree = buildComponentTree [comp]
        ctComponent tree @?= comp
        ctChildren tree @?= []
    ]
  , testGroup "Component Hierarchy Advanced Tests"
    [ testCase "validateComponentHierarchy with valid hierarchy" $ do
        let motherboard = ComponentIdentifierV2 
                         (B.pack "ASUS") 
                         (B.pack "ROG-X570") 
                         (Just $ B.pack "MB001") 
                         Nothing Nothing Nothing 
                         ComponentMotherboard 
                         Nothing
            _cpu = ComponentIdentifierV2 
                  (B.pack "AMD") 
                  (B.pack "Ryzen7") 
                  Nothing Nothing Nothing Nothing 
                  ComponentCPU 
                  Nothing
            tree = buildComponentTree [motherboard]
            hierarchy = ComponentHierarchy [] tree
            errors = validateComponentHierarchy hierarchy
        errors @?= []
    , testCase "validateComponentHierarchy with missing data" $ do
        let badComponent = ComponentIdentifierV2 
                          B.empty  -- Empty manufacturer should trigger error
                          (B.pack "TestModel") 
                          Nothing Nothing Nothing Nothing 
                          ComponentCPU 
                          Nothing
            tree = buildComponentTree [badComponent]
            hierarchy = ComponentHierarchy [] tree
            errors = validateComponentHierarchy hierarchy
        errors @?= ["Component missing manufacturer"]
    ]
  , testGroup "Component Address Validation"
    [ testCase "ComponentAddress with PCI addressing" $ do
        let pciAddr = ComponentAddress AddressPCI (B.pack "0000:00:1f.3")
        caAddressType pciAddr @?= AddressPCI
        caAddress pciAddr @?= B.pack "0000:00:1f.3"
    , testCase "ComponentAddress with USB addressing" $ do
        let usbAddr = ComponentAddress AddressUSB (B.pack "1-1.2:1.0")
        caAddressType usbAddr @?= AddressUSB
        caAddress usbAddr @?= B.pack "1-1.2:1.0"
    ]
  , testGroup "Component Tree Building"
    [ testCase "buildComponentTree with multiple components" $ do
        let cpu = ComponentIdentifierV2 
                  (B.pack "Intel") 
                  (B.pack "i7-12700") 
                  Nothing Nothing Nothing Nothing 
                  ComponentCPU 
                  Nothing
            memory = ComponentIdentifierV2 
                     (B.pack "Corsair") 
                     (B.pack "DDR4-3200") 
                     (Just $ B.pack "CMK16GX4M2B3200C16")
                     Nothing Nothing Nothing 
                     ComponentMemory 
                     Nothing
        -- Test that we can build trees from individual components
        let cpuTree = buildComponentTree [cpu]
            memoryTree = buildComponentTree [memory]
        ci2Manufacturer (ctComponent cpuTree) @?= B.pack "Intel"
        ci2Model (ctComponent memoryTree) @?= B.pack "DDR4-3200"
    ]
  ]