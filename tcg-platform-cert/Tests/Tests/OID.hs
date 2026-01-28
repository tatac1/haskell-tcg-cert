module Tests.OID (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Data.X509.TCG.OID

tests :: TestTree
tests = testGroup "TCG OID Tests"
  [ testGroup "TCG Root OID"
    [ testCase "tcgOID is correct" $
        tcgOID @?= [2, 23, 133]
    ]
  , testGroup "Platform Attribute OIDs"
    [ testCase "tcg_at_platformConfiguration" $
        tcg_at_platformConfiguration @?= [2, 23, 133, 5, 1, 7, 1]
    , testCase "tcg_at_platformConfiguration_v2" $
        tcg_at_platformConfiguration_v2 @?= [2, 23, 133, 5, 1, 7, 2]
    , testCase "tcg_at_componentIdentifier" $
        tcg_at_componentIdentifier @?= [2, 23, 133, 2, 2]
    , testCase "tcg_at_componentIdentifier_v2" $
        tcg_at_componentIdentifier_v2 @?= [2, 23, 133, 2, 24]
    ]
  , testGroup "Component Class OIDs"
    [ testCase "tcg_class_motherboard" $
        tcg_class_motherboard @?= [2, 23, 133, 18, 1, 1]
    , testCase "tcg_class_cpu" $
        tcg_class_cpu @?= [2, 23, 133, 18, 1, 2]
    , testCase "tcg_class_memory" $
        tcg_class_memory @?= [2, 23, 133, 18, 1, 3]
    ]
  , testGroup "Key Purpose OIDs"
    [ testCase "tcg_kp_EKCertificate" $
        tcg_kp_EKCertificate @?= [2, 23, 133, 8, 1]
    , testCase "tcg_kp_PlatformAttributeCertificate" $
        tcg_kp_PlatformAttributeCertificate @?= [2, 23, 133, 8, 2]
    , testCase "tcg_kp_DeltaAttributeCertificate" $
        tcg_kp_DeltaAttributeCertificate @?= [2, 23, 133, 8, 5]
    ]
  ]

