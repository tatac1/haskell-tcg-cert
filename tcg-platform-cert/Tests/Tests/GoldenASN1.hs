{-# LANGUAGE OverloadedStrings #-}

-- |
-- Golden tests for ASN.1 encoding structures per IWG Platform Certificate
-- Profile v1.1. These tests verify exact DER byte output for known inputs.

module Tests.GoldenASN1 (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString as B
import Data.List (isSubsequenceOf)
import Data.ASN1.Types
import Data.X509.TCG
  ( TBBSecurityAssertions(..)
  , ComponentConfigV2(..)
  , encodeComponentIdentifierV2
  , encodeComponentClass
  , buildTBBSecurityAssertionsAttr
  , buildExtendedTCGAttrs
  , buildPlatformConfigurationV2Attr
  , oidToContentBytes
  , ExtendedTCGAttributes(..)
  , PlatformConfigUri(..)
  , defaultExtendedTCGAttributes
  )
import Data.X509.TCG.OID
import Data.X509.TCG.Platform (ComponentStatus(..))
import Data.X509.Attribute (Attribute(..))

tests :: TestTree
tests = testGroup "Golden ASN.1 Tests"
  [ componentIdentifierV2Tests
  , componentClassTests
  , platformConfigV2AttrTests
  , tbbDefaultOmissionTests
  , attributeOrderingTests
  , oidVLQGoldenTests
  ]

-- * ComponentIdentifierV2 tag structure

componentIdentifierV2Tests :: TestTree
componentIdentifierV2Tests = testGroup "ComponentIdentifierV2 Tag Structure"
  [ testCase "Serial tag [0] IMPLICIT" $ do
      let comp = baseComponent { ccv2Serial = Just "SN001" }
          asn1 = encodeComponentIdentifierV2 comp
      assertBool "serial tag [0]" $ Other Context 0 "SN001" `elem` asn1

  , testCase "Revision tag [1] IMPLICIT" $ do
      let comp = baseComponent { ccv2Revision = Just "1.0" }
          asn1 = encodeComponentIdentifierV2 comp
      assertBool "revision tag [1]" $ Other Context 1 "1.0" `elem` asn1

  , testCase "FieldReplaceable tag [3] IMPLICIT TRUE" $ do
      let comp = baseComponent { ccv2FieldReplaceable = Just True }
          asn1 = encodeComponentIdentifierV2 comp
      assertBool "fieldReplaceable tag [3] = 0xff" $
        Other Context 3 (B.singleton 0xff) `elem` asn1

  , testCase "FieldReplaceable tag [3] IMPLICIT FALSE" $ do
      let comp = baseComponent { ccv2FieldReplaceable = Just False }
          asn1 = encodeComponentIdentifierV2 comp
      assertBool "fieldReplaceable tag [3] = 0x00" $
        Other Context 3 (B.singleton 0x00) `elem` asn1

  , testCase "Status tag [7] IMPLICIT (Added=0)" $ do
      let comp = baseComponent { ccv2Status = Just ComponentAdded }
          asn1 = encodeComponentIdentifierV2 comp
      assertBool "status tag [7] = 0x00" $
        Other Context 7 (B.singleton 0) `elem` asn1

  , testCase "ManufacturerId tag [2] IMPLICIT OID" $ do
      let mfgOid = [1, 3, 6, 1, 4, 1, 343]  -- Intel OID
          comp = baseComponent { ccv2ManufacturerId = Just mfgOid }
          asn1 = encodeComponentIdentifierV2 comp
      assertBool "manufacturerId tag [2]" $
        Other Context 2 (oidToContentBytes mfgOid) `elem` asn1

  , testCase "Addresses tag [4] CONSTRUCTED" $ do
      let addrOid = [1, 3, 6, 1, 4, 1, 343, 2, 1]
          comp = baseComponent { ccv2Addresses = Just [(addrOid, "addr1")] }
          asn1 = encodeComponentIdentifierV2 comp
      assertBool "addresses tag [4] constructed open" $
        any (\a -> case a of Start (Container Context 4) -> True; _ -> False) asn1
      assertBool "addresses tag [4] constructed close" $
        any (\a -> case a of End (Container Context 4) -> True; _ -> False) asn1
      assertBool "addresses contains OID" $
        OID addrOid `elem` asn1

  , testCase "Status tag [7] IMPLICIT (Modified=1)" $ do
      let comp = baseComponent { ccv2Status = Just ComponentModified }
          asn1 = encodeComponentIdentifierV2 comp
      assertBool "status tag [7] = 0x01" $
        Other Context 7 (B.singleton 1) `elem` asn1

  , testCase "Status tag [7] IMPLICIT (Removed=2)" $ do
      let comp = baseComponent { ccv2Status = Just ComponentRemoved }
          asn1 = encodeComponentIdentifierV2 comp
      assertBool "status tag [7] = 0x02" $
        Other Context 7 (B.singleton 2) `elem` asn1

  , testCase "Status Unchanged omitted" $ do
      let comp = baseComponent { ccv2Status = Just ComponentUnchanged }
          asn1 = encodeComponentIdentifierV2 comp
      assertBool "no tag [7] for Unchanged" $
        not $ any (\a -> case a of Other Context 7 _ -> True; _ -> False) asn1

  , testCase "Optional fields absent when Nothing" $ do
      let asn1 = encodeComponentIdentifierV2 baseComponent
      assertBool "no tag [0]" $ not $ any (isContextTag 0) asn1
      assertBool "no tag [1]" $ not $ any (isContextTag 1) asn1
      assertBool "no tag [2]" $ not $ any (isContextTag 2) asn1
      assertBool "no tag [3]" $ not $ any (isContextTag 3) asn1
      assertBool "no tag [7]" $ not $ any (isContextTag 7) asn1
  ]

-- * ComponentClass encoding

componentClassTests :: TestTree
componentClassTests = testGroup "ComponentClass Encoding"
  [ testCase "ComponentClass is SEQUENCE { OID, OCTET STRING(4) }" $ do
      let classValue = B.pack [0x00, 0x01, 0x00, 0x02]
          asn1 = encodeComponentClass classValue
      asn1 @?= [ Start Sequence
                , OID tcg_registry_componentClass_tcg
                , OctetString classValue
                , End Sequence
                ]
  ]

-- * PlatformConfigurationV2 attribute structure

platformConfigV2AttrTests :: TestTree
platformConfigV2AttrTests = testGroup "PlatformConfigurationV2 Attribute"
  [ testCase "Single component wrapped in [0] IMPLICIT SEQUENCE" $ do
      let Attribute oid vals = buildPlatformConfigurationV2Attr [baseComponent]
      oid @?= tcg_at_platformConfiguration_v2
      let flatVals = concat vals
      assertBool "starts with Container Context 0" $
        case flatVals of
          (Start (Container Context 0) : _) -> True
          _ -> False
      assertBool "contains component SEQUENCE" $ Start Sequence `elem` flatVals

  , testCase "Empty component list" $ do
      let Attribute oid vals = buildPlatformConfigurationV2Attr []
      oid @?= tcg_at_platformConfiguration_v2
      let flatVals = concat vals
      assertBool "Container wraps empty sequence" $
        case flatVals of
          [Start (Container Context 0), End (Container Context 0)] -> True
          _ -> False
  ]

-- * TBB DEFAULT value omission/presence

tbbDefaultOmissionTests :: TestTree
tbbDefaultOmissionTests = testGroup "TBB DEFAULT Value Handling"
  [ testCase "version=0 omitted" $ do
      let tbb = baseTBB { tbbVersion = 0 }
          Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
          flatVals = concat vals
      assertBool "IntVal 0 not in output" $ IntVal 0 `notElem` flatVals

  , testCase "version=1 present" $ do
      let tbb = baseTBB { tbbVersion = 1 }
          Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
          flatVals = concat vals
      assertBool "IntVal 1 in output" $ IntVal 1 `elem` flatVals

  , testCase "iso9000Certified=False omitted" $ do
      let tbb = baseTBB { tbbISO9000Certified = Just False }
          Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
          flatVals = concat vals
      assertBool "Boolean False not in output" $ Boolean False `notElem` flatVals

  , testCase "iso9000Certified=True present" $ do
      let tbb = baseTBB { tbbISO9000Certified = Just True }
          Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
          flatVals = concat vals
      assertBool "Boolean True in output" $ Boolean True `elem` flatVals

  , testCase "plus=False omitted in CC measures" $ do
      let tbb = baseTBB
            { tbbCCVersion = Just "3.1"
            , tbbEvalAssuranceLevel = Just 4
            , tbbEvalStatus = Just 2
            , tbbPlus = Just False
            }
          Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
          flatVals = concat vals
      assertBool "Boolean False not in output" $ Boolean False `notElem` flatVals

  , testCase "plus=True present in CC measures" $ do
      let tbb = baseTBB
            { tbbCCVersion = Just "3.1"
            , tbbEvalAssuranceLevel = Just 4
            , tbbEvalStatus = Just 2
            , tbbPlus = Just True
            }
          Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
          flatVals = concat vals
      assertBool "Boolean True in output" $ Boolean True `elem` flatVals

  , testCase "fipsPlus=False omitted in FIPS level" $ do
      let tbb = baseTBB
            { tbbFIPSVersion = Just "140-2"
            , tbbFIPSSecurityLevel = Just 2
            , tbbFIPSPlus = Just False
            }
          Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
          flatVals = concat vals
      assertBool "Boolean False not in output" $ Boolean False `notElem` flatVals

  , testCase "fipsPlus=True present in FIPS level" $ do
      let tbb = baseTBB
            { tbbFIPSVersion = Just "140-2"
            , tbbFIPSSecurityLevel = Just 2
            , tbbFIPSPlus = Just True
            }
          Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
          flatVals = concat vals
      assertBool "Boolean True in output" $ Boolean True `elem` flatVals
  ]

-- * Attribute OID ordering

attributeOrderingTests :: TestTree
attributeOrderingTests = testGroup "Attribute OID Ordering"
  [ testCase "Full attribute ordering (all present)" $ do
      let extAttrs = defaultExtendedTCGAttributes
            { etaSecurityAssertions = Just baseTBB
            , etaPlatformSpecVersion = Just (1, 1, 0)
            , etaComponentsV2 = Just [baseComponent]
            , etaCredentialSpecVersion = Just (2, 0, 0)
            , etaPlatformConfigUri = Just (PlatformConfigUri "https://example.com" Nothing Nothing)
            }
          attrs = buildExtendedTCGAttrs extAttrs
          oids = map attrType attrs
          expectedOrder =
            [ tcg_at_tcgCredentialType
            , tcg_at_tbbSecurityAssertions
            , tcg_at_tcgPlatformSpecification
            , tcg_at_platformConfiguration_v2
            , tcg_at_tcgCredentialSpecification
            , tcg_paa_platformConfigUri
            ]
      oids @?= expectedOrder

  , testCase "Partial attribute ordering (some absent)" $ do
      let extAttrs = defaultExtendedTCGAttributes
            { etaPlatformSpecVersion = Just (1, 1, 0)
            , etaComponentsV2 = Just [baseComponent]
            -- No security assertions, no config URI, no cred spec
            }
          attrs = buildExtendedTCGAttrs extAttrs
          oids = map attrType attrs
          expectedFullOrder =
            [ tcg_at_tcgCredentialType
            , tcg_at_tbbSecurityAssertions
            , tcg_at_tcgPlatformSpecification
            , tcg_at_platformConfiguration_v2
            , tcg_at_tcgCredentialSpecification
            , tcg_paa_platformConfigUri
            ]
      assertBool "relative ordering preserved" $ oids `isSubsequenceOf` expectedFullOrder

  , testCase "CredentialType always first" $ do
      let extAttrs = defaultExtendedTCGAttributes
            { etaComponentsV2 = Just [baseComponent]
            }
          attrs = buildExtendedTCGAttrs extAttrs
          oids = map attrType attrs
      case oids of
        (first:_) -> first @?= tcg_at_tcgCredentialType
        []        -> assertFailure "no attributes generated"
  ]

-- * OID VLQ golden values

oidVLQGoldenTests :: TestTree
oidVLQGoldenTests = testGroup "OID VLQ Encoding Golden Values"
  [ testCase "tcg-at-tbbSecurityAssertions (2.23.133.2.19)" $
      oidToContentBytes [2, 23, 133, 2, 19]
        @?= B.pack [0x67, 0x81, 0x05, 0x02, 0x13]

  , testCase "tcg-at-platformConfiguration-v2 (2.23.133.5.1.7.2)" $
      oidToContentBytes [2, 23, 133, 5, 1, 7, 2]
        @?= B.pack [0x67, 0x81, 0x05, 0x05, 0x01, 0x07, 0x02]

  , testCase "tcg-at-tcgCredentialType (2.23.133.2.25)" $
      oidToContentBytes [2, 23, 133, 2, 25]
        @?= B.pack [0x67, 0x81, 0x05, 0x02, 0x19]

  , testCase "tcg-registry-componentClass-tcg (2.23.133.18.3.1)" $
      oidToContentBytes [2, 23, 133, 18, 3, 1]
        @?= B.pack [0x67, 0x81, 0x05, 0x12, 0x03, 0x01]

  , testCase "Single arc OID (2)" $
      oidToContentBytes [2]
        @?= B.pack [0x50]  -- 40 * 2 = 80 = 0x50

  , testCase "Two arc OID (2.23)" $
      oidToContentBytes [2, 23]
        @?= B.pack [0x67]  -- 40 * 2 + 23 = 103 = 0x67
  ]

-- * Test helpers

-- | Base component with all optional fields as Nothing
baseComponent :: ComponentConfigV2
baseComponent = ComponentConfigV2
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

-- | Base TBB with minimal fields (version=0, all Nothing)
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

-- | Check if an ASN1 element is a context-tagged element with given tag number
isContextTag :: Int -> ASN1 -> Bool
isContextTag n (Other Context n' _) = fromIntegral n == n'
isContextTag n (Start (Container Context n')) = fromIntegral n == n'
isContextTag _ _ = False
