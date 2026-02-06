{-# LANGUAGE OverloadedStrings #-}

module ComplianceGuideSpec (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Data.ASN1.Types (ASN1(..), ASN1Class(..), ASN1ConstructionType(..), OID)
import Data.ASN1.Types.String (ASN1CharacterString(..), ASN1StringEncoding(..))
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Encoding (encodeASN1)
import qualified Data.ByteString.Lazy as L
import Time.Types (Date(..), DateTime(..), Month(..), TimeOfDay(..))

import Data.X509
  ( Extensions(..)
  , ExtensionRaw(..)
  , SignatureALG(..)
  , HashALG(..)
  , PubKeyALG(..)
  , objectToSignedExact
  , AltName(..)
  , DistinguishedName(..)
  )
import Data.X509.AttCert
  ( AttCertIssuer(..)
  , AttCertValidityPeriod(..)
  , Holder(..)
  , IssuerSerial(..)
  , V2Form(..)
  )
import Data.X509.Attribute (Attribute(..), Attributes(..))

import Data.X509.TCG.OID
  ( tcg_at_platformConfiguration_v2
  , tcg_at_tcgCredentialType
  , tcg_kp_DeltaAttributeCertificate
  , tcg_registry_componentClass_tcg
  , tcg_registry_componentClass_pcie
  , tcg_address_ethernetmac
  , tcg_address_wlanmac
  , tcg_address_bluetoothmac
  , tcg_paa_platformManufacturer
  , tcg_paa_platformModel
  , tcg_paa_platformVersion
  , tcg_paa_platformSerial
  )
import Data.X509.TCG.Platform (PlatformCertificateInfo(..), SignedPlatformCertificate)

import Data.X509.TCG.Compliance.Delta
import Data.X509.TCG.Compliance.Value
import Data.X509.TCG.Compliance.Errata
import Data.X509.TCG.Compliance.Registry
import Data.X509.TCG.Compliance.Check (runCategoryChecks, defaultComplianceOptions, ComplianceOptions(..))
import Data.X509.TCG.Compliance.Reference (defaultReferenceDB)
import Data.X509.TCG.Compliance.Result (CheckStatus(..), CheckResult(..), CategoryResult(..))
import Data.X509.TCG.Compliance.Types (ComplianceMode(..), CheckCategory(..), CheckId(..), detectCertificateType)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

dummySign :: B.ByteString -> (B.ByteString, SignatureALG, ())
dummySign _ = (B.replicate 32 0x00, SignatureALG HashSHA256 PubKeyALG_RSA, ())

issuerDN :: DistinguishedName
issuerDN = DistinguishedName [([2,5,4,3], ASN1CharacterString UTF8 (B8.pack "Test Issuer"))]

testIssuer :: AttCertIssuer
testIssuer = AttCertIssuerV2 (V2Form [AltDirectoryName issuerDN] Nothing Nothing)

mkHolder :: Maybe Integer -> Holder
mkHolder Nothing = Holder Nothing Nothing Nothing
mkHolder (Just serialNo) =
  let isr = IssuerSerial [AltDirectoryName issuerDN] serialNo Nothing
  in Holder (Just isr) Nothing Nothing

mkValidity :: Integer -> Integer -> AttCertValidityPeriod
mkValidity yStart yEnd =
  let nb = DateTime (Date (fromIntegral yStart) January 1) (TimeOfDay 0 0 0 0)
      na = DateTime (Date (fromIntegral yEnd) January 1) (TimeOfDay 0 0 0 0)
  in AttCertValidityPeriod nb na

mkSignedCert :: Integer -> Holder -> Attributes -> Extensions -> AttCertValidityPeriod -> SignedPlatformCertificate
mkSignedCert serialNo holder attrs exts validity =
  let pci = PlatformCertificateInfo
        { pciVersion = 2
        , pciHolder = holder
        , pciIssuer = testIssuer
        , pciSignature = SignatureALG HashSHA256 PubKeyALG_RSA
        , pciSerialNumber = serialNo
        , pciValidity = validity
        , pciAttributes = attrs
        , pciIssuerUniqueID = Nothing
        , pciExtensions = exts
        }
  in fst (objectToSignedExact dummySign pci)

mkSanExtension :: [(OID, B.ByteString)] -> ExtensionRaw
mkSanExtension attrs =
  let rdnSets = concatMap mkRdn attrs
      dn = [Start Sequence] ++ rdnSets ++ [End Sequence]
      generalNames =
        [ Start Sequence
        , Start (Container Context 4)
        ] ++ dn ++
        [ End (Container Context 4)
        , End Sequence
        ]
      raw = L.toStrict (encodeASN1 DER generalNames)
  in ExtensionRaw [2,5,29,17] False raw
  where
    mkRdn (oid, val) =
      [ Start Set
      , Start Sequence
      , OID oid
      , ASN1String (ASN1CharacterString UTF8 val)
      , End Sequence
      , End Set
      ]

data CompSpec = CompSpec
  { csRegistry :: OID
  , csClassValue :: B.ByteString
  , csManufacturer :: B.ByteString
  , csModel :: B.ByteString
  , csRevision :: Maybe B.ByteString
  , csStatus :: Maybe Integer
  , csAddresses :: [(OID, B.ByteString)]
  }

encodeComponentV2 :: CompSpec -> [ASN1]
encodeComponentV2 comp =
  [ Start Sequence
  , Start Sequence
  , OID (csRegistry comp)
  , OctetString (csClassValue comp)
  , End Sequence
  , ASN1String (ASN1CharacterString UTF8 (csManufacturer comp))
  , ASN1String (ASN1CharacterString UTF8 (csModel comp))
  ]
  ++ maybe [] (\r -> [Other Context 1 r]) (csRevision comp)
  ++ encodeAddresses (csAddresses comp)
  ++ maybe [] (\s -> [Other Context 7 (B.singleton (fromIntegral s))]) (csStatus comp)
  ++ [ End Sequence ]

encodeAddresses :: [(OID, B.ByteString)] -> [ASN1]
encodeAddresses [] = []
encodeAddresses addrs =
  [ Start (Container Context 4) ]
  ++ concatMap encodeAddress addrs ++
  [ End (Container Context 4) ]
  where
    encodeAddress (oid, val) =
      [ Start Sequence
      , OID oid
      , ASN1String (ASN1CharacterString UTF8 val)
      , End Sequence
      ]

mkPlatformConfigV2Attr :: [CompSpec] -> Attribute
mkPlatformConfigV2Attr comps =
  let asn1 =
        [ Start Sequence
        , Start (Container Context 0)
        ] ++ concatMap encodeComponentV2 comps ++
        [ End (Container Context 0)
        , End Sequence
        ]
      raw = L.toStrict (encodeASN1 DER asn1)
  in Attribute tcg_at_platformConfiguration_v2 [[OctetString raw]]

mkDeltaCredentialAttr :: Attribute
mkDeltaCredentialAttr = Attribute tcg_at_tcgCredentialType [[OID tcg_kp_DeltaAttributeCertificate]]

mkBaseCert :: Integer -> [CompSpec] -> [(OID, B.ByteString)] -> AttCertValidityPeriod -> SignedPlatformCertificate
mkBaseCert serialNo comps sanAttrs validity =
  let attrs = Attributes [mkPlatformConfigV2Attr comps]
      exts = Extensions (Just [mkSanExtension sanAttrs])
  in mkSignedCert serialNo (mkHolder Nothing) attrs exts validity

mkDeltaCert :: Integer -> Integer -> [CompSpec] -> [(OID, B.ByteString)] -> AttCertValidityPeriod -> SignedPlatformCertificate
mkDeltaCert baseSerial deltaSerial comps sanAttrs validity =
  let attrs = Attributes [mkPlatformConfigV2Attr comps, mkDeltaCredentialAttr]
      exts = Extensions (Just [mkSanExtension sanAttrs])
  in mkSignedCert deltaSerial (mkHolder (Just baseSerial)) attrs exts validity

assertStatus :: CheckStatus -> CheckResult -> Assertion
assertStatus expected res =
  case (expected, crStatus res) of
    (Pass, Pass) -> pure ()
    (Fail _, Fail _) -> pure ()
    (Skip _, Skip _) -> pure ()
    (Error _, Error _) -> pure ()
    _ -> assertFailure ("Unexpected status: " <> show (crStatus res))

isError :: CheckStatus -> Bool
isError (Error _) = True
isError _ = False

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

tests :: TestTree
tests = testGroup "Compliance Guide Strictness"
  [ testCase "DLT-001 delta-only changes pass when modified differs" $ do
      let baseComp = CompSpec tcg_registry_componentClass_tcg (B.pack [0,1,0,1]) "M" "Model" (Just "r1") Nothing []
          deltaComp = baseComp { csRevision = Just "r2", csStatus = Just 1 }
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          validity = mkValidity 2024 2030
          baseCert = mkBaseCert 100 [baseComp] san validity
          deltaCert = mkDeltaCert 100 101 [deltaComp] san validity
      res <- checkDeltaHasPlatformConfigWithCert deltaCert baseCert defaultReferenceDB
      assertStatus Pass res

  , testCase "DLT-001 fails when modified has no changes" $ do
      let baseComp = CompSpec tcg_registry_componentClass_tcg (B.pack [0,1,0,1]) "M" "Model" (Just "r1") Nothing []
          deltaComp = baseComp { csStatus = Just 1 }
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          validity = mkValidity 2024 2030
          baseCert = mkBaseCert 100 [baseComp] san validity
          deltaCert = mkDeltaCert 100 101 [deltaComp] san validity
      res <- checkDeltaHasPlatformConfigWithCert deltaCert baseCert defaultReferenceDB
      case crStatus res of
        Fail _ -> pure ()
        other -> assertFailure ("Expected Fail, got " <> show other)

  , testCase "DLT-005 OperationalCompatibility fails on notAfter precede" $ do
      let baseComp = CompSpec tcg_registry_componentClass_tcg (B.pack [0,1,0,1]) "M" "Model" Nothing Nothing []
          deltaComp = baseComp { csStatus = Just 1, csRevision = Just "r2" }
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          baseValidity = mkValidity 2024 2030
          deltaValidity = mkValidity 2024 2029
          baseCert = mkBaseCert 100 [baseComp] san baseValidity
          deltaCert = mkDeltaCert 100 101 [deltaComp] san deltaValidity
      res <- checkValidityMatchesBaseWithCertWithMode OperationalCompatibility deltaCert baseCert defaultReferenceDB
      case crStatus res of
        Fail _ -> pure ()
        other -> assertFailure ("Expected Fail, got " <> show other)

  , testCase "DLT-005 StrictV11 requires notAfter match" $ do
      let baseComp = CompSpec tcg_registry_componentClass_tcg (B.pack [0,1,0,1]) "M" "Model" Nothing Nothing []
          deltaComp = baseComp { csStatus = Just 1, csRevision = Just "r2" }
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          baseValidity = mkValidity 2024 2030
          deltaValidity = mkValidity 2024 2030
          baseCert = mkBaseCert 100 [baseComp] san baseValidity
          deltaCert = mkDeltaCert 100 101 [deltaComp] san deltaValidity
      res <- checkValidityMatchesBaseWithCertWithMode StrictV11 deltaCert baseCert defaultReferenceDB
      assertStatus Pass res

  , testCase "DLT-009 manufacturer mismatch fails" $ do
      let baseComp = CompSpec tcg_registry_componentClass_tcg (B.pack [0,1,0,1]) "BaseM" "Model" Nothing Nothing []
          deltaComp = baseComp { csStatus = Just 1, csRevision = Just "r2" }
          baseSan =
            [ (tcg_paa_platformManufacturer, "BaseM")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          deltaSan =
            [ (tcg_paa_platformManufacturer, "DeltaM")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          validity = mkValidity 2024 2030
          baseCert = mkBaseCert 100 [baseComp] baseSan validity
          deltaCert = mkDeltaCert 100 101 [deltaComp] deltaSan validity
      res <- checkManufacturerMatchesBaseWithCert deltaCert baseCert defaultReferenceDB
      case crStatus res of
        Fail _ -> pure ()
        other -> assertFailure ("Expected Fail, got " <> show other)

  , testCase "ERR-005 accepts multiple MAC address formats" $ do
      let macs =
            [ (tcg_address_ethernetmac, "aa:bb:cc:dd:ee:ff")
            , (tcg_address_wlanmac, "AA-BB-CC-DD-EE-FF")
            , (tcg_address_bluetoothmac, "AABB.CCDD.EEFF")
            ]
          comp = CompSpec tcg_registry_componentClass_tcg (B.pack [0,1,0,1]) "M" "Model" Nothing Nothing macs
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          validity = mkValidity 2024 2030
          cert = mkBaseCert 100 [comp] san validity
      res <- check48BitMacOids cert defaultReferenceDB
      assertStatus Pass res

  , testCase "REG-004 non-canonical PCIe MAC yields Skip" $ do
      let pcieClass = B.pack [0x00, 0x02, 0x00, 0x00]
          macs = [(tcg_address_ethernetmac, "aa:bb:cc:dd:ee:ff")]
          comp = CompSpec tcg_registry_componentClass_pcie pcieClass "M" "Model" Nothing Nothing macs
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          validity = mkValidity 2024 2030
          cert = mkBaseCert 100 [comp] san validity
      res <- checkRegistryTranslationScope cert defaultReferenceDB
      case crStatus res of
        Skip _ -> pure ()
        other -> assertFailure ("Expected Skip, got " <> show other)

  , testCase "DER malformed platformConfiguration fails" $ do
      let badAttr = Attribute tcg_at_platformConfiguration_v2 [[OctetString (B.pack [0x30, 0x01])]]
          attrs = Attributes [badAttr]
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          exts = Extensions (Just [mkSanExtension san])
          validity = mkValidity 2024 2030
          cert = mkSignedCert 100 (mkHolder Nothing) attrs exts validity
      res <- checkComponentId cert defaultReferenceDB
      case crStatus res of
        Fail _ -> pure ()
        other -> assertFailure ("Expected Fail, got " <> show other)

  , testCase "VAL-001 fails when STRMAX exceeded" $ do
      let longStr = B.replicate 257 0x41
          san =
            [ (tcg_paa_platformManufacturer, longStr)
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          attrs = Attributes []
          exts = Extensions (Just [mkSanExtension san])
          validity = mkValidity 2024 2030
          cert = mkSignedCert 100 (mkHolder Nothing) attrs exts validity
      res <- checkManufacturerStr cert defaultReferenceDB
      case crStatus res of
        Fail _ -> pure ()
        other -> assertFailure ("Expected Fail, got " <> show other)

  , testCase "StrictV11 without base yields Error for base-required Delta checks" $ do
      let baseComp = CompSpec tcg_registry_componentClass_tcg (B.pack [0,1,0,1]) "M" "Model" Nothing Nothing []
          deltaComp = baseComp { csStatus = Just 1, csRevision = Just "r2" }
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          validity = mkValidity 2024 2030
          deltaCert = mkDeltaCert 100 101 [deltaComp] san validity
          certType = detectCertificateType deltaCert
          opts = defaultComplianceOptions { coMode = StrictV11, coBaseCert = Nothing }
      cat <- runCategoryChecks deltaCert certType defaultReferenceDB opts Delta
      let errIds = [crId c | c <- catChecks cat, isError (crStatus c)]
      assertBool "DLT-001 should be Error without base in StrictV11" (CheckId Delta 1 `elem` errIds)
      assertBool "DLT-004 should be Error without base in StrictV11" (CheckId Delta 4 `elem` errIds)

  , testCase "REG-004 pass with canonical PCIe MAC" $ do
      let pcieClass = B.pack [0x00, 0x02, 0x00, 0x00]
          macs = [(tcg_address_ethernetmac, "AABBCCDDEEFF")]
          comp = CompSpec tcg_registry_componentClass_pcie pcieClass "M" "Model" Nothing Nothing macs
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          validity = mkValidity 2024 2030
          cert = mkBaseCert 100 [comp] san validity
      res <- checkRegistryTranslationScope cert defaultReferenceDB
      assertStatus Pass res

  , testCase "REG-004 skip when no scoped registry present" $ do
      let tcgClass = B.pack [0x00, 0x01, 0x00, 0x01]
          comp = CompSpec tcg_registry_componentClass_tcg tcgClass "M" "Model" Nothing Nothing []
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          validity = mkValidity 2024 2030
          cert = mkBaseCert 100 [comp] san validity
      res <- checkRegistryTranslationScope cert defaultReferenceDB
      case crStatus res of
        Skip _ -> pure ()
        other -> assertFailure ("Expected Skip, got " <> show other)

  , testCase "REG-004 fail on malformed platformConfiguration" $ do
      let badAttr = Attribute tcg_at_platformConfiguration_v2 [[OctetString (B.pack [0x30, 0x01])]]
          attrs = Attributes [badAttr]
          san =
            [ (tcg_paa_platformManufacturer, "M")
            , (tcg_paa_platformModel, "Model")
            , (tcg_paa_platformVersion, "1")
            , (tcg_paa_platformSerial, "S")
            ]
          exts = Extensions (Just [mkSanExtension san])
          validity = mkValidity 2024 2030
          cert = mkSignedCert 100 (mkHolder Nothing) attrs exts validity
      res <- checkRegistryTranslationScope cert defaultReferenceDB
      case crStatus res of
        Fail _ -> pure ()
        other -> assertFailure ("Expected Fail, got " <> show other)
  ]
