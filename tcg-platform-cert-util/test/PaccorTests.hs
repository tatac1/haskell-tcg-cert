{-# LANGUAGE OverloadedStrings #-}

module PaccorTests (paccorTests) where

import Test.Tasty
import Test.Tasty.HUnit
import Data.Maybe (isJust)
import qualified Data.ByteString as B
import Data.X509 (Extensions(..), ExtensionRaw(..))
import Data.X509.TCG.Util.Paccor
import Data.X509.TCG.Util.Config (PlatformCertConfig(..), SecurityAssertionsConfig(..))
import Data.X509.TCG.Util.Certificate (loadCACertificate)

-- Test fixture paths (relative to package root)
fixturePolicyRef :: FilePath
fixturePolicyRef = "test/fixtures/PolicyReference.json"

fixtureComponentList :: FilePath
fixtureComponentList = "test/fixtures/ComponentList.json"

fixtureExtensions :: FilePath
fixtureExtensions = "test/fixtures/Extensions.json"

fixtureCACert :: FilePath
fixtureCACert = "test/fixtures/TestCA.cert.pem"

paccorTests :: TestTree
paccorTests = testGroup "Paccor Config Parsing"
  [ testCase "parse PolicyReference.json" $ do
      result <- loadPaccorPolicyReference fixturePolicyRef
      case result of
        Left err -> assertFailure $ "Failed to parse: " ++ err
        Right pr -> do
          -- TCGPLATFORMSPECIFICATION
          case pprPlatformSpec pr of
            Nothing -> assertFailure "Missing TCGPLATFORMSPECIFICATION"
            Just ps -> do
              psvMajor (ppsVersion ps) @?= 2
              psvMinor (ppsVersion ps) @?= 0
              psvRevision (ppsVersion ps) @?= 43
              ppsPlatformClass ps @?= "AAAAAQ=="
          -- TCGCREDENTIALSPECIFICATION
          case pprCredentialSpec pr of
            Nothing -> assertFailure "Missing TCGCREDENTIALSPECIFICATION"
            Just cs -> do
              psvMajor cs @?= 1
              psvMinor cs @?= 1
              psvRevision cs @?= 11
          -- TBBSECURITYASSERTIONS
          case pprSecurityAssertions pr of
            Nothing -> assertFailure "Missing TBBSECURITYASSERTIONS"
            Just sa -> do
              ptbbVersion sa @?= Just 0
              ptbbIso9000Certified sa @?= Just False
              ptbbRtmType sa @?= Just "static"
              -- CCINFO
              case ptbbCCInfo sa of
                Nothing -> assertFailure "Missing CCINFO"
                Just cc -> do
                  pccInfoVersion cc @?= "3.1"
                  pccInfoAssuranceLevel cc @?= "level7"
                  pccInfoEvalStatus cc @?= "evaluationCompleted"
                  pccInfoPlus cc @?= Just True
                  pccInfoStrengthOfFunction cc @?= Just "medium"
                  pccInfoProfileOid cc @?= Just "1.2.3.4.5.6"
                  pccInfoTargetOid cc @?= Just "2.3.4.5.6.7"
              -- FIPSLEVEL
              case ptbbFipsLevel sa of
                Nothing -> assertFailure "Missing FIPSLEVEL"
                Just fl -> do
                  pflVersion fl @?= "140-2"
                  pflLevel fl @?= "level4"
                  pflPlus fl @?= Just False

  , testCase "merge PolicyReference into PlatformCertConfig" $ do
      -- Load ComponentList
      configResult <- loadAnyConfig
        fixtureComponentList
      config <- case configResult of
        Left err -> assertFailure ("Config: " ++ err) >> undefined
        Right c -> return c
      -- Load PolicyReference
      prResult <- loadPaccorPolicyReference
        fixturePolicyRef
      pr <- case prResult of
        Left err -> assertFailure ("PolicyRef: " ++ err) >> undefined
        Right p -> return p
      -- Merge
      let merged = mergePolicyReference pr config
      -- Verify merged fields
      pccPlatformSpecMajor merged @?= Just 2
      pccPlatformSpecMinor merged @?= Just 0
      pccPlatformSpecRevision merged @?= Just 43
      pccCredentialSpecMajor merged @?= Just 1
      pccCredentialSpecMinor merged @?= Just 1
      pccCredentialSpecRevision merged @?= Just 11
      pccPlatformClass merged @?= Just "00000001"  -- Base64 "AAAAAQ==" decoded
      -- SecurityAssertions populated
      case pccSecurityAssertions merged of
        Nothing -> assertFailure "Missing securityAssertions after merge"
        Just sa -> do
          sacRTMType sa @?= Just "static"
          sacCCVersion sa @?= Just "3.1"
          sacEvalAssuranceLevel sa @?= Just 7  -- "level7" -> 7
          sacFIPSVersion sa @?= Just "140-2"
          sacFIPSSecurityLevel sa @?= Just 4   -- "level4" -> 4
          sacPlus sa @?= Just True
          sacStrengthOfFunction sa @?= Just "medium"
          sacISO9000Certified sa @?= Just False

  , testCase "parse Extensions.json" $ do
      result <- loadPaccorExtensions
        fixtureExtensions
      case result of
        Left err -> assertFailure $ "Failed to parse: " ++ err
        Right ext -> do
          -- CERTIFICATEPOLICIES
          case pextCertPolicies ext of
            Nothing -> assertFailure "Missing CERTIFICATEPOLICIES"
            Just policies -> do
              length policies @?= 1
              pcpOid (head policies) @?= "1.2.840.113741.1.5.2.4"
              length (pcpQualifiers (head policies)) @?= 2
              -- Verify qualifier types
              let qs = pcpQualifiers (head policies)
              ppqId (head qs) @?= "CPS"
              ppqValue (head qs) @?= "http://www.example.invalid/cps"
              ppqId (qs !! 1) @?= "USERNOTICE"
              ppqValue (qs !! 1) @?= "TCG Trusted Platform Endorsement"
          -- AUTHORITYINFOACCESS
          case pextAuthorityInfoAccess ext of
            Nothing -> assertFailure "Missing AUTHORITYINFOACCESS"
            Just aias -> do
              length aias @?= 1
              paiaMethod (head aias) @?= "OCSP"
              paiaLocation (head aias) @?= "http://www.example.invalid/ocsp"
          -- CRLDISTRIBUTION
          case pextCrlDistribution ext of
            Nothing -> assertFailure "Missing CRLDISTRIBUTION"
            Just crl -> do
              pcrlReason crl @?= Just 8
              case pcrlDistName crl of
                Nothing -> assertFailure "Missing DISTRIBUTIONNAME"
                Just dn -> do
                  pdnType dn @?= 0
                  pdnName dn @?= "http://www.example.invalid/crl/platform.crl"

  , testCase "end-to-end: load all paccor configs and merge" $ do
      -- Load ComponentList
      configResult <- loadAnyConfig
        fixtureComponentList
      config0 <- case configResult of
        Left err -> assertFailure ("Config: " ++ err) >> undefined
        Right c -> return c
      -- Load PolicyReference and merge
      prResult <- loadPaccorPolicyReference
        fixturePolicyRef
      pr <- case prResult of
        Left err -> assertFailure ("PolicyRef: " ++ err) >> undefined
        Right p -> return p
      let config = mergePolicyReference pr config0
      -- Load Extensions and convert
      extResult <- loadPaccorExtensions
        fixtureExtensions
      ext <- case extResult of
        Left err -> assertFailure ("Extensions: " ++ err) >> undefined
        Right e -> return e
      let extensions = paccorExtensionsToX509 ext
      -- Verify merged config has all expected fields
      pccPlatformSpecMajor config @?= Just 2
      pccCredentialSpecMajor config @?= Just 1
      isJust (pccSecurityAssertions config) @? "SecurityAssertions should be set"
      -- Verify extensions are not empty
      case extensions of
        Extensions Nothing -> assertFailure "Extensions should not be empty"
        Extensions (Just exts) ->
          length exts >= 2 @? "Should have CertPolicies + AIA at minimum"
      -- Verify components from ComponentList
      length (pccComponents config) > 0 @? "Should have components from ComponentList"

  , testCase "convert PaccorExtensions to X.509 Extensions" $ do
      result <- loadPaccorExtensions
        fixtureExtensions
      ext <- case result of
        Left err -> assertFailure err >> undefined
        Right e -> return e
      let extensions = paccorExtensionsToX509 ext
      case extensions of
        Extensions Nothing -> assertFailure "Extensions should not be empty"
        Extensions (Just exts) -> do
          -- Should have 3 extensions: CertPolicies, AIA, CRL DP
          length exts @?= 3
          -- CertificatePolicies OID = 2.5.29.32, non-critical
          let certPol = exts !! 0
          extRawOID certPol @?= [2, 5, 29, 32]
          extRawCritical certPol @?= False
          -- AuthorityInfoAccess OID = 1.3.6.1.5.5.7.1.1, non-critical
          let aia = exts !! 1
          extRawOID aia @?= [1, 3, 6, 1, 5, 5, 7, 1, 1]
          extRawCritical aia @?= False
          -- CRLDistributionPoints OID = 2.5.29.31, non-critical
          let crl = exts !! 2
          extRawOID crl @?= [2, 5, 29, 31]
          extRawCritical crl @?= False

  , testCase "build AKI extension from CA certificate (CHN-001)" $ do
      -- Load IWG CA certificate which should have a Subject Key Identifier
      caCertResult <- loadCACertificate
        fixtureCACert
      caCert <- case caCertResult of
        Left err -> assertFailure ("CA cert: " ++ err) >> undefined
        Right c -> return c
      -- buildAkiExtension should extract SKI and produce AKI
      let mAki = buildAkiExtension caCert
      case mAki of
        Nothing -> assertFailure "CA cert should have SKI, so AKI should be generated"
        Just aki -> do
          -- OID = 2.5.29.35 (Authority Key Identifier)
          extRawOID aki @?= [2, 5, 29, 35]
          -- Must be non-critical per CHN-001
          extRawCritical aki @?= False
          -- Content should not be empty
          B.length (extRawContent aki) > 0 @? "AKI content should not be empty"
  ]
