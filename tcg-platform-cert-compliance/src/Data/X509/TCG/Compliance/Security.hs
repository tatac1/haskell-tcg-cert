{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Security
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Security assertion checks (SEC-001 to SEC-005).
--
-- Validates security-related attributes per IWG Profile.

module Data.X509.TCG.Compliance.Security
  ( -- * All Security Checks
    runSecurityChecks

    -- * Individual Checks
  , checkTbbSecForBaseOnly   -- SEC-001
  , checkTcgSpecForBaseOnly  -- SEC-002
  , checkMeasurementRootType -- SEC-003
  , checkCCMeasuresConsist   -- SEC-004
  , checkUriRefHash          -- SEC-005
  ) where

import Control.Applicative ((<|>))
import Data.Maybe (isJust)
import qualified Data.Text as T
import qualified Data.ByteString as B

import Data.X509.Attribute (Attributes(..), Attribute(..), attrType)

import Data.X509.TCG.Platform (SignedPlatformCertificate, getPlatformCertificate)
import Data.X509.TCG.Platform (PlatformCertificateInfo(..))
import Data.X509.TCG.OID (tcg_at_tbbSecurityAssertions, tcg_at_tcgPlatformSpecification, tcg_at_platformConfiguration, tcg_at_platformConfiguration_v2)
import Data.X509.TCG.Utils (lookupAttributeByOID)

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.ASN1
  ( ParsedTbbSecurityAssertions(..)
  , ParsedCommonCriteriaMeasures(..)
  , ParsedURIReference(..)
  , ParsedPlatformConfiguration(..)
  , ParsedComponent(..)
  , parseTBBSecurityAssertions
  , parsePlatformConfiguration
  )
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Internal (lookupRef, ComplianceCheck)

-- | Run all security compliance checks
runSecurityChecks :: SignedPlatformCertificate -> ReferenceDB -> IO [CheckResult]
runSecurityChecks cert refDB = sequence
  [ checkTbbSecForBaseOnly cert refDB
  , checkTcgSpecForBaseOnly cert refDB
  , checkMeasurementRootType cert refDB
  , checkCCMeasuresConsist cert refDB
  , checkUriRefHash cert refDB
  ]

-- | SEC-001: TBBSecurityAssertions for Base only
-- Reference: IWG Profile §3.1.1, line 693
-- "tBBSecurityAssertions MUST NOT be included in Delta"
checkTbbSecForBaseOnly :: ComplianceCheck
checkTbbSecForBaseOnly cert refDB = do
  let cid = CheckId Security 1
      ref = lookupRef cid refDB
      certType = detectCertificateType cert
      pci = getPlatformCertificate cert
      Attributes attrs = pciAttributes pci
      hasTbbSec = any (\a -> attrType a == tcg_at_tbbSecurityAssertions) attrs
  case certType of
    BasePlatformCert ->
      -- For Base certificates, TBBSecurityAssertions is allowed
      mkPass cid "TBBSecurityAssertions check (Base certificate - allowed)" ref
    DeltaPlatformCert ->
      if hasTbbSec
        then mkFail cid "TBBSecurityAssertions for Base only" ref
               "TBBSecurityAssertions MUST NOT be included in Delta Platform Certificate"
        else mkPass cid "TBBSecurityAssertions properly omitted from Delta" ref

-- | SEC-002: TCGPlatformSpecification for Base only
-- Reference: IWG Profile §3.1.3, line 851
-- "TCGPlatformSpecification MUST NOT be included in Delta"
checkTcgSpecForBaseOnly :: ComplianceCheck
checkTcgSpecForBaseOnly cert refDB = do
  let cid = CheckId Security 2
      ref = lookupRef cid refDB
      certType = detectCertificateType cert
      pci = getPlatformCertificate cert
      Attributes attrs = pciAttributes pci
      hasTcgSpec = any (\a -> attrType a == tcg_at_tcgPlatformSpecification) attrs
  case certType of
    BasePlatformCert ->
      -- For Base certificates, TCGPlatformSpecification is allowed
      mkPass cid "TCGPlatformSpecification check (Base certificate - allowed)" ref
    DeltaPlatformCert ->
      if hasTcgSpec
        then mkFail cid "TCGPlatformSpecification for Base only" ref
               "TCGPlatformSpecification MUST NOT be included in Delta Platform Certificate"
        else mkPass cid "TCGPlatformSpecification properly omitted from Delta" ref

-- | SEC-003: MeasurementRootType values (0-5)
-- Reference: IWG Profile §3.1.1, line 727
-- "MeasurementRootType ::= ENUMERATED { static(0)..virtual(5) }"
checkMeasurementRootType :: ComplianceCheck
checkMeasurementRootType cert refDB = do
  let cid = CheckId Security 3
      ref = lookupRef cid refDB
      certType = detectCertificateType cert
      pci = getPlatformCertificate cert
      Attributes attrs = pciAttributes pci
      hasTbbSec = any (\a -> attrType a == tcg_at_tbbSecurityAssertions) attrs
  case certType of
    DeltaPlatformCert -> mkSkip cid "MeasurementRootType values" ref
      "Not applicable to Delta certificates"
    BasePlatformCert ->
      if not hasTbbSec
        then mkSkip cid "MeasurementRootType values" ref
               "No TBBSecurityAssertions attribute"
        else
          case lookupAttributeByOID tcg_at_tbbSecurityAssertions (pciAttributes pci) of
            Nothing -> mkSkip cid "MeasurementRootType values" ref
              "No TBBSecurityAssertions attribute"
            Just asn1Values ->
              case parseTBBSecurityAssertions asn1Values of
                Left err -> mkFail cid "MeasurementRootType values" ref err
                Right tbb ->
                  case ptbbRtmType tbb of
                    Nothing -> mkSkip cid "MeasurementRootType values" ref "No MeasurementRootType present"
                    Just v ->
                      if v >= 0 && v <= 5
                        then mkPass cid "MeasurementRootType values are valid" ref
                        else mkFail cid "MeasurementRootType values" ref $
                          "Invalid MeasurementRootType value: " <> T.pack (show v)

-- | SEC-004: CommonCriteriaMeasures consistency
-- Reference: IWG Profile §3.1.1, line 688
-- "profileOid and profileUri MUST represent consistent values"
checkCCMeasuresConsist :: ComplianceCheck
checkCCMeasuresConsist cert refDB = do
  let cid = CheckId Security 4
      ref = lookupRef cid refDB
      certType = detectCertificateType cert
      pci = getPlatformCertificate cert
      Attributes attrs = pciAttributes pci
      hasTbbSec = any (\a -> attrType a == tcg_at_tbbSecurityAssertions) attrs
      manualNote = "Structure-only check. Semantic consistency between OID and URI is not validated; manual review required."
  case certType of
    DeltaPlatformCert -> mkSkip cid "CommonCriteriaMeasures consistency (structure-only)" ref
      "Not applicable to Delta certificates"
    BasePlatformCert ->
      if not hasTbbSec
        then mkSkip cid "CommonCriteriaMeasures consistency (structure-only)" ref
               "No TBBSecurityAssertions attribute"
        else
          case lookupAttributeByOID tcg_at_tbbSecurityAssertions (pciAttributes pci) of
            Nothing -> mkSkip cid "CommonCriteriaMeasures consistency (structure-only)" ref
              "No TBBSecurityAssertions attribute"
            Just asn1Values ->
              case parseTBBSecurityAssertions asn1Values of
                Left err -> mkFail cid "CommonCriteriaMeasures consistency (structure-only)" ref err
                Right tbb ->
                  case ptbbCcInfo tbb of
                    Nothing -> mkSkip cid "CommonCriteriaMeasures consistency (structure-only)" ref
                      "No CommonCriteriaMeasures present"
                    Just cc ->
                      let hasProfilePair = isJust (pccProfileOid cc) && isJust (pccProfileUri cc)
                          hasTargetPair = isJust (pccTargetOid cc) && isJust (pccTargetUri cc)
                      in if hasProfilePair || hasTargetPair
                           then mkPassWithDetails cid "CommonCriteriaMeasures consistency (structure-only)" ref manualNote
                           else mkSkip cid "CommonCriteriaMeasures consistency (structure-only)" ref
                                 "OID/URI pair not both present; consistency not applicable"

-- | SEC-005: URIReference hash requirements
-- Reference: IWG Profile §3.1.1, lines 402-403
-- "hashAlgorithm and hashValue MUST both exist in each reference"
-- Validates URIReference fields in:
--   - TBBSecurityAssertions: profileUri, targetUri
--   - PlatformConfiguration: componentIdentifiersUri, platformPropertiesUri
--   - ComponentIdentifier: componentPlatformCertUri
checkUriRefHash :: ComplianceCheck
checkUriRefHash cert refDB = do
  let cid = CheckId Security 5
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      uriMax = 1024
      validateUriRef label uriRef =
        let uriLen = B.length (puriUri uriRef)
            hasAlg = isJust (puriHashAlg uriRef)
            hasVal = isJust (puriHashValue uriRef)
        in if uriLen < 1 || uriLen > uriMax
             then Left $ label <> ": URI length out of range"
             else if hasAlg /= hasVal
               then Left $ label <> ": hashAlgorithm/hashValue must both be present or both absent"
               else Right ()

      -- Collect URIs from TBBSecurityAssertions
      tbbUris = case lookupAttributeByOID tcg_at_tbbSecurityAssertions (pciAttributes pci) of
        Nothing -> []
        Just asn1Values ->
          case parseTBBSecurityAssertions asn1Values of
            Left _ -> []
            Right tbb -> concat
              [ maybe [] (\u -> [("TBB.profileUri", u)]) (ptbbCcInfo tbb >>= pccProfileUri)
              , maybe [] (\u -> [("TBB.targetUri", u)]) (ptbbCcInfo tbb >>= pccTargetUri)
              ]

      -- Collect URIs from PlatformConfiguration (v1 or v2)
      platformConfigUris =
        let mConfig = lookupAttributeByOID tcg_at_platformConfiguration_v2 (pciAttributes pci)
                  <|> lookupAttributeByOID tcg_at_platformConfiguration (pciAttributes pci)
        in case mConfig of
             Nothing -> []
             Just asn1Values ->
               case parsePlatformConfiguration asn1Values of
                 Left _ -> []
                 Right cfg -> concat
                   [ maybe [] (\u -> [("PlatformConfig.componentIdentifiersUri", u)]) (ppcComponentsUri cfg)
                   , maybe [] (\u -> [("PlatformConfig.platformPropertiesUri", u)]) (ppcPropertiesUri cfg)
                   -- Collect componentPlatformCertUri from each component
                   , concatMap (\(i, c) ->
                       maybe [] (\u -> [("Component[" <> T.pack (show i) <> "].componentPlatformCertUri", u)]) (pcPlatformCertUri c)
                     ) (zip [0::Int ..] (ppcComponents cfg))
                   ]

      allUris = tbbUris ++ platformConfigUris

      firstError [] = Nothing
      firstError ((label, u):rest) =
        case validateUriRef label u of
          Left err -> Just err
          Right () -> firstError rest

  if null allUris
    then mkSkip cid "URIReference hash requirements" ref
           "No URIReference fields present"
    else case firstError allUris of
           Nothing -> mkPass cid "URIReference hash requirements satisfied" ref
           Just err -> mkFail cid "URIReference hash requirements" ref err
