{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Value
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Value constraint checks (VAL-001 to VAL-017).
--
-- Validates attribute value constraints per IWG Profile.
-- These checks ensure that attribute values conform to the
-- expected formats, ranges, and constraints specified in the
-- IWG Platform Certificate Profile v1.1.

module Data.X509.TCG.Compliance.Value
  ( -- * All Value Checks
    runValueChecks

    -- * Individual Checks
  , checkManufacturerStr     -- VAL-001
  , checkPlatformModel       -- VAL-002
  , checkPlatformVersion     -- VAL-003
  , checkPlatformSerial      -- VAL-004
  , checkManufacturerId      -- VAL-005
  , checkTpmSecAssertions    -- VAL-006
  , checkTpmSecVersion       -- VAL-007
  , checkFipsLevel           -- VAL-008
  , checkIso9000Certified    -- VAL-009
  , checkEalLevel            -- VAL-010
  , checkComponentId         -- VAL-011
  , checkClassRegistry       -- VAL-012
  , checkClassValue          -- VAL-013
  , checkAttrCertId          -- VAL-014
  , checkComponentIdV2       -- VAL-015 (OperationalCompatibility default)
  , checkComponentIdV2WithMode -- VAL-015 (mode-aware)
  , checkCertId              -- VAL-016
  , checkSofRange            -- VAL-017
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.ByteString as B
import qualified Data.Text.Encoding as TE
import Control.Applicative ((<|>))
import qualified Data.Map.Strict as Map

import Data.ASN1.Types (ASN1(..), OID)
import Data.ASN1.Types.String (ASN1StringEncoding(..))

import Data.X509.TCG.Platform (SignedPlatformCertificate, getPlatformCertificate)
import Data.X509.TCG.Platform (PlatformCertificateInfo(..))
import Data.X509.TCG.OID
  ( tcg_paa_platformManufacturer
  , tcg_paa_platformModel
  , tcg_paa_platformVersion
  , tcg_paa_platformSerial
  , tcg_paa_platformManufacturerId
  , tcg_at_platformManufacturer
  , tcg_at_platformModel
  , tcg_at_platformVersion
  , tcg_at_platformSerial
  , tcg_at_tbbSecurityAssertions
  , tcg_at_platformConfiguration
  , tcg_at_platformConfiguration_v2
  )
import Data.X509.TCG.Utils (lookupAttributeByOID)

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.ASN1
  ( asn1StringValue
  , asn1OIDValue
  , formatOID
  , stripSequence
  , extractSANAttributes
  , ParsedComponent(..)
  , ParsedPlatformConfiguration(..)
  , ParsedAttributeCertificateIdentifier(..)
  , ParsedCertificateIdentifier(..)
  , ParsedTbbSecurityAssertions(..)
  , ParsedFipsLevel(..)
  , ParsedCommonCriteriaMeasures(..)
  , parsePlatformConfiguration
  , parsePlatformComponents
  , parseTBBSecurityAssertions
  )
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Internal (lookupRef, ComplianceCheck)

strMax :: Int
strMax = 256

uriMax :: Int
uriMax = 1024

requireUtf8String :: Text -> ASN1 -> Either Text B.ByteString
requireUtf8String label val =
  case asn1StringValue val of
    Just (UTF8, bs) ->
      case TE.decodeUtf8' bs of
        Left _ -> Left $ label <> ": invalid UTF8String"
        Right _ ->
          if B.length bs >= 1 && B.length bs <= strMax
            then Right bs
            else Left $ label <> ": UTF8String length out of range"
    Just (enc, _) -> Left $ label <> ": expected UTF8String, got " <> T.pack (show enc)
    Nothing -> Left $ label <> ": expected UTF8String"

requireOIDValue :: Text -> ASN1 -> Either Text OID
requireOIDValue label val =
  case asn1OIDValue val of
    Just oid -> Right oid
    Nothing -> Left $ label <> ": expected OBJECT IDENTIFIER"

isIanaPen :: OID -> Bool
isIanaPen oid = take 6 oid == [1,3,6,1,4,1] && length oid > 6


lookupNameAttrValues :: SignedPlatformCertificate -> [OID] -> Either Text (Maybe [ASN1])
lookupNameAttrValues cert oids = do
  let pci = getPlatformCertificate cert
      exts = pciExtensions pci
      firstJust [] = Nothing
      firstJust (x:xs) = case x of
        Just _ -> x
        Nothing -> firstJust xs
  sanMap <- extractSANAttributes exts
  case sanMap of
    Nothing -> Right Nothing
    Just m ->
      Right (firstJust [case Map.lookup oid m of
                          Just (v:_) -> Just v
                          _ -> Nothing
                       | oid <- oids])

-- | Get parsed component list from platformConfiguration (v1 or v2).
getPlatformComponents :: SignedPlatformCertificate -> Either Text [ParsedComponent]
getPlatformComponents cert =
  let attrs = pciAttributes $ getPlatformCertificate cert
      values = lookupAttributeByOID tcg_at_platformConfiguration_v2 attrs
        <|> lookupAttributeByOID tcg_at_platformConfiguration attrs
  in case values of
       Nothing -> Right []
       Just v -> parsePlatformComponents v

getPlatformConfiguration :: SignedPlatformCertificate -> Either Text (Maybe ParsedPlatformConfiguration)
getPlatformConfiguration cert =
  let attrs = pciAttributes $ getPlatformCertificate cert
  in case lookupAttributeByOID tcg_at_platformConfiguration_v2 attrs
      <|> lookupAttributeByOID tcg_at_platformConfiguration attrs of
       Nothing -> Right Nothing
       Just v -> Just <$> parsePlatformConfiguration v

-- | Run all value constraint checks
runValueChecks :: SignedPlatformCertificate -> ReferenceDB -> IO [CheckResult]
runValueChecks cert refDB = sequence
  [ checkManufacturerStr cert refDB
  , checkPlatformModel cert refDB
  , checkPlatformVersion cert refDB
  , checkPlatformSerial cert refDB
  , checkManufacturerId cert refDB
  , checkTpmSecAssertions cert refDB
  , checkTpmSecVersion cert refDB
  , checkFipsLevel cert refDB
  , checkIso9000Certified cert refDB
  , checkEalLevel cert refDB
  , checkComponentId cert refDB
  , checkClassRegistry cert refDB
  , checkClassValue cert refDB
  , checkAttrCertId cert refDB
  , checkComponentIdV2 cert refDB
  , checkCertId cert refDB
  , checkSofRange cert refDB
  ]

-- | VAL-001: Manufacturer string must be valid UTF8String
-- Reference: IWG Profile §3.1.6, line 957
checkManufacturerStr :: ComplianceCheck
checkManufacturerStr cert refDB = do
  let cid = CheckId Value 1
      ref = lookupRef cid refDB
  case lookupNameAttrValues cert [tcg_paa_platformManufacturer, tcg_at_platformManufacturer] of
    Left err -> mkFail cid "platformManufacturerStr UTF8String" ref err
    Right Nothing -> mkSkip cid "platformManufacturerStr UTF8String" ref
      "platformManufacturerStr attribute not present"
    Right (Just []) -> mkFail cid "platformManufacturerStr UTF8String" ref
      "platformManufacturerStr attribute is empty"
    Right (Just (val:_)) ->
      case requireUtf8String "platformManufacturerStr" val of
        Right _ -> mkPass cid "platformManufacturerStr is valid UTF8String" ref
        Left err -> mkFail cid "platformManufacturerStr UTF8String" ref err

-- | VAL-002: Platform model must be valid UTF8String
-- Reference: IWG Profile §3.1.6, line 959
checkPlatformModel :: ComplianceCheck
checkPlatformModel cert refDB = do
  let cid = CheckId Value 2
      ref = lookupRef cid refDB
  case lookupNameAttrValues cert [tcg_paa_platformModel, tcg_at_platformModel] of
    Left err -> mkFail cid "platformModel UTF8String" ref err
    Right Nothing -> mkSkip cid "platformModel UTF8String" ref
      "platformModel attribute not present"
    Right (Just []) -> mkFail cid "platformModel UTF8String" ref
      "platformModel attribute is empty"
    Right (Just (val:_)) ->
      case requireUtf8String "platformModel" val of
        Right _ -> mkPass cid "platformModel is valid UTF8String" ref
        Left err -> mkFail cid "platformModel UTF8String" ref err

-- | VAL-003: Platform version must be valid UTF8String
-- Reference: IWG Profile §3.1.6, line 961
checkPlatformVersion :: ComplianceCheck
checkPlatformVersion cert refDB = do
  let cid = CheckId Value 3
      ref = lookupRef cid refDB
  case lookupNameAttrValues cert [tcg_paa_platformVersion, tcg_at_platformVersion] of
    Left err -> mkFail cid "platformVersion UTF8String" ref err
    Right Nothing -> mkSkip cid "platformVersion UTF8String" ref
      "platformVersion attribute not present"
    Right (Just []) -> mkFail cid "platformVersion UTF8String" ref
      "platformVersion attribute is empty"
    Right (Just (val:_)) ->
      case requireUtf8String "platformVersion" val of
        Right _ -> mkPass cid "platformVersion is valid UTF8String" ref
        Left err -> mkFail cid "platformVersion UTF8String" ref err

-- | VAL-004: Platform serial must be valid UTF8String
-- Reference: IWG Profile §3.1.6, line 963
checkPlatformSerial :: ComplianceCheck
checkPlatformSerial cert refDB = do
  let cid = CheckId Value 4
      ref = lookupRef cid refDB
  case lookupNameAttrValues cert [tcg_paa_platformSerial, tcg_at_platformSerial] of
    Left err -> mkFail cid "platformSerial UTF8String" ref err
    Right Nothing -> mkSkip cid "platformSerial UTF8String" ref
      "platformSerial attribute not present"
    Right (Just []) -> mkFail cid "platformSerial UTF8String" ref
      "platformSerial attribute is empty"
    Right (Just (val:_)) ->
      case requireUtf8String "platformSerial" val of
        Right _ -> mkPass cid "platformSerial is valid UTF8String" ref
        Left err -> mkFail cid "platformSerial UTF8String" ref err

-- | VAL-005: Manufacturer ID must be valid Private Enterprise Number
-- Reference: IWG Profile §3.1.6, line 965
checkManufacturerId :: ComplianceCheck
checkManufacturerId cert refDB = do
  let cid = CheckId Value 5
      ref = lookupRef cid refDB
      validatePen oidVal =
        if isIanaPen oidVal
          then mkPass cid "platformManufacturerId is valid IANA PEN OID" ref
          else mkFail cid "platformManufacturerId OID" ref $
                 "Expected IANA PEN OID under 1.3.6.1.4.1, got " <> formatOID oidVal
  case lookupNameAttrValues cert [tcg_paa_platformManufacturerId] of
    Left err -> mkFail cid "platformManufacturerId OID" ref err
    Right Nothing -> mkSkip cid "platformManufacturerId OID" ref
      "platformManufacturerId attribute not present"
    Right (Just []) -> mkFail cid "platformManufacturerId OID" ref
      "platformManufacturerId attribute is empty"
    Right (Just values) ->
      -- Per IWG §3.1.6 lines 463-465: ManufacturerId ::= SEQUENCE { manufacturerIdentifier PrivateEnterpriseNumber }
      -- ManufacturerId MUST be a SEQUENCE, bare OID is non-compliant
      case values of
        (OID _ : _) -> mkFail cid "platformManufacturerId structure" ref
          "ManufacturerId must be SEQUENCE per IWG §3.1.6, got bare OID"
        _ ->
          case stripSequence values of
            Left err -> mkFail cid "platformManufacturerId structure" ref $
              "ManufacturerId must be SEQUENCE per IWG §3.1.6: " <> err
            Right content ->
              case content of
                (nestedVal:_) ->
                  case requireOIDValue "platformManufacturerId" nestedVal of
                    Left err -> mkFail cid "platformManufacturerId OID" ref err
                    Right oidVal -> validatePen oidVal
                [] -> mkFail cid "platformManufacturerId OID" ref
                  "platformManufacturerId SEQUENCE missing manufacturerIdentifier"

-- | VAL-006: TPM Security Assertions must be properly structured
-- Reference: IWG Profile §3.1.1, line 695
checkTpmSecAssertions :: ComplianceCheck
checkTpmSecAssertions cert refDB = do
  let cid = CheckId Value 6
      certType = detectCertificateType cert
      reqLevel = getRequirementLevel cid certType
      ref = (lookupRef cid refDB) { srLevel = reqLevel }
      pci = getPlatformCertificate cert
      attrs = pciAttributes pci
  case certType of
    DeltaPlatformCert ->
      case lookupAttributeByOID tcg_at_tbbSecurityAssertions attrs of
        Nothing -> mkPass cid "TBBSecurityAssertions correctly omitted in Delta" ref
        Just _ -> mkFail cid "TBBSecurityAssertions omitted in Delta" ref
          "TBBSecurityAssertions MUST NOT be included in Delta certificates"
    BasePlatformCert ->
      case lookupAttributeByOID tcg_at_tbbSecurityAssertions attrs of
        Nothing -> mkSkip cid "TBBSecurityAssertions structure" ref "No TBBSecurityAssertions attribute"
        Just asn1Values ->
          case parseTBBSecurityAssertions asn1Values of
            Right _ -> mkPass cid "TBBSecurityAssertions structure is valid" ref
            Left err -> mkFail cid "TBBSecurityAssertions structure" ref err

-- | VAL-007: TPM Security version must match specification
-- Reference: IWG Profile §3.1.1, line 708
checkTpmSecVersion :: ComplianceCheck
checkTpmSecVersion cert refDB = do
  let cid = CheckId Value 7
      ref = lookupRef cid refDB
      certType = detectCertificateType cert
      pci = getPlatformCertificate cert
      attrs = pciAttributes pci
  case certType of
    DeltaPlatformCert ->
      mkSkip cid "TBBSecurityAssertions.version" ref "Not applicable to Delta certificates"
    BasePlatformCert ->
      case lookupAttributeByOID tcg_at_tbbSecurityAssertions attrs of
        Nothing -> mkSkip cid "TBBSecurityAssertions.version" ref "No TBBSecurityAssertions attribute"
        Just asn1Values ->
          case parseTBBSecurityAssertions asn1Values of
            Left err -> mkFail cid "TBBSecurityAssertions.version" ref err
            Right tbb ->
              case ptbbVersion tbb of
                Nothing -> mkPass cid "TBBSecurityAssertions.version omitted (DEFAULT v1)" ref
                Just 0 -> mkPass cid "TBBSecurityAssertions.version is v1(0)" ref
                Just v -> mkFail cid "TBBSecurityAssertions.version" ref $
                  "Invalid TBBSecurityAssertions.version: " <> T.pack (show v)

-- | VAL-008: FIPS SecurityLevel must be 1-4
-- Reference: IWG Profile §3.1.1, line 783
checkFipsLevel :: ComplianceCheck
checkFipsLevel cert refDB = do
  let cid = CheckId Value 8
      ref = lookupRef cid refDB
      certType = detectCertificateType cert
      pci = getPlatformCertificate cert
      attrs = pciAttributes pci
  case certType of
    DeltaPlatformCert ->
      mkSkip cid "FIPS level in range 1-4" ref "Not applicable to Delta certificates"
    BasePlatformCert ->
      case lookupAttributeByOID tcg_at_tbbSecurityAssertions attrs of
        Nothing -> mkSkip cid "FIPS level in range 1-4" ref "No TBBSecurityAssertions attribute"
        Just asn1Values ->
          case parseTBBSecurityAssertions asn1Values of
            Left err -> mkFail cid "FIPS level in range 1-4" ref err
            Right tbb ->
              case ptbbFipsLevel tbb of
                Nothing -> mkSkip cid "FIPS level in range 1-4" ref "No FIPSLevel in TBBSecurityAssertions"
                Just fips ->
                  if pfLevel fips >= 1 && pfLevel fips <= 4
                    then if B.length (pfVersion fips) >= 1 && B.length (pfVersion fips) <= strMax
                           then mkPass cid "FIPS level in range 1-4" ref
                           else mkFail cid "FIPS level in range 1-4" ref "FIPSLevel.version length out of range"
                    else mkFail cid "FIPS level in range 1-4" ref $
                      "Invalid FIPS level: " <> T.pack (show (pfLevel fips))

-- | VAL-009: ISO 9000 Certified must be boolean
-- Reference: IWG Profile §3.1.1, line 793
checkIso9000Certified :: ComplianceCheck
checkIso9000Certified cert refDB = do
  let cid = CheckId Value 9
      ref = lookupRef cid refDB
      certType = detectCertificateType cert
      pci = getPlatformCertificate cert
      attrs = pciAttributes pci
  case certType of
    DeltaPlatformCert ->
      mkSkip cid "ISO9000 certified boolean" ref "Not applicable to Delta certificates"
    BasePlatformCert ->
      case lookupAttributeByOID tcg_at_tbbSecurityAssertions attrs of
        Nothing -> mkSkip cid "ISO9000 certified boolean" ref "No TBBSecurityAssertions attribute"
        Just asn1Values ->
          case parseTBBSecurityAssertions asn1Values of
            Left err -> mkFail cid "ISO9000 certified boolean" ref err
            Right tbb ->
              case ptbbIso9000Uri tbb of
                Just uri ->
                  if B.length uri >= 1 && B.length uri <= uriMax
                    then mkPass cid "ISO9000 certified boolean present" ref
                    else mkFail cid "ISO9000 certified boolean" ref "iso9000Uri length out of range"
                Nothing ->
                  case ptbbIso9000Certified tbb of
                    Just _ -> mkPass cid "ISO9000 certified boolean present" ref
                    Nothing -> mkSkip cid "ISO9000 certified boolean" ref "ISO9000Certified omitted (DEFAULT FALSE)"

-- | VAL-010: Common Criteria EAL must be 1-7
-- Reference: IWG Profile §3.1.1, line 749
checkEalLevel :: ComplianceCheck
checkEalLevel cert refDB = do
  let cid = CheckId Value 10
      ref = lookupRef cid refDB
      certType = detectCertificateType cert
      pci = getPlatformCertificate cert
      attrs = pciAttributes pci
  case certType of
    DeltaPlatformCert ->
      mkSkip cid "EAL level in range 1-7" ref "Not applicable to Delta certificates"
    BasePlatformCert ->
      case lookupAttributeByOID tcg_at_tbbSecurityAssertions attrs of
        Nothing -> mkSkip cid "EAL level in range 1-7" ref "No TBBSecurityAssertions attribute"
        Just asn1Values ->
          case parseTBBSecurityAssertions asn1Values of
            Left err -> mkFail cid "EAL level in range 1-7" ref err
            Right tbb ->
              case ptbbCcInfo tbb of
                Nothing -> mkSkip cid "EAL level in range 1-7" ref "No CommonCriteriaMeasures present"
                Just cc ->
                  if pccAssurance cc >= 1 && pccAssurance cc <= 7
                    then if B.length (pccVersion cc) >= 1 && B.length (pccVersion cc) <= strMax
                           then mkPass cid "EAL level in range 1-7" ref
                           else mkFail cid "EAL level in range 1-7" ref "CommonCriteriaMeasures.version length out of range"
                    else mkFail cid "EAL level in range 1-7" ref $
                      "Invalid EAL level: " <> T.pack (show (pccAssurance cc))

-- | VAL-011: ComponentIdentifier structure must be valid
-- Reference: IWG Profile §3.1.6, line 977
checkComponentId :: ComplianceCheck
checkComponentId cert refDB = do
  let cid = CheckId Value 11
      ref = lookupRef cid refDB
  case getPlatformConfiguration cert of
    Left err -> mkFail cid "ComponentIdentifier structure" ref err
    Right Nothing -> mkSkip cid "ComponentIdentifier structure" ref "No platformConfiguration"
    Right (Just cfg) ->
      if null (ppcComponents cfg)
        then mkSkip cid "ComponentIdentifier structure" ref "No components"
        else
          let requiresClass = not (ppcIsLegacy cfg)
              bad = [c | c <- ppcComponents cfg
                       , (requiresClass &&
                          (pcClassRegistry c == Nothing || pcClassValue c == Nothing))
                         || pcManufacturer c == Nothing
                         || pcModel c == Nothing
                         || not (validPen (pcManufacturerId c))
                         || not (validStr (pcManufacturer c))
                         || not (validStr (pcModel c))
                         || not (validOptStr (pcSerial c))
                         || not (validOptStr (pcRevision c))
                       ]
              validStr (Just bs) = B.length bs >= 1 && B.length bs <= strMax
              validStr _ = False
              validOptStr Nothing = True
              validOptStr (Just bs) = B.length bs >= 1 && B.length bs <= strMax
              validPen Nothing = True
              validPen (Just oid) = isIanaPen oid
          in if null bad
               then mkPass cid "ComponentIdentifiers present" ref
               else mkFail cid "ComponentIdentifier structure" ref "ComponentIdentifier missing required fields or invalid string length"

-- | VAL-012: Component class registry must be valid OID
-- Reference: IWG Profile §3.1.6, line 977
-- Note: ComponentIdentifier v1 does not have class registry field.
-- This check applies only to v2 components (platformConfigurationV2).
checkClassRegistry :: ComplianceCheck
checkClassRegistry cert refDB = do
  let cid = CheckId Value 12
      ref = lookupRef cid refDB
  case getPlatformConfiguration cert of
    Left err -> mkFail cid "Component class registry OID" ref err
    Right Nothing -> mkSkip cid "Component class registry OID" ref "No platformConfiguration"
    Right (Just cfg)
      | ppcIsLegacy cfg ->
          mkSkip cid "Component class registry OID" ref
            "Legacy platformConfiguration (v1) omits componentClassRegistry"
      | null (ppcComponents cfg) ->
          mkSkip cid "Component class registry OID" ref "No components"
      | otherwise ->
          let registries = [oid | ParsedComponent { pcClassRegistry = Just oid } <- ppcComponents cfg]
          in if null registries
               then mkFail cid "Component class registry OID" ref "Missing componentClassRegistry"
               else mkPass cid "Component class registry OID present" ref

-- | VAL-013: Validate componentClassValue structure
-- Reference: TCG Component Class Registry v1.0 §3, line 228
-- Note: ComponentIdentifier v1 does not have class value field.
-- This check applies only to v2 components (platformConfigurationV2).
checkClassValue :: ComplianceCheck
checkClassValue cert refDB = do
  let cid = CheckId Value 13
      ref = lookupRef cid refDB
  case getPlatformConfiguration cert of
    Left err -> mkFail cid "componentClassValue structure" ref err
    Right Nothing -> mkSkip cid "componentClassValue structure" ref "No platformConfiguration"
    Right (Just cfg)
      | ppcIsLegacy cfg ->
          mkSkip cid "componentClassValue structure" ref
            "Legacy platformConfiguration (v1) omits componentClassValue"
      | null (ppcComponents cfg) ->
          mkSkip cid "componentClassValue structure" ref "No components"
      | otherwise ->
          let classValues = [val | ParsedComponent { pcClassValue = Just val } <- ppcComponents cfg]
              invalid = filter (\bs -> B.length bs /= 4) classValues
          in if null classValues
               then mkFail cid "componentClassValue structure" ref "Missing componentClassValue"
               else if null invalid
                 then mkPass cid "componentClassValue structure is valid" ref
                 else mkFail cid "componentClassValue structure" ref
                        ("Invalid componentClassValue length(s): " <> T.pack (show (map B.length invalid)))

-- | VAL-014: Attribute Certificate ID structure
-- Reference: IWG Profile §3.2.4, line 1168
checkAttrCertId :: ComplianceCheck
checkAttrCertId cert refDB = do
  let cid = CheckId Value 14
      ref = lookupRef cid refDB
  case getPlatformComponents cert of
    Left err -> mkFail cid "Attribute certificate ID structure" ref err
    Right comps ->
      let certIds = [cid' | ParsedComponent { pcPlatformCert = Just cid' } <- comps]
          attrIds = [aci | ParsedCertificateIdentifier { pciAttrCertId = Just aci } <- certIds]
          invalid = [aci | aci <- attrIds, B.null (paciHashValue aci)]
      in if null comps
           then mkSkip cid "Attribute certificate ID structure" ref "No components"
           else if null certIds
             then mkSkip cid "Attribute certificate ID structure" ref "No componentPlatformCert present"
             else if null attrIds
               then mkSkip cid "Attribute certificate ID structure" ref "No attributeCertIdentifier present"
               else if null invalid
                 then mkPass cid "Attribute certificate ID structure valid" ref
                 else mkFail cid "Attribute certificate ID structure" ref
                        "attributeCertIdentifier.hashOverSignatureValue must be non-empty"

-- | VAL-015: ComponentIdentifierV2 structure must be valid
-- Reference: IWG Profile §3.1.7, line 1001
checkComponentIdV2 :: ComplianceCheck
checkComponentIdV2 = checkComponentIdV2WithMode OperationalCompatibility

checkComponentIdV2WithMode :: ComplianceMode -> ComplianceCheck
checkComponentIdV2WithMode mode cert refDB = do
  let cid = CheckId Value 15
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      attrs = pciAttributes pci
      v2Values = lookupAttributeByOID tcg_at_platformConfiguration_v2 attrs
      v1Values = lookupAttributeByOID tcg_at_platformConfiguration attrs
  case v2Values of
    Just values ->
      case parsePlatformConfiguration values of
        Left err -> mkFail cid "ComponentIdentifierV2 structure" ref err
        Right _ -> mkPass cid "platformConfigurationV2 attribute structure valid" ref
    Nothing ->
      case v1Values of
        Nothing -> mkSkip cid "ComponentIdentifierV2 structure" ref "No platformConfiguration attribute"
        Just values ->
          case mode of
            StrictV11 ->
              mkFail cid "ComponentIdentifierV2 structure" ref
                "platformConfiguration uses deprecated v1 OID; tcg-at-platformConfiguration-v2 is required in StrictV11 mode"
            OperationalCompatibility ->
              case parsePlatformConfiguration values of
                Left err -> mkFail cid "ComponentIdentifierV2 structure" ref err
                Right _ ->
                  mkPassWithDetails cid "platformConfiguration v1 accepted (operational compatibility)" ref
                    "OperationalCompatibility mode: tcg-at-platformConfiguration (v1) accepted"

-- | VAL-016: Certificate ID structure
-- Reference: IWG Profile §3.2.4, line 1168
checkCertId :: ComplianceCheck
checkCertId cert refDB = do
  let cid = CheckId Value 16
      ref = lookupRef cid refDB
  case getPlatformComponents cert of
    Left err -> mkFail cid "Certificate ID structure" ref err
    Right comps ->
      let certIds = [cid' | ParsedComponent { pcPlatformCert = Just cid' } <- comps]
          invalid = [c | c <- certIds, pciAttrCertId c == Nothing && pciIssuerSerial c == Nothing]
      in if null comps
           then mkSkip cid "Certificate ID structure" ref "No components"
           else if null certIds
             then mkSkip cid "Certificate ID structure" ref "No componentPlatformCert present"
             else if null invalid
               then mkPass cid "Certificate ID structure valid" ref
               else mkFail cid "Certificate ID structure" ref "CertificateIdentifier missing attributeCertIdentifier or genericCertIdentifier"

-- | VAL-017: StrengthOfFunction must be 0-2
-- Reference: IWG Profile §3.1.1, line 758
checkSofRange :: ComplianceCheck
checkSofRange cert refDB = do
  let cid = CheckId Value 17
      ref = lookupRef cid refDB
      certType = detectCertificateType cert
      pci = getPlatformCertificate cert
      attrs = pciAttributes pci
  case certType of
    DeltaPlatformCert ->
      mkSkip cid "StrengthOfFunction in range 0-2" ref "Not applicable to Delta certificates"
    BasePlatformCert ->
      case lookupAttributeByOID tcg_at_tbbSecurityAssertions attrs of
        Nothing -> mkSkip cid "StrengthOfFunction in range 0-2" ref "No TBBSecurityAssertions attribute"
        Just asn1Values ->
          case parseTBBSecurityAssertions asn1Values of
            Left err -> mkFail cid "StrengthOfFunction in range 0-2" ref err
            Right tbb ->
              case ptbbCcInfo tbb of
                Nothing -> mkSkip cid "StrengthOfFunction in range 0-2" ref "No CommonCriteriaMeasures present"
                Just cc ->
                  case pccStrength cc of
                    Nothing -> mkSkip cid "StrengthOfFunction in range 0-2" ref "No StrengthOfFunction present"
                    Just v | v >= 0 && v <= 2 -> mkPass cid "StrengthOfFunction in range 0-2" ref
                    Just v -> mkFail cid "StrengthOfFunction in range 0-2" ref $
                      "Invalid StrengthOfFunction: " <> T.pack (show v)
