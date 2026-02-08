{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Delta
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Delta certificate specific compliance checks (DLT-001 to DLT-012).
--
-- These checks validate requirements specific to Delta Platform Certificates
-- as defined in IWG Platform Certificate Profile v1.1 Section 3.3.

module Data.X509.TCG.Compliance.Delta
  ( -- * Check Runner
    runDeltaChecks
  , runDeltaChecksWithBase

    -- * Individual Checks
  , checkDeltaHasPlatformConfig  -- DLT-001
  , checkDeltaHasPlatformConfigWithCert -- DLT-001 (base-aware)
  , checkDeltaHasCredentialType  -- DLT-002
  , checkDeltaSerialPositive     -- DLT-003
  , checkHolderRefsBase          -- DLT-004 (needs base cert)
  , checkValidityMatchesBase     -- DLT-005 (needs base cert)
  , checkValidityMatchesBaseWithMode -- DLT-005 (mode-aware, no base)
  , checkAttributeStatusValues   -- DLT-006
  , checkStatusFieldDeltaOnly    -- DLT-007
  , checkComponentsHaveStatus    -- DLT-008
  , checkManufacturerMatchesBase -- DLT-009 (needs base cert)
  , checkModelMatchesBase        -- DLT-010 (needs base cert)
  , checkVersionMatchesBase      -- DLT-011 (needs base cert)
  , checkSerialMatchesBase       -- DLT-012 (needs base cert)

    -- * Base Certificate Comparison Checks
  , checkHolderRefsBaseWithCert
  , checkValidityMatchesBaseWithCert
  , checkValidityMatchesBaseWithCertWithMode
  , checkManufacturerMatchesBaseWithCert
  , checkModelMatchesBaseWithCert
  , checkVersionMatchesBaseWithCert
  , checkSerialMatchesBaseWithCert
  ) where

import qualified Data.Text as T
import qualified Data.ByteString as B
import qualified Data.Map.Strict as Map
import Control.Applicative ((<|>))

import Data.X509.TCG.Platform
  ( SignedPlatformCertificate
  , getPlatformCertificate
  , pciAttributes
  , pciSerialNumber
  , pciHolder
  , pciValidity
  , pciIssuer
  , pciExtensions
  )
import Data.X509 (AltName(..), DistinguishedName)
import Data.X509.AttCert (AttCertValidityPeriod(..), acNotAfter, Holder(..), IssuerSerial(..), AttCertIssuer(..), V2Form(..))
import Data.X509.TCG.OID
  ( tcg_at_tcgCredentialType
  , tcg_at_platformConfiguration
  , tcg_at_platformConfiguration_v2
  , tcg_paa_platformManufacturer
  , tcg_paa_platformModel
  , tcg_paa_platformVersion
  , tcg_paa_platformSerial
  , tcg_paa_platformManufacturerId
  , tcg_at_platformManufacturer
  , tcg_at_platformModel
  , tcg_at_platformVersion
  , tcg_at_platformSerial
  , tcg_kp_DeltaAttributeCertificate
  )
import Data.X509.TCG.Utils (lookupAttributeByOID)
import Data.ASN1.Types (ASN1(..), OID)
import Data.ASN1.Types.String (ASN1StringEncoding(..))
import qualified Data.Text.Encoding as TE

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.ASN1
  ( asn1StringValue
  , parsePlatformConfiguration
  , ParsedPlatformConfiguration(..)
  , ParsedProperty(..)
  , ParsedComponent(..)
  , stripSequence
  , extractSANAttributes
  )
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Internal (ComplianceCheck, lookupRef)

withRequirement :: RequirementLevel -> SpecReference -> SpecReference
withRequirement lvl ref = ref { srLevel = lvl }

tshow :: Show a => a -> T.Text
tshow = T.pack . show

-- | STRMAX per IWG Profile §2.2: UTF8String (SIZE (1..255))
strMax :: Int
strMax = 255

requireUtf8String :: T.Text -> ASN1 -> Either T.Text B.ByteString
requireUtf8String label val =
  case val of
    OctetString bs -> validateUtf8Bytes label bs
    _ ->
      case asn1StringValue val of
        Just (UTF8, bs) -> validateUtf8Bytes label bs
        Just (enc, _) -> Left $ label <> ": expected UTF8String or OctetString, got " <> T.pack (show enc)
        Nothing -> Left $ label <> ": expected UTF8String or OctetString"

validateUtf8Bytes :: T.Text -> B.ByteString -> Either T.Text B.ByteString
validateUtf8Bytes label bs =
  case TE.decodeUtf8' bs of
    Left _ -> Left $ label <> ": invalid UTF-8 encoding"
    Right _ ->
      if B.length bs >= 1 && B.length bs <= strMax
        then Right bs
        else Left $ label <> ": UTF8String length out of range (1.." <> tshow strMax <> ")"

lookupNameAttrValues :: SignedPlatformCertificate -> [OID] -> Either T.Text (Maybe [ASN1])
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

getRequiredAttrUtf8 :: SignedPlatformCertificate -> [OID] -> T.Text -> Either T.Text B.ByteString
getRequiredAttrUtf8 cert oids label =
  case lookupNameAttrValues cert oids of
    Left err -> Left err
    Right Nothing -> Left (label <> " attribute not present")
    Right (Just []) -> Left (label <> " attribute is empty")
    Right (Just (val:_)) -> requireUtf8String label val

extractDNsFromGeneralNames :: [AltName] -> [DistinguishedName]
extractDNsFromGeneralNames [] = []
extractDNsFromGeneralNames (AltDirectoryName dn : rest) = dn : extractDNsFromGeneralNames rest
extractDNsFromGeneralNames (_ : rest) = extractDNsFromGeneralNames rest

extractIssuerDNs :: AttCertIssuer -> [DistinguishedName]
extractIssuerDNs (AttCertIssuerV1 gns) = extractDNsFromGeneralNames gns
extractIssuerDNs (AttCertIssuerV2 v2form) =
  case v2formBaseCertificateID v2form of
    Just issuerSerial -> extractDNsFromGeneralNames (issuer issuerSerial)
    Nothing -> extractDNsFromGeneralNames (v2formIssuerName v2form)

getDeltaConfiguration :: SignedPlatformCertificate -> Either T.Text (Maybe ParsedPlatformConfiguration)
getDeltaConfiguration = getParsedPlatformConfiguration

getParsedPlatformConfiguration :: SignedPlatformCertificate -> Either T.Text (Maybe ParsedPlatformConfiguration)
getParsedPlatformConfiguration cert =
  let attrs = pciAttributes $ getPlatformCertificate cert
      values = lookupAttributeByOID tcg_at_platformConfiguration_v2 attrs
        <|> lookupAttributeByOID tcg_at_platformConfiguration attrs
  in case values of
       Nothing -> Right Nothing
       Just [] -> Left "platformConfiguration attribute is empty"
       Just values' -> Just <$> parsePlatformConfiguration values'

-- | Run all delta compliance checks (without base certificate)
runDeltaChecks :: SignedPlatformCertificate -> ReferenceDB -> IO [CheckResult]
runDeltaChecks cert refDB = sequence
  [ checkDeltaHasPlatformConfig cert refDB   -- DLT-001
  , checkDeltaHasCredentialType cert refDB   -- DLT-002
  , checkDeltaSerialPositive cert refDB      -- DLT-003
  , checkHolderRefsBase cert refDB           -- DLT-004
  , checkValidityMatchesBase cert refDB      -- DLT-005
  , checkAttributeStatusValues cert refDB    -- DLT-006
  , checkStatusFieldDeltaOnly cert refDB     -- DLT-007
  , checkComponentsHaveStatus cert refDB     -- DLT-008
  , checkManufacturerMatchesBase cert refDB  -- DLT-009
  , checkModelMatchesBase cert refDB         -- DLT-010
  , checkVersionMatchesBase cert refDB       -- DLT-011
  , checkSerialMatchesBase cert refDB        -- DLT-012
  ]

-- | Run all delta compliance checks with base certificate for comparison
runDeltaChecksWithBase :: SignedPlatformCertificate  -- ^ Delta certificate
                       -> SignedPlatformCertificate  -- ^ Base certificate
                       -> ReferenceDB
                       -> IO [CheckResult]
runDeltaChecksWithBase deltaCert baseCert refDB = sequence
  [ checkDeltaHasPlatformConfigWithCert deltaCert baseCert refDB -- DLT-001
  , checkDeltaHasCredentialType deltaCert refDB              -- DLT-002
  , checkDeltaSerialPositive deltaCert refDB                 -- DLT-003
  , checkHolderRefsBaseWithCert deltaCert baseCert refDB     -- DLT-004
  , checkValidityMatchesBaseWithCert deltaCert baseCert refDB -- DLT-005
  , checkAttributeStatusValues deltaCert refDB               -- DLT-006
  , checkStatusFieldDeltaOnly deltaCert refDB                -- DLT-007
  , checkComponentsHaveStatus deltaCert refDB                -- DLT-008
  , checkManufacturerMatchesBaseWithCert deltaCert baseCert refDB -- DLT-009
  , checkModelMatchesBaseWithCert deltaCert baseCert refDB   -- DLT-010
  , checkVersionMatchesBaseWithCert deltaCert baseCert refDB -- DLT-011
  , checkSerialMatchesBaseWithCert deltaCert baseCert refDB  -- DLT-012
  ]

-- | DLT-001: Delta platformConfiguration semantics
-- Reference: IWG Profile §2.2.6.13, line 654
-- "The Delta Platform Certificate MUST only include platform properties
-- that have changed (added, modified, or deleted) with respect to the base certificate."
checkDeltaHasPlatformConfig :: ComplianceCheck
checkDeltaHasPlatformConfig cert refDB = do
  let cid = CheckId Delta 1
      ref = lookupRef cid refDB
      desc = "Delta platformConfiguration semantics"
      certType = detectCertificateType cert

  -- Only applicable to Delta certificates
  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert ->
      case getDeltaConfiguration cert of
        Left err -> mkFail cid desc ref err
        Right Nothing -> mkSkip cid desc ref
          "platformConfiguration is not present (MAY for Delta)"
        Right (Just _) -> mkPass cid
          "platformConfiguration present and structurally valid" ref

-- | DLT-001 (base-aware): Delta platformConfiguration must only include changes.
checkDeltaHasPlatformConfigWithCert :: SignedPlatformCertificate
                                    -> SignedPlatformCertificate
                                    -> ReferenceDB
                                    -> IO CheckResult
checkDeltaHasPlatformConfigWithCert deltaCert baseCert refDB = do
  let cid = CheckId Delta 1
      ref = lookupRef cid refDB
      desc = "Delta platformConfiguration delta-only changes"
      certType = detectCertificateType deltaCert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert ->
      case getParsedPlatformConfiguration deltaCert of
        Left err -> mkFail cid desc ref err
        Right Nothing -> mkSkip cid desc ref
          "platformConfiguration is not present (MAY for Delta)"
        Right (Just deltaCfg) ->
          if ppcIsLegacy deltaCfg
            then mkFail cid desc ref
              "Delta platformConfiguration must use v2 encoding with status enumerators"
            else
              case getParsedPlatformConfiguration baseCert of
                Left err -> mkFail cid desc ref ("Base certificate: " <> err)
                Right Nothing -> mkFail cid desc ref
                  "Base certificate missing platformConfiguration; cannot validate delta-only changes"
                Right (Just baseCfg) -> do
                  let legacyBase = ppcIsLegacy baseCfg
                      (issues, usedLegacy) = validateDeltaOnlyChanges legacyBase baseCfg deltaCfg
                  if null issues
                    then
                      if usedLegacy
                        then mkPassWithDetails cid desc ref
                          "Legacy base platformConfiguration: comparison uses manufacturer/model/serial identity only"
                        else mkPass cid desc ref
                    else mkFail cid desc ref (T.intercalate "; " issues)

validateDeltaOnlyChanges :: Bool
                         -> ParsedPlatformConfiguration
                         -> ParsedPlatformConfiguration
                         -> ([T.Text], Bool)
validateDeltaOnlyChanges legacyBase baseCfg deltaCfg =
  let baseComps = ppcComponents baseCfg
      deltaComps = ppcComponents deltaCfg
      baseProps = ppcProperties baseCfg
      deltaProps = ppcProperties deltaCfg
      compIssues = concatMap (validateDeltaComponent legacyBase baseComps) deltaComps
      propIssues = concatMap (validateDeltaProperty baseProps) deltaProps
  in (compIssues ++ propIssues, legacyBase)

type ComponentKey = (Maybe OID, Maybe B.ByteString, Maybe B.ByteString, Maybe B.ByteString, Maybe B.ByteString, Maybe OID)

componentKey :: Bool -> ParsedComponent -> ComponentKey
componentKey legacy c =
  let reg = if legacy then Nothing else pcClassRegistry c
      cls = if legacy then Nothing else pcClassValue c
  in (reg, cls, pcManufacturer c, pcModel c, pcSerial c, pcManufacturerId c)

normalizeComponent :: Bool -> ParsedComponent -> ParsedComponent
normalizeComponent legacy c =
  let c' = c { pcStatus = Nothing }
  in if legacy
       then c' { pcClassRegistry = Nothing, pcClassValue = Nothing }
       else c'

findMatchingBaseComponent :: Bool -> [ParsedComponent] -> ParsedComponent -> Either T.Text (Maybe ParsedComponent)
findMatchingBaseComponent legacy baseComps deltaComp =
  let matches = [c | c <- baseComps, matchesBaseComponent legacy deltaComp c]
  in case matches of
       [] -> Right Nothing
       [c] -> Right (Just c)
       _ -> Left ("Ambiguous base component identity for key " <> tshow (componentKey legacy deltaComp))

matchesBaseComponent :: Bool -> ParsedComponent -> ParsedComponent -> Bool
matchesBaseComponent legacy deltaComp baseComp =
  let classMatch
        | legacy = True
        | otherwise =
            pcClassRegistry deltaComp == pcClassRegistry baseComp
              && pcClassValue deltaComp == pcClassValue baseComp
      mfgMatch = pcManufacturer deltaComp == pcManufacturer baseComp
      modelMatch = pcModel deltaComp == pcModel baseComp
      serialMatch = case pcSerial deltaComp of
        Nothing -> True
        Just s -> pcSerial baseComp == Just s
      mfgIdMatch = case pcManufacturerId deltaComp of
        Nothing -> True
        Just oid -> pcManufacturerId baseComp == Just oid
  in classMatch && mfgMatch && modelMatch && serialMatch && mfgIdMatch

validateDeltaComponent :: Bool -> [ParsedComponent] -> ParsedComponent -> [T.Text]
validateDeltaComponent legacy baseComps deltaComp =
  case pcStatus deltaComp of
    Nothing -> ["Delta component missing status enumerator"]
    Just status ->
      case findMatchingBaseComponent legacy baseComps deltaComp of
        Left err -> [err]
        Right mBase ->
          case status of
            0 ->
              case mBase of
                Nothing -> []
                Just _ -> ["Delta component marked added but exists in base"]
            1 ->
              case mBase of
                Nothing -> ["Delta component marked modified but missing in base"]
                Just baseComp ->
                  let deltaNorm = normalizeComponent legacy deltaComp
                      baseNorm = normalizeComponent legacy baseComp
                  in if deltaNorm == baseNorm
                       then ["Delta component marked modified but has no changes vs base"]
                       else []
            2 ->
              case mBase of
                Nothing -> ["Delta component marked removed but missing in base"]
                Just _ -> []
            _ -> ["Delta component has invalid status value"]

validateDeltaProperty :: [ParsedProperty] -> ParsedProperty -> [T.Text]
validateDeltaProperty baseProps deltaProp =
  case ppStatus deltaProp of
    Nothing -> ["Delta property missing status enumerator"]
    Just status ->
      let matches = [p | p <- baseProps, ppName p == ppName deltaProp]
      in case matches of
           [] ->
             case status of
               0 -> []
               1 -> ["Delta property marked modified but missing in base"]
               2 -> ["Delta property marked removed but missing in base"]
               _ -> ["Delta property has invalid status value"]
           [baseProp] ->
             case status of
               0 -> ["Delta property marked added but exists in base"]
               1 ->
                 if ppValue baseProp == ppValue deltaProp
                   then ["Delta property marked modified but has no changes vs base"]
                   else []
               2 -> []
               _ -> ["Delta property has invalid status value"]
           _ -> ["Ambiguous base property identity for name " <> tshow (ppName deltaProp)]

-- | DLT-002: Delta certificate must have tcgCredentialType attribute
-- Reference: IWG Profile §3.3, line 1296
-- "TCG Certificate Type attribute MUST be included"
checkDeltaHasCredentialType :: ComplianceCheck
checkDeltaHasCredentialType cert refDB = do
  let cid = CheckId Delta 2
      ref = lookupRef cid refDB
      desc = "Delta certificate must have tcgCredentialType attribute"
      certType = detectCertificateType cert
      attrs = pciAttributes $ getPlatformCertificate cert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert ->
      case lookupAttributeByOID tcg_at_tcgCredentialType attrs of
        Nothing -> mkFail cid desc ref
          "Delta certificate must include tcgCredentialType attribute"
        Just asn1Values ->
          if any isDeltaOID asn1Values
            then mkPass cid desc ref
            else mkFail cid desc ref
              "tcgCredentialType must indicate Delta Platform Certificate"
  where
    isDeltaOID (OID oid) = oid == tcg_kp_DeltaAttributeCertificate
    isDeltaOID _ = False

-- | DLT-003: Serial number must be positive integer
-- Reference: IWG Profile §3.3.2, line 1282
-- "Positive integer value unique relative to the issuer"
checkDeltaSerialPositive :: ComplianceCheck
checkDeltaSerialPositive cert refDB = do
  let cid = CheckId Delta 3
      ref = lookupRef cid refDB
      desc = "Delta serial number must be positive integer"
      certType = detectCertificateType cert
      serialNum = pciSerialNumber $ getPlatformCertificate cert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert ->
      if serialNum > 0
        then mkPass cid desc ref
        else mkFail cid desc ref $
          "Serial number must be positive, got: " <> T.pack (show serialNum)

-- | DLT-004: Holder must reference base certificate
-- Reference: IWG Profile §3.3.4, line 1286
-- "Identity of the associated base Platform/Delta Platform Certificate"
-- Note: Requires base certificate for comparison
checkHolderRefsBase :: ComplianceCheck
checkHolderRefsBase cert refDB = do
  let cid = CheckId Delta 4
      ref = lookupRef cid refDB
      desc = "Holder must reference base certificate"
      certType = detectCertificateType cert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert -> mkSkip cid desc ref
      "Requires base certificate for comparison (not provided)"

-- | DLT-005: Delta validity notAfter must not precede base certificate
-- Reference: IWG Profile §2.2.6.10, line 640 / §3.3.6 line 823
-- "The validity period's 'Not After' date SHOULD NOT precede that of the base certificate."
-- Note: Requires base certificate for comparison
checkValidityMatchesBase :: ComplianceCheck
checkValidityMatchesBase = checkValidityMatchesBaseWithMode OperationalCompatibility

checkValidityMatchesBaseWithMode :: ComplianceMode -> ComplianceCheck
checkValidityMatchesBaseWithMode mode cert refDB = do
  let cid = CheckId Delta 5
      reqLevel = case mode of
        StrictV11 -> Must
        OperationalCompatibility -> ShouldNot
      ref = withRequirement reqLevel (lookupRef cid refDB)
      desc = "Delta validity notAfter must not precede base certificate"
      certType = detectCertificateType cert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert -> mkSkip cid desc ref
      "Requires base certificate for comparison (not provided)"

-- | DLT-006: AttributeStatus values must be 0-2
-- Reference: IWG Profile §3.1.6, line 1006
-- "AttributeStatus ::= ENUMERATED { added(0), modified(1), removed(2) }"
checkAttributeStatusValues :: ComplianceCheck
checkAttributeStatusValues cert refDB = do
  let cid = CheckId Delta 6
      ref = lookupRef cid refDB
      desc = "AttributeStatus values must be 0-2"
      certType = detectCertificateType cert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert ->
      case getDeltaConfiguration cert of
        Left err -> mkFail cid desc ref err
        Right Nothing -> mkSkip cid desc ref "No platformConfiguration present"
        Right (Just cfg) ->
          let present = [s | ParsedComponent { pcStatus = Just s } <- ppcComponents cfg]
                     ++ [s | ParsedProperty { ppStatus = Just s } <- ppcProperties cfg]
              invalid = filter (\s -> s < 0 || s > 2) present
          in if null present
               then mkSkip cid desc ref "No status enumerators present"
               else if null invalid
                 then mkPass cid desc ref
                 else mkFail cid desc ref $
                   "Invalid status values found: " <> T.pack (show invalid)

-- | DLT-007: status field must only be used in Delta certificates
-- Reference: IWG Profile §3.1.6, line 928
-- "The status field contained within the componentIdentifier field MUST be
-- used only in Delta Platform Certificates."
checkStatusFieldDeltaOnly :: ComplianceCheck
checkStatusFieldDeltaOnly cert refDB = do
  let cid = CheckId Delta 7
      ref = lookupRef cid refDB
      desc = "status field must only be used in Delta certificates"
      certType = detectCertificateType cert

  case certType of
    DeltaPlatformCert -> mkPass cid desc ref
    BasePlatformCert ->
      case getDeltaConfiguration cert of
        Left err -> mkFail cid desc ref err
        Right Nothing -> mkPass cid desc ref
        Right (Just cfg) ->
          let hasStatus =
                any (\c -> pcStatus c /= Nothing) (ppcComponents cfg) ||
                any (\p -> ppStatus p /= Nothing) (ppcProperties cfg)
          in if hasStatus
               then mkFail cid desc ref "Base certificate MUST NOT include status fields"
               else mkPass cid desc ref

-- | DLT-008: Components in Delta must include status enumerator
-- Reference: IWG Profile §3.1.6, line 938
-- "the status enumerator MUST be included to indicate whether the field
-- was added, modified, or removed from the base certificate."
checkComponentsHaveStatus :: ComplianceCheck
checkComponentsHaveStatus cert refDB = do
  let cid = CheckId Delta 8
      ref = lookupRef cid refDB
      desc = "Components in Delta must include status enumerator"
      certType = detectCertificateType cert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert ->
      case getDeltaConfiguration cert of
        Left err -> mkFail cid desc ref err
        Right Nothing -> mkSkip cid desc ref "No platformConfiguration present"
        Right (Just cfg) ->
          if null (ppcComponents cfg) && null (ppcProperties cfg)
            then mkSkip cid desc ref "No components or properties in platformConfiguration"
            else
              let compMissing = [c | c <- ppcComponents cfg, pcStatus c == Nothing]
                  propMissing = [p | p <- ppcProperties cfg, ppStatus p == Nothing]
              in if null compMissing && null propMissing
                   then mkPass cid desc ref
                   else mkFail cid desc ref "Components/properties missing status enumerator"

-- | DLT-009: platformManufacturerStr must match base certificate
-- Reference: IWG Profile §2.2.6.4, line 611
-- "This field MUST equal that of the base Platform Certificate"
-- Note: Requires base certificate for comparison
checkManufacturerMatchesBase :: ComplianceCheck
checkManufacturerMatchesBase cert refDB = do
  let cid = CheckId Delta 9
      ref = lookupRef cid refDB
      desc = "platformManufacturerStr must match base certificate"
      certType = detectCertificateType cert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert -> mkSkip cid desc ref
      "Requires base certificate for comparison (not provided)"

-- | DLT-010: platformModel must match base certificate
-- Reference: IWG Profile §2.2.6.6, line 625
-- "This field MUST equal that of the base Platform Certificate"
-- Note: Requires base certificate for comparison
checkModelMatchesBase :: ComplianceCheck
checkModelMatchesBase cert refDB = do
  let cid = CheckId Delta 10
      ref = lookupRef cid refDB
      desc = "platformModel must match base certificate"
      certType = detectCertificateType cert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert -> mkSkip cid desc ref
      "Requires base certificate for comparison (not provided)"

-- | DLT-011: platformVersion must match base certificate
-- Reference: IWG Profile §2.2.6.7, line 629
-- "This field MUST equal that of the base Platform Certificate"
-- Note: Requires base certificate for comparison
checkVersionMatchesBase :: ComplianceCheck
checkVersionMatchesBase cert refDB = do
  let cid = CheckId Delta 11
      ref = lookupRef cid refDB
      desc = "platformVersion must match base certificate"
      certType = detectCertificateType cert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert -> mkSkip cid desc ref
      "Requires base certificate for comparison (not provided)"

-- | DLT-012: platformSerial must match base certificate
-- Reference: IWG Profile §2.2.6.12, line 646
-- "This field MUST equal that of the base Platform Certificate"
-- Note: Requires base certificate for comparison
checkSerialMatchesBase :: ComplianceCheck
checkSerialMatchesBase cert refDB = do
  let cid = CheckId Delta 12
      ref = lookupRef cid refDB
      desc = "platformSerial/platformManufacturerId must match base certificate"
      certType = detectCertificateType cert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert -> mkSkip cid desc ref
      "Requires base certificate for comparison (not provided)"

-- ============================================================================
-- Base Certificate Comparison Checks
-- These functions perform actual comparisons with a provided base certificate
-- ============================================================================

-- | DLT-004 with base certificate: Holder must reference base certificate
-- For Delta certificates, the holder's BaseCertificateID should contain
-- the issuer and serial number of the base certificate (or previous delta).
checkHolderRefsBaseWithCert :: SignedPlatformCertificate  -- ^ Delta certificate
                            -> SignedPlatformCertificate  -- ^ Base certificate
                            -> ReferenceDB
                            -> IO CheckResult
checkHolderRefsBaseWithCert deltaCert baseCert refDB = do
  let cid = CheckId Delta 4
      ref = lookupRef cid refDB
      desc = "Holder must reference base certificate"
      certType = detectCertificateType deltaCert
      deltaHolder = pciHolder $ getPlatformCertificate deltaCert
      baseIssuer = pciIssuer $ getPlatformCertificate baseCert
      baseSerial = pciSerialNumber $ getPlatformCertificate baseCert
      baseIssuerDNs = extractIssuerDNs baseIssuer

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert ->
      -- The holder in Delta should contain a BaseCertificateID that references
      -- the base certificate's issuer and serial number
      case holderBaseCertificateID deltaHolder of
        Nothing -> mkFail cid desc ref
          "Delta certificate holder does not contain BaseCertificateID"
        Just issuerSerial ->
          -- Check if the issuer serial references the base certificate
          -- The issuer field contains AltNames which should include the base issuer DN
          -- The serial should match the base certificate's serial
          if serial issuerSerial /= baseSerial
            then mkFail cid desc ref $
              "Delta holder serial (" <> T.pack (show (serial issuerSerial)) <>
              ") does not match base certificate serial (" <> T.pack (show baseSerial) <> ")"
            else
              let holderDns = extractDNsFromGeneralNames (issuer issuerSerial)
              in if null baseIssuerDNs
                   then mkFail cid desc ref "Base issuer distinguished name not available for comparison"
                   else if any (`elem` holderDns) baseIssuerDNs
                          then mkPass cid desc ref
                          else mkFail cid desc ref "Delta holder issuer does not match base issuer DN"

-- | DLT-005 with base certificate: Delta validity notAfter must not precede base
checkValidityMatchesBaseWithCert :: SignedPlatformCertificate
                                 -> SignedPlatformCertificate
                                 -> ReferenceDB
                                 -> IO CheckResult
checkValidityMatchesBaseWithCert = checkValidityMatchesBaseWithCertWithMode OperationalCompatibility

checkValidityMatchesBaseWithCertWithMode :: ComplianceMode
                                         -> SignedPlatformCertificate
                                         -> SignedPlatformCertificate
                                         -> ReferenceDB
                                         -> IO CheckResult
checkValidityMatchesBaseWithCertWithMode mode deltaCert baseCert refDB = do
  let cid = CheckId Delta 5
      reqLevel = case mode of
        StrictV11 -> Must
        OperationalCompatibility -> ShouldNot
      ref = withRequirement reqLevel (lookupRef cid refDB)
      desc = "Delta validity notAfter must not precede base certificate"
      certType = detectCertificateType deltaCert
      deltaValidity = pciValidity $ getPlatformCertificate deltaCert
      baseValidity = pciValidity $ getPlatformCertificate baseCert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert ->
      let deltaNotAfter = acNotAfter deltaValidity
          baseNotAfter = acNotAfter baseValidity
      in case mode of
           StrictV11 ->
             if deltaNotAfter == baseNotAfter
               then mkPass cid desc ref
               else mkFail cid desc ref $
                 "StrictV11 requires delta notAfter to match base; delta=" <>
                 T.pack (show deltaNotAfter) <> ", base=" <> T.pack (show baseNotAfter)
           OperationalCompatibility ->
             if deltaNotAfter < baseNotAfter
               then mkFail cid desc ref $
                 "Delta notAfter (" <> T.pack (show deltaNotAfter) <>
                 ") precedes base notAfter (" <> T.pack (show baseNotAfter) <> ")"
               else mkPass cid desc ref

-- | DLT-009 with base certificate: platformManufacturerStr must match
checkManufacturerMatchesBaseWithCert :: SignedPlatformCertificate
                                     -> SignedPlatformCertificate
                                     -> ReferenceDB
                                     -> IO CheckResult
checkManufacturerMatchesBaseWithCert deltaCert baseCert refDB = do
  let cid = CheckId Delta 9
      ref = lookupRef cid refDB
      desc = "platformManufacturerStr must match base certificate"
      certType = detectCertificateType deltaCert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert -> do
      case (getRequiredAttrUtf8 deltaCert [tcg_paa_platformManufacturer, tcg_at_platformManufacturer] "platformManufacturerStr",
            getRequiredAttrUtf8 baseCert [tcg_paa_platformManufacturer, tcg_at_platformManufacturer] "platformManufacturerStr") of
        (Left err, _) -> mkFail cid desc ref err
        (_, Left err) -> mkFail cid desc ref ("Base certificate: " <> err)
        (Right dVal, Right bVal) ->
          if dVal == bVal
            then mkPass cid desc ref
            else mkFail cid desc ref "Delta manufacturer does not match base manufacturer"

-- | DLT-010 with base certificate: platformModel must match
checkModelMatchesBaseWithCert :: SignedPlatformCertificate
                              -> SignedPlatformCertificate
                              -> ReferenceDB
                              -> IO CheckResult
checkModelMatchesBaseWithCert deltaCert baseCert refDB = do
  let cid = CheckId Delta 10
      ref = lookupRef cid refDB
      desc = "platformModel must match base certificate"
      certType = detectCertificateType deltaCert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert -> do
      case (getRequiredAttrUtf8 deltaCert [tcg_paa_platformModel, tcg_at_platformModel] "platformModel",
            getRequiredAttrUtf8 baseCert [tcg_paa_platformModel, tcg_at_platformModel] "platformModel") of
        (Left err, _) -> mkFail cid desc ref err
        (_, Left err) -> mkFail cid desc ref ("Base certificate: " <> err)
        (Right dVal, Right bVal) ->
          if dVal == bVal
            then mkPass cid desc ref
            else mkFail cid desc ref "Delta model does not match base model"

-- | DLT-011 with base certificate: platformVersion must match
checkVersionMatchesBaseWithCert :: SignedPlatformCertificate
                                -> SignedPlatformCertificate
                                -> ReferenceDB
                                -> IO CheckResult
checkVersionMatchesBaseWithCert deltaCert baseCert refDB = do
  let cid = CheckId Delta 11
      ref = lookupRef cid refDB
      desc = "platformVersion must match base certificate"
      certType = detectCertificateType deltaCert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert -> do
      case (getRequiredAttrUtf8 deltaCert [tcg_paa_platformVersion, tcg_at_platformVersion] "platformVersion",
            getRequiredAttrUtf8 baseCert [tcg_paa_platformVersion, tcg_at_platformVersion] "platformVersion") of
        (Left err, _) -> mkFail cid desc ref err
        (_, Left err) -> mkFail cid desc ref ("Base certificate: " <> err)
        (Right dVal, Right bVal) ->
          if dVal == bVal
            then mkPass cid desc ref
            else mkFail cid desc ref "Delta version does not match base version"

-- | DLT-012 with base certificate: platformSerial must match
checkSerialMatchesBaseWithCert :: SignedPlatformCertificate
                               -> SignedPlatformCertificate
                               -> ReferenceDB
                               -> IO CheckResult
checkSerialMatchesBaseWithCert deltaCert baseCert refDB = do
  let cid = CheckId Delta 12
      ref = lookupRef cid refDB
      desc = "platformSerial/platformManufacturerId must match base certificate"
      certType = detectCertificateType deltaCert

  case certType of
    BasePlatformCert -> mkSkip cid desc ref "Not a Delta certificate"
    DeltaPlatformCert -> do
      let serialDelta = getOptionalAttrUtf8 deltaCert [tcg_paa_platformSerial, tcg_at_platformSerial] "platformSerial"
          serialBase  = getOptionalAttrUtf8 baseCert [tcg_paa_platformSerial, tcg_at_platformSerial] "platformSerial"
          mfgIdDelta = getOptionalManufacturerId deltaCert
          mfgIdBase  = getOptionalManufacturerId baseCert
      case (serialDelta, serialBase, mfgIdDelta, mfgIdBase) of
        (Left err, _, _, _) -> mkFail cid desc ref err
        (_, Left err, _, _) -> mkFail cid desc ref ("Base certificate: " <> err)
        (_, _, Left err, _) -> mkFail cid desc ref err
        (_, _, _, Left err) -> mkFail cid desc ref ("Base certificate: " <> err)
        (Right dSerial, Right bSerial, Right dMfg, Right bMfg) -> do
          let serialCheck = case dSerial of
                Nothing -> Nothing
                Just dVal -> case bSerial of
                  Nothing -> Just (Left "Base certificate missing platformSerial")
                  Just bVal ->
                    if dVal == bVal
                      then Just (Right ())
                      else Just (Left "Delta platformSerial does not match base")
              mfgCheck = case dMfg of
                Nothing -> Nothing
                Just dOid -> case bMfg of
                  Nothing -> Just (Left "Base certificate missing platformManufacturerId")
                  Just bOid ->
                    if dOid == bOid
                      then Just (Right ())
                      else Just (Left "Delta platformManufacturerId does not match base")
          case (serialCheck, mfgCheck) of
            (Nothing, Nothing) ->
              mkSkip cid desc ref "platformSerial/platformManufacturerId not present in Delta"
            (Just (Left err), _) -> mkFail cid desc ref err
            (_, Just (Left err)) -> mkFail cid desc ref err
            _ -> mkPass cid desc ref

getOptionalAttrUtf8 :: SignedPlatformCertificate -> [OID] -> T.Text -> Either T.Text (Maybe B.ByteString)
getOptionalAttrUtf8 cert oids label =
  case lookupNameAttrValues cert oids of
    Left err -> Left err
    Right Nothing -> Right Nothing
    Right (Just []) -> Left (label <> " attribute is empty")
    Right (Just (val:_)) -> Just <$> requireUtf8String label val

getOptionalManufacturerId :: SignedPlatformCertificate -> Either T.Text (Maybe OID)
getOptionalManufacturerId cert =
  case lookupNameAttrValues cert [tcg_paa_platformManufacturerId] of
    Left err -> Left err
    Right Nothing -> Right Nothing
    Right (Just []) -> Left "platformManufacturerId attribute is empty"
    Right (Just values) ->
      case values of
        (OID oid : _) -> Right (Just oid)
        _ ->
          case stripSequence values of
            Left err -> Left err
            Right content ->
              case content of
                (OID oid : _) -> Right (Just oid)
                _ -> Left "platformManufacturerId: expected OBJECT IDENTIFIER"
