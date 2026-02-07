{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Chain
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Certificate chain validation checks (CHN-001 to CHN-005).
--
-- Validates chain-related extensions and bindings per IWG Profile.

module Data.X509.TCG.Compliance.Chain
  ( -- * All Chain Checks
    runChainChecks

    -- * Individual Checks
  , checkAuthorityKeyId   -- CHN-001
  , checkAuthorityInfoAcc -- CHN-002
  , checkCrlDistribution  -- CHN-003
  , checkEkCertBinding    -- CHN-004
  , checkTargetingInfo    -- CHN-005
  ) where

import Data.List (find)
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.ByteString as B

import Data.X509 (Extensions(..), ExtensionRaw(..))
import Data.X509.AttCert (Holder(..))
import Data.ASN1.Types (ASN1(..), ASN1ConstructionType(..), ASN1Class(..))
import Data.ASN1.Types.String (ASN1CharacterString(..), ASN1StringEncoding(..))

import Data.X509.TCG.Platform (SignedPlatformCertificate, getPlatformCertificate)
import Data.X509.TCG.Platform (PlatformCertificateInfo(..))

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.ASN1
  ( decodeASN1WithLimit
  , stripSequenceOrContent
  , parseTargetingInformation
  , ParsedTargetingInfo(..)
  )
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Internal (lookupRef, ComplianceCheck)

-- | Run all chain compliance checks
runChainChecks :: SignedPlatformCertificate -> ReferenceDB -> IO [CheckResult]
runChainChecks cert refDB = sequence
  [ checkAuthorityKeyId cert refDB
  , checkAuthorityInfoAcc cert refDB
  , checkCrlDistribution cert refDB
  , checkEkCertBinding cert refDB
  , checkTargetingInfo cert refDB
  ]

-- | CHN-001: Authority Key Identifier extension
-- Reference: IWG Profile §3.2.11, line 1249
-- "Authority Key Identifier extension" - MUST NOT be critical
checkAuthorityKeyId :: ComplianceCheck
checkAuthorityKeyId cert refDB = do
  let cid = CheckId Chain 1
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      Extensions mexts = pciExtensions pci
  case mexts of
    Nothing ->
      mkSkip cid "Authority Key Identifier" ref "No extensions present"
    Just exts ->
      -- Authority Key Identifier OID: 2.5.29.35
      case find (\e -> extRawOID e == [2,5,29,35]) exts of
        Just ext ->
          if extRawCritical ext
            then mkFail cid "Authority Key Identifier" ref
                   "Authority Key Identifier MUST NOT be critical"
            else do
              let ExtensionRaw _ _ raw = ext
              case decodeASN1WithLimit (256 * 1024) raw of
                Left err -> mkFail cid "Authority Key Identifier" ref err
                Right asn1 ->
                  case extractAkiKeyIdentifier asn1 of
                    Left err -> mkFail cid "Authority Key Identifier" ref err
                    Right Nothing -> mkSkip cid "Authority Key Identifier" ref
                      "AKI keyIdentifier omitted (allowed when issuer SKI is unavailable)"
                    Right (Just bs) ->
                      if B.null bs
                        then mkFail cid "Authority Key Identifier" ref
                          "Authority Key Identifier keyIdentifier must be non-empty"
                        else mkPass cid "Authority Key Identifier present and valid" ref
        Nothing ->
          mkSkip cid "Authority Key Identifier" ref
            "Authority Key Identifier extension not present (recommended per IWG Profile §3.2.11)"

-- | CHN-002: Authority Info Access extension
-- Reference: IWG Profile §3.2.12, line 1253
-- "Authority Info Access extension" - MUST NOT be critical if present
checkAuthorityInfoAcc :: ComplianceCheck
checkAuthorityInfoAcc cert refDB = do
  let cid = CheckId Chain 2
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      Extensions mexts = pciExtensions pci
      uriMax = 1024
  case mexts of
    Nothing ->
      mkSkip cid "Authority Info Access" ref "No extensions present"
    Just exts ->
      -- Authority Info Access OID: 1.3.6.1.5.5.7.1.1
      case find (\e -> extRawOID e == [1,3,6,1,5,5,7,1,1]) exts of
        Just ext ->
          if extRawCritical ext
            then mkFail cid "Authority Info Access" ref
                   "Authority Info Access MUST NOT be critical"
            else do
              let ExtensionRaw _ _ raw = ext
              case decodeASN1WithLimit (256 * 1024) raw of
                Left err -> mkFail cid "Authority Info Access" ref err
                Right asn1 ->
                  case parseAuthorityInfoAccess asn1 of
                    Left err -> mkFail cid "Authority Info Access" ref err
                    Right uris ->
                      let bad = filter (not . validUri uriMax) uris
                          hasOcsp = any snd uris
                      in if null uris
                           then mkFail cid "Authority Info Access" ref "No accessLocation URI found"
                           else if not (null bad)
                             then mkFail cid "Authority Info Access" ref "Invalid AIA accessLocation URI"
                             else if hasOcsp
                               then mkPass cid "Authority Info Access present and valid" ref
                               else mkSkip cid "Authority Info Access" ref
                                      "No id-ad-ocsp accessMethod found (SHOULD)"
        Nothing ->
          mkSkip cid "Authority Info Access" ref
            "Authority Info Access extension not present (optional)"

-- | CHN-003: CRL Distribution Points extension
-- Reference: IWG Profile §3.2.13, line 1262
-- "CRL Distribution Points extension" - MUST NOT be critical if present
-- Note: Base/Delta = SHOULD (if present, URI should be provided)
checkCrlDistribution :: ComplianceCheck
checkCrlDistribution cert refDB = do
  let cid = CheckId Chain 3
      ref = lookupRef cid refDB
      desc = "CRL Distribution Points"
      pci = getPlatformCertificate cert
      Extensions mexts = pciExtensions pci
  case mexts of
    Nothing ->
      mkSkip cid desc ref "No extensions present"
    Just exts ->
      -- CRL Distribution Points OID: 2.5.29.31
      case find (\e -> extRawOID e == [2,5,29,31]) exts of
        Just ext ->
          if extRawCritical ext
            then mkFail cid desc ref
                   "CRL Distribution Points MUST NOT be critical"
            else do
              let ExtensionRaw _ _ raw = ext
              case decodeASN1WithLimit (256 * 1024) raw of
                Left err -> mkFail cid desc ref err
                Right asn1 ->
                  case extractCrlUris asn1 of
                    Left err -> mkFail cid desc ref err
                    Right uris ->
                      let bad = filter (not . validUriBytes 1024) uris
                      in if null uris
                           then mkFail cid desc ref "No CRL distributionPoint URI found"
                           else if not (null bad)
                             then mkFail cid desc ref "Invalid CRL distributionPoint URI"
                             else evaluateOcspPreference cid ref desc exts
        Nothing ->
          mkSkip cid desc ref "CRL Distribution Points extension not present (optional)"

evaluateOcspPreference :: CheckId -> SpecReference -> Text -> [ExtensionRaw] -> IO CheckResult
evaluateOcspPreference cid ref desc exts =
  case find (\e -> extRawOID e == [1,3,6,1,5,5,7,1,1]) exts of
    Nothing ->
      mkPass cid "CRL Distribution Points present and valid" ref
    Just aiaExt -> do
      let ExtensionRaw _ _ aiaRaw = aiaExt
      case decodeASN1WithLimit (256 * 1024) aiaRaw of
        Left _ ->
          mkPassWithDetails cid "CRL Distribution Points present and valid" ref
            "AIA present but OCSP-preference advisory could not be evaluated"
        Right aiaAsn1 ->
          case parseAuthorityInfoAccess aiaAsn1 of
            Left _ ->
              mkPassWithDetails cid "CRL Distribution Points present and valid" ref
                "AIA present but OCSP-preference advisory could not be evaluated"
            Right access ->
              if any snd access
                then mkPassWithDetails cid "CRL Distribution Points present and valid" ref
                       "AIA includes OCSP; OCSP preference can be applied when both OCSP and CRL are available"
                else mkSkip cid desc ref
                       "CRL DP is valid, but AIA lacks OCSP. Prefer OCSP when both AIA and CRL are provided (SHOULD)."

-- | CHN-004: EK Certificate binding
-- Reference: IWG Profile §2.1.5.2, line 375
-- "SHALL be an unambiguous indication of the EK Certificates"
-- Note: Base = MUST, Delta = MAY (per IWG Table 1 & Table 2)
checkEkCertBinding :: ComplianceCheck
checkEkCertBinding cert refDB = do
  let cid = CheckId Chain 4
      ref = lookupRef cid refDB
      desc = "EK Certificate binding"
      pci = getPlatformCertificate cert
      holder = pciHolder pci
      certType = detectCertificateType cert
      reqLevel = getRequirementLevel cid certType
  -- Check that holder references an EK certificate via baseCertificateID
  if isJust (holderBaseCertificateID holder)
    then mkPass cid "EK Certificate binding (baseCertificateID present)" ref
    else
      -- Not present - handle based on requirement level
      case reqLevel of
        Must -> mkFail cid desc ref
                  "Holder MUST reference EK Certificate via baseCertificateID (MUST for Base)"
        _    -> mkSkip cid desc ref
                  "No baseCertificateID in holder (MAY for Delta)"

-- | CHN-005: Targeting Information extension
-- Reference: IWG Profile §3.2.9, line 1206
-- "Additional required TPM EK certificates" - Optional but must be critical
checkTargetingInfo :: ComplianceCheck
checkTargetingInfo cert refDB = do
  let cid = CheckId Chain 5
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      Extensions mexts = pciExtensions pci
  case mexts of
    Nothing ->
      mkSkip cid "Targeting Information" ref "No extensions present"
    Just exts ->
      -- AC Targeting extension OID (RFC 5755): 2.5.29.55
      case find (\e -> extRawOID e == [2,5,29,55]) exts of
        Just ext ->
          if extRawCritical ext
            then do
              let ExtensionRaw _ _ raw = ext
              case decodeASN1WithLimit (256 * 1024) raw of
                Left err -> mkFail cid "Targeting Information" ref err
                Right asn1 ->
                  case parseTargetingInformation asn1 of
                    Left err -> mkFail cid "Targeting Information" ref err
                    Right info ->
                      if not (ptiHasTargetName info)
                        then mkFail cid "Targeting Information" ref
                          "TargetingInformation must include targetName"
                        else if not (ptiHasSerialNumberRdn info)
                          then mkFail cid "Targeting Information" ref
                            "targetName must include EK serialNumber RDN"
                          else if ptiHasNonTargetName info
                            then mkFail cid "Targeting Information" ref
                              "TargetingInformation contains non-targetName entries"
                            else mkPass cid "Targeting Information extension present and valid" ref
            else mkFail cid "Targeting Information" ref
                   "Targeting Information MUST be critical if present"
        Nothing ->
          mkSkip cid "Targeting Information" ref
            "Targeting Information extension not present (optional)"

-- ============================================================================
-- Internal parsing helpers
-- ============================================================================

type AccessUri = (B.ByteString, Bool) -- (uri, isOcsp)

-- | Extract keyIdentifier from AuthorityKeyIdentifier extension
extractAkiKeyIdentifier :: [ASN1] -> Either Text (Maybe B.ByteString)
extractAkiKeyIdentifier asn1 = do
  content <- stripSequenceOrContent asn1
  go content
  where
    go [] = Right Nothing
    go (Other Context 0 bs : _) = Right (Just bs)
    go (Start (Container Context 0) : rest) = do
      (ctx, _remaining) <- collectContainer (Container Context 0) rest
      case [bs | OctetString bs <- ctx] of
        (bs:_) -> Right (Just bs)
        [] -> Left "AuthorityKeyIdentifier: keyIdentifier missing OCTET STRING"
    go (_:rest) = go rest

parseAuthorityInfoAccess :: [ASN1] -> Either Text [AccessUri]
parseAuthorityInfoAccess asn1 = do
  content <- stripSequenceOrContent asn1
  parseAccessDescriptions content
  where
    parseAccessDescriptions [] = Right []
    parseAccessDescriptions (Start Sequence : rest) = do
      (body, remaining) <- collectContainer Sequence rest
      access <- parseAccessDescription body
      others <- parseAccessDescriptions remaining
      return (access : others)
    parseAccessDescriptions _ = Left "AuthorityInfoAccess: expected SEQUENCE OF AccessDescription"

    parseAccessDescription body =
      case body of
        (OID method : rest) -> do
          uri <- parseGeneralNameUri rest
          let isOcsp = method == [1,3,6,1,5,5,7,48,1] -- id-ad-ocsp
          return (uri, isOcsp)
        _ -> Left "AuthorityInfoAccess: invalid AccessDescription"

parseGeneralNameUri :: [ASN1] -> Either Text B.ByteString
parseGeneralNameUri [Other Context 6 bs] =
  if B.all (< 0x80) bs then Right bs else Left "GeneralName URI: invalid IA5String"
parseGeneralNameUri [Start (Container Context 6) , ASN1String (ASN1CharacterString IA5 bs) , End (Container Context 6)] =
  if B.all (< 0x80) bs then Right bs else Left "GeneralName URI: invalid IA5String"
parseGeneralNameUri _ = Left "GeneralName: expected uniformResourceIdentifier"

extractCrlUris :: [ASN1] -> Either Text [B.ByteString]
extractCrlUris asn1 = do
  content <- stripSequenceOrContent asn1
  collectContextPrimitive 6 content

validUri :: Int -> AccessUri -> Bool
validUri maxLen (uri, _) = validUriBytes maxLen uri

validUriBytes :: Int -> B.ByteString -> Bool
validUriBytes maxLen uri = B.length uri >= 1 && B.length uri <= maxLen && B.all (< 0x80) uri

collectContainer :: ASN1ConstructionType -> [ASN1] -> Either Text ([ASN1], [ASN1])
collectContainer container = go (1 :: Int) []
  where
    go :: Int -> [ASN1] -> [ASN1] -> Either Text ([ASN1], [ASN1])
    go _ _ [] = Left "ASN.1: unterminated container"
    go depth acc (x:xs)
      | x == Start container = go (depth + 1) (x:acc) xs
      | x == End container =
          if depth == 1
            then Right (reverse acc, xs)
            else go (depth - 1) (x:acc) xs
      | otherwise = go depth (x:acc) xs

collectContextPrimitive :: Int -> [ASN1] -> Either Text [B.ByteString]
collectContextPrimitive tag xs = fmap reverse (go xs [])
  where
    go [] acc = Right acc
    go (Start c : rest) acc = do
      (content, remaining) <- collectContainer c rest
      acc' <- go content acc
      go remaining acc'
    go (Other Context t bs : rest) acc
      | t == tag = go rest (bs:acc)
    go (_:rest) acc = go rest acc
