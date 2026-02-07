{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Extension
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Extension validation checks (EXT-001 to EXT-005).
--
-- Validates extension field requirements per IWG Profile.

module Data.X509.TCG.Compliance.Extension
  ( -- * All Extension Checks
    runExtensionChecks

    -- * Individual Checks
  , checkCertificatePolicies   -- EXT-001
  , checkSubjectAltNames       -- EXT-002
  , checkUserNotice            -- EXT-003
  , checkIssuerUniqueId        -- EXT-004
  , checkTargetingInfoCritical -- EXT-005
  ) where

import Data.List (find)
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as B
import qualified Data.Map.Strict as Map
import Data.Word (Word8)

import Data.X509 (Extensions(..), ExtensionRaw(..))
import Data.ASN1.Types (ASN1(..))
import Data.ASN1.Types.String (ASN1StringEncoding(..))

import Data.X509.TCG.Platform (SignedPlatformCertificate, getPlatformCertificate)
import Data.X509.TCG.Platform (PlatformCertificateInfo(..))
import Data.X509.TCG.OID
  ( tcg_paa_platformManufacturer
  , tcg_paa_platformModel
  , tcg_paa_platformVersion
  , tcg_at_platformManufacturer
  , tcg_at_platformModel
  , tcg_at_platformVersion
  )

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.ASN1
  ( decodeASN1WithLimit
  , parseCertificatePolicies
  , ParsedCertificatePolicies(..)
  , extractSANAttributes
  , asn1StringValue
  )
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Internal (lookupRef, ComplianceCheck)

-- | Run all extension compliance checks
runExtensionChecks :: SignedPlatformCertificate -> ReferenceDB -> IO [CheckResult]
runExtensionChecks cert refDB = sequence
  [ checkCertificatePolicies cert refDB
  , checkSubjectAltNames cert refDB
  , checkUserNotice cert refDB
  , checkIssuerUniqueId cert refDB
  , checkTargetingInfoCritical cert refDB
  ]

-- | EXT-001: Certificate Policies extension
-- Reference: IWG Profile §3.2.7, line 1186
-- "CertificatePolicies extension MUST be included"
checkCertificatePolicies :: ComplianceCheck
checkCertificatePolicies cert refDB = do
  let cid = CheckId Extension 1
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      Extensions mexts = pciExtensions pci
      uriMax = 1024
  case mexts of
    Nothing -> mkFail cid "Certificate Policies extension" ref
                 "No extensions present"
    Just exts ->
      -- Certificate Policies OID: 2.5.29.32
      case find (\e -> extRawOID e == [2,5,29,32]) exts of
        Just ext ->
          if extRawCritical ext
            then mkFail cid "Certificate Policies extension" ref
                   "Certificate Policies MUST NOT be critical"
            else do
              let ExtensionRaw _ _ raw = ext
              case decodeASN1WithLimit (256 * 1024) raw of
                Left err -> mkFail cid "Certificate Policies extension" ref err
                Right asn1 ->
                  case parseCertificatePolicies asn1 of
                    Left err -> mkFail cid "Certificate Policies extension" ref err
                    Right pols ->
                      if null (pcpPolicyIds pols)
                        then mkFail cid "Certificate Policies extension" ref
                          "CertificatePolicies must include at least one policyIdentifier"
                        else if null (pcpCpsUris pols)
                          then mkFail cid "Certificate Policies extension" ref
                            "cPSuri policy qualifier with HTTP URL is required (IWG §3.2.7)"
                          else
                            let badLen = filter (\u -> B.length u < 1 || B.length u > uriMax) (pcpCpsUris pols)
                                isHttpScheme u =
                                  let lowerUri = B.map toLowerAscii u
                                  in "http://" `B.isPrefixOf` lowerUri || "https://" `B.isPrefixOf` lowerUri
                                badScheme = filter (not . isHttpScheme) (pcpCpsUris pols)
                            in if not (null badLen)
                                 then mkFail cid "Certificate Policies extension" ref
                                       "cPSuri length must be 1..URIMAX"
                                 else if not (null badScheme)
                                   then mkFail cid "Certificate Policies extension" ref
                                          "cPSuri must use HTTP/HTTPS scheme per IWG §3.2.7"
                                   else mkPass cid "Certificate Policies extension present and valid" ref
        Nothing ->
          mkFail cid "Certificate Policies extension" ref
            "Certificate Policies extension not found"

-- | EXT-002: Subject Alternative Names extension
-- Reference: IWG Profile §3.2.8, line 1197
-- "Subject Alternative Names extension MUST be included"
checkSubjectAltNames :: ComplianceCheck
checkSubjectAltNames cert refDB = do
  let cid = CheckId Extension 2
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      Extensions mexts = pciExtensions pci
      strMax = 255  -- STRMAX per IWG Profile §2.2
  case mexts of
    Nothing -> mkFail cid "Subject Alternative Names extension" ref
                 "No extensions present"
    Just exts ->
      -- Subject Alternative Name OID: 2.5.29.17
      case find (\e -> extRawOID e == [2,5,29,17]) exts of
        Just ext ->
          if extRawCritical ext
            then mkFail cid "Subject Alternative Names extension" ref
                   "Subject Alternative Names MUST NOT be critical"
            else do
              case extractSANAttributes (Extensions (Just exts)) of
                Left err -> mkFail cid "Subject Alternative Names extension" ref err
                Right Nothing -> mkFail cid "Subject Alternative Names extension" ref
                  "Subject Alternative Names extension not present"
                Right (Just sanMap) ->
                  let required =
                        [ ("platformManufacturerStr", [tcg_paa_platformManufacturer, tcg_at_platformManufacturer])
                        , ("platformModel", [tcg_paa_platformModel, tcg_at_platformModel])
                        , ("platformVersion", [tcg_paa_platformVersion, tcg_at_platformVersion])
                        ]
                      lookupFirst oids =
                        let firstJust [] = Nothing
                            firstJust (x:xs) = case x of
                              Just _ -> x
                              Nothing -> firstJust xs
                        in firstJust [ case Map.lookup oid sanMap of
                                         Just (v:_) -> Just v
                                         _ -> Nothing
                                     | oid <- oids
                                     ]
                      missing = [label | (label, oids) <- required, lookupFirst oids == Nothing]
                      invalid = [label | (label, oids) <- required
                                       , Just (val:_) <- [lookupFirst oids]
                                       , not (isValidUtf8Value val strMax)
                                       ]
                  in if not (null missing)
                       then mkFail cid "Subject Alternative Names extension" ref $
                              "Missing required directoryName attributes: " <> T.intercalate ", " missing
                       else if not (null invalid)
                         then mkFail cid "Subject Alternative Names extension" ref $
                                "Invalid directoryName attribute encoding for: " <> T.intercalate ", " invalid
                         else mkPass cid "Subject Alternative Names extension present and valid" ref
        Nothing ->
          mkFail cid "Subject Alternative Names extension" ref
            "Subject Alternative Names extension not found"

-- | EXT-003: userNotice policy qualifier
-- Reference: IWG Profile §3.2.7, line 1190
-- "userNotice MUST be 'TCG Trusted Platform Endorsement'"
checkUserNotice :: ComplianceCheck
checkUserNotice cert refDB = do
  let cid = CheckId Extension 3
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      Extensions mexts = pciExtensions pci
      expectedNotice = "TCG Trusted Platform Endorsement" :: Text
      expectedBytes = TE.encodeUtf8 expectedNotice
  case mexts of
    Nothing -> mkFail cid "userNotice policy qualifier" ref
                 "No extensions present"
    Just exts ->
      -- Certificate Policies OID: 2.5.29.32
      case find (\e -> extRawOID e == [2,5,29,32]) exts of
        Just ext -> do
          let ExtensionRaw _ _ raw = ext
          case decodeASN1WithLimit (256 * 1024) raw of
            Left err -> mkFail cid "userNotice policy qualifier" ref err
            Right asn1 ->
              case parseCertificatePolicies asn1 of
                Left err -> mkFail cid "userNotice policy qualifier" ref err
                Right pols ->
                  if any (matchesNotice expectedNotice expectedBytes) (pcpUserNotices pols)
                    then mkPass cid "userNotice policy qualifier matches expected text" ref
                    else mkFail cid "userNotice policy qualifier" ref
                           "userNotice 'TCG Trusted Platform Endorsement' not found"
        Nothing ->
          mkFail cid "userNotice policy qualifier" ref
            "Certificate Policies extension not found"

matchesNotice :: Text -> B.ByteString -> B.ByteString -> Bool
matchesNotice expectedText expectedBytes bs =
  case TE.decodeUtf8' bs of
    Right t -> t == expectedText
    Left _ -> bs == expectedBytes

-- | EXT-004: Issuer Unique Id MUST be omitted
-- Reference: IWG Profile §3.2.14, line 1267
-- "Issuer Unique Id fields MUST be omitted"
checkIssuerUniqueId :: ComplianceCheck
checkIssuerUniqueId cert refDB = do
  let cid = CheckId Extension 4
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
  if isJust (pciIssuerUniqueID pci)
    then mkFail cid "Issuer Unique Id properly omitted" ref
      "issuerUniqueID MUST be omitted in Platform Certificate"
    else mkPass cid "Issuer Unique Id properly omitted" ref

-- | EXT-005: Targeting Information must be critical if present
-- Reference: IWG Profile §3.2.9, line 1208
-- "if included, assign 'critical' the value of TRUE"
checkTargetingInfoCritical :: ComplianceCheck
checkTargetingInfoCritical cert refDB = do
  let cid = CheckId Extension 5
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      Extensions mexts = pciExtensions pci
  case mexts of
    Nothing ->
      mkSkip cid "Targeting Information critical" ref "No extensions present"
    Just exts ->
      -- AC Targeting extension OID (from RFC 5755): 2.5.29.55
      case find (\e -> extRawOID e == [2,5,29,55]) exts of
        Just ext ->
          if extRawCritical ext
            then mkPass cid "Targeting Information is critical" ref
            else mkFail cid "Targeting Information critical" ref
                   "Targeting Information extension MUST be critical if present"
        Nothing ->
          mkSkip cid "Targeting Information critical" ref
            "Targeting Information extension not present"

isValidUtf8Value :: ASN1 -> Int -> Bool
isValidUtf8Value val maxLen =
  case asn1StringValue val of
    Just (UTF8, bs) -> B.length bs >= 1 && B.length bs <= maxLen
    _ -> False

-- | Convert ASCII byte to lowercase (for scheme comparison)
toLowerAscii :: Word8 -> Word8
toLowerAscii w
  | w >= 65 && w <= 90 = w + 32  -- A-Z -> a-z
  | otherwise = w
