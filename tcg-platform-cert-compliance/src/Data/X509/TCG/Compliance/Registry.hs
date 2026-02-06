{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Registry
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Component class registry validation checks (REG-001 to REG-004).
--
-- Validates component class registry OIDs and structures per
-- TCG Component Class Registry specifications.

module Data.X509.TCG.Compliance.Registry
  ( -- * All Registry Checks
    runRegistryChecks

    -- * Individual Checks
  , checkTcgRegistryOid            -- REG-001 (default mode)
  , checkTcgRegistryOidWithMode    -- REG-001 (mode-aware)
  , checkClassValueStruct          -- REG-002
  , checkTcgRegistryValues         -- REG-003
  , checkRegistryTranslationScope  -- REG-004
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.ByteString as B
import Control.Applicative ((<|>))
import Data.Word (Word8)

import Data.ASN1.Types (OID)
import Data.X509.TCG.Platform (SignedPlatformCertificate, getPlatformCertificate)
import Data.X509.TCG.Platform (PlatformCertificateInfo(..))
import Data.X509.TCG.OID
  ( tcg_at_platformConfiguration
  , tcg_at_platformConfiguration_v2
  , tcg_registry_componentClass_tcg
  , tcg_registry_componentClass_ietf
  , tcg_registry_componentClass_dmtf
  , tcg_registry_componentClass_pcie
  , tcg_registry_componentClass_storage
  )
import Data.X509.TCG.Utils (lookupAttributeByOID)

import Data.X509.TCG.Compliance.ASN1 (ParsedComponent(..), ParsedAddress(..), parsePlatformComponents, formatOID)

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Internal (lookupRef, ComplianceCheck)

-- | Run all registry compliance checks
runRegistryChecks :: SignedPlatformCertificate -> ReferenceDB -> IO [CheckResult]
runRegistryChecks cert refDB = sequence
  [ checkTcgRegistryOidWithMode OperationalCompatibility cert refDB
  , checkClassValueStruct cert refDB
  , checkTcgRegistryValues cert refDB
  , checkRegistryTranslationScope cert refDB
  ]

-- | Known component class registry OIDs
tcgRegistryOID :: OID
tcgRegistryOID = tcg_registry_componentClass_tcg

ietfRegistryOID :: OID
ietfRegistryOID = tcg_registry_componentClass_ietf

dmtfRegistryOID :: OID
dmtfRegistryOID = tcg_registry_componentClass_dmtf

pcieRegistryOID :: OID
pcieRegistryOID = tcg_registry_componentClass_pcie

storageRegistryOID :: OID
storageRegistryOID = tcg_registry_componentClass_storage

-- | REG-001: TCG registry OID validation
-- Default mode wrapper (OperationalCompatibility).
checkTcgRegistryOid :: ComplianceCheck
checkTcgRegistryOid = checkTcgRegistryOidWithMode OperationalCompatibility

-- | REG-001: componentClassRegistry OID validation with compliance mode.
checkTcgRegistryOidWithMode :: ComplianceMode -> ComplianceCheck
checkTcgRegistryOidWithMode mode cert refDB = do
  let cid = CheckId Registry 1
      ref = lookupRef cid refDB
      allowed = allowedRegistryOids mode
  case getPlatformComponents cert of
    Left err -> mkFail cid "componentClassRegistry OID validity" ref err
    Right comps ->
      let registries = [oid | ParsedComponent { pcClassRegistry = Just oid } <- comps]
          invalid = filter (`notElem` allowed) registries
      in if null comps
           then mkSkip cid "componentClassRegistry OID validity" ref "No components in configuration"
           else if null registries
             then mkSkip cid "componentClassRegistry OID validity" ref "No component class registry info"
             else if null invalid
               then mkPassWithDetails cid "componentClassRegistry OID values are valid" ref
                      ("Mode: " <> complianceModeText mode)
               else mkFail cid "componentClassRegistry OID validity" ref $
                      "Disallowed componentClassRegistry OID(s) for mode "
                      <> complianceModeText mode <> ": "
                      <> T.intercalate ", " (map formatOID invalid)

-- | REG-002: componentClassValue structure
-- Reference: TCG Registry §3, line 228
-- "4-byte OCTET STRING: 2 bytes category + 2 bytes sub-category"
checkClassValueStruct :: ComplianceCheck
checkClassValueStruct cert refDB = do
  let cid = CheckId Registry 2
      ref = lookupRef cid refDB
  case getPlatformComponents cert of
    Left err -> mkFail cid "componentClassValue structure" ref err
    Right comps ->
      let missingForRegistry =
            [ idx
            | (idx, ParsedComponent { pcClassRegistry = Just _, pcClassValue = Nothing }) <- zip [0 :: Int ..] comps
            ]
          orphanValues =
            [ idx
            | (idx, ParsedComponent { pcClassRegistry = Nothing, pcClassValue = Just _ }) <- zip [0 :: Int ..] comps
            ]
          invalidLen =
            [ (idx, B.length val)
            | (idx, ParsedComponent { pcClassValue = Just val }) <- zip [0 :: Int ..] comps
            , B.length val /= 4
            ]
      in if null comps
           then mkSkip cid "componentClassValue structure" ref "No components"
           else if not (null missingForRegistry)
             then mkFail cid "componentClassValue structure" ref $
                    "componentClassRegistry present but componentClassValue missing at component index(es): "
                    <> T.pack (show missingForRegistry)
             else if not (null orphanValues)
               then mkFail cid "componentClassValue structure" ref $
                      "componentClassValue present without componentClassRegistry at component index(es): "
                      <> T.pack (show orphanValues)
               else if not (null invalidLen)
                 then mkFail cid "componentClassValue structure" ref $
                        "componentClassValue must be OCTET STRING SIZE(4), invalid length(s): "
                        <> T.pack (show invalidLen)
                 else mkPass cid "componentClassValue structure is valid" ref

-- | REG-003: TCG registry class value conformance.
-- Automated check validates the 2-byte class category prefix (0x0000..0x000A).
-- Full table-level conformance may require manual evidence.
checkTcgRegistryValues :: ComplianceCheck
checkTcgRegistryValues cert refDB = do
  let cid = CheckId Registry 3
      ref = lookupRef cid refDB
  case getPlatformComponents cert of
    Left err -> mkFail cid "TCG registry value conformance" ref err
    Right comps ->
      let tcgComponents =
            [ (idx, val)
            | (idx, ParsedComponent { pcClassRegistry = Just oid, pcClassValue = Just val }) <- zip [0 :: Int ..] comps
            , oid == tcgRegistryOID
            ]
          tcgMissing =
            [ idx
            | (idx, ParsedComponent { pcClassRegistry = Just oid, pcClassValue = Nothing }) <- zip [0 :: Int ..] comps
            , oid == tcgRegistryOID
            ]
          badPrefix =
            [ (idx, val)
            | (idx, val) <- tcgComponents
            , not (isKnownTcgClassPrefix val)
            ]
      in if null comps
           then mkSkip cid "TCG registry value conformance" ref "No components"
           else if null tcgComponents && null tcgMissing
             then mkSkip cid "TCG registry value conformance" ref "No tcg-registry-componentClass-tcg components"
             else if not (null tcgMissing)
               then mkFail cid "TCG registry value conformance" ref $
                      "TCG registry components missing componentClassValue at index(es): "
                      <> T.pack (show tcgMissing)
               else if not (null badPrefix)
                 then mkSkip cid "TCG registry value conformance" ref $
                        "Automated checker cannot classify category prefix for index/value: "
                        <> T.pack (show (map (\(i, v) -> (i, bytesToHex v)) badPrefix))
                        <> ". Manual table-level evidence is required."
                 else mkPassWithDetails cid "TCG registry value prefix conformance" ref
                        "Automated check validates known category prefix (0x0000..0x000A); full table-level evidence may require manual review"

-- | REG-004: Translation-table driven registry scope checks for dmtf/pcie/storage.
-- Validates cert-internal constraints and reports where source-data evidence is needed.
checkRegistryTranslationScope :: ComplianceCheck
checkRegistryTranslationScope cert refDB = do
  let cid = CheckId Registry 4
      ref = lookupRef cid refDB
  case getPlatformComponents cert of
    Left err -> mkFail cid "Registry translation scope" ref err
    Right comps ->
      let scoped =
            [ (idx, c)
            | (idx, c@ParsedComponent { pcClassRegistry = Just oid }) <- zip [0 :: Int ..] comps
            , oid `elem` [dmtfRegistryOID, pcieRegistryOID, storageRegistryOID]
            ]
          missingIdentityFields =
            [ idx
            | (idx, ParsedComponent { pcManufacturer = Nothing }) <- scoped
            ] ++
            [ idx
            | (idx, ParsedComponent { pcModel = Nothing }) <- scoped
            ]
          nonCanonicalPcieMac =
            [ (idx, paValue addr)
            | (idx, c@ParsedComponent { pcClassRegistry = Just oid }) <- scoped
            , oid == pcieRegistryOID
            , maybe False isPcieNetworkController (pcClassValue c)
            , addr <- pcAddresses c
            , not (isUpperHexNoDelimiter (paValue addr))
            ]
      in if null comps
           then mkSkip cid "Registry translation scope" ref "No components"
           else if null scoped
             then mkSkip cid "Registry translation scope" ref "No dmtf/pcie/storage components"
             else if not (null missingIdentityFields)
               then mkFail cid "Registry translation scope" ref $
                      "Translation-table scoped component missing manufacturer/model at index(es): "
                      <> T.pack (show (dedup missingIdentityFields))
               else if not (null nonCanonicalPcieMac)
                 then mkSkip cid "Registry translation scope" ref $
                        "PCIe network controller addressValue is not canonical uppercase hex without delimiters at index/value: "
                        <> T.pack (show (map (\(i, v) -> (i, bytesToHex v)) nonCanonicalPcieMac))
               else mkPassWithDetails cid "Registry translation scope constraints satisfied" ref
                      "Source-data translation conformance (SMBIOS/PCIe/ATA/SCSI/NVMe) requires external evidence"

-- | Parse platform configuration components (v1 or v2) from certificate.
getPlatformComponents :: SignedPlatformCertificate -> Either Text [ParsedComponent]
getPlatformComponents cert =
  let attrs = pciAttributes $ getPlatformCertificate cert
      values = lookupAttributeByOID tcg_at_platformConfiguration_v2 attrs
        <|> lookupAttributeByOID tcg_at_platformConfiguration attrs
  in case values of
       Nothing -> Right []
       Just v -> parsePlatformComponents v

allowedRegistryOids :: ComplianceMode -> [OID]
allowedRegistryOids StrictV11 =
  [ tcgRegistryOID
  , ietfRegistryOID
  , dmtfRegistryOID
  ]
allowedRegistryOids OperationalCompatibility =
  [ tcgRegistryOID
  , ietfRegistryOID
  , dmtfRegistryOID
  , pcieRegistryOID
  , storageRegistryOID
  ]

isKnownTcgClassPrefix :: B.ByteString -> Bool
isKnownTcgClassPrefix bs =
  B.length bs == 4 &&
  let hi = fromIntegral (B.index bs 0) :: Int
      lo = fromIntegral (B.index bs 1) :: Int
      category = (hi * 256) + lo
  in category >= 0x0000 && category <= 0x000A

isPcieNetworkController :: B.ByteString -> Bool
isPcieNetworkController bs =
  B.length bs == 4 && B.index bs 1 == 0x02

isUpperHexNoDelimiter :: B.ByteString -> Bool
isUpperHexNoDelimiter bs =
  not (B.null bs) && B.all isUpperHex bs

isUpperHex :: Word8 -> Bool
isUpperHex w =
  (w >= 48 && w <= 57) || (w >= 65 && w <= 70)

bytesToHex :: B.ByteString -> Text
bytesToHex bs = T.concat (map byteHex (B.unpack bs))
  where
    byteHex :: Word8 -> Text
    byteHex w =
      let n = fromIntegral w :: Int
          hexChars = "0123456789ABCDEF"
          hi = hexChars !! (n `div` 16)
          lo = hexChars !! (n `mod` 16)
      in T.pack [hi, lo]

dedup :: Ord a => [a] -> [a]
dedup = foldr insertIfMissing []
  where
    insertIfMissing x acc
      | x `elem` acc = acc
      | otherwise = x : acc
