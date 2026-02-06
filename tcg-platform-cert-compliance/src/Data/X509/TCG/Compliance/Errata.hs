{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.Errata
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Errata correction checks (ERR-001 to ERR-005).
--
-- Validates corrections from the IWG Platform Certificate Profile Errata.

module Data.X509.TCG.Compliance.Errata
  ( -- * All Errata Checks
    runErrataChecks

    -- * Individual Checks
  , checkComponentIdOrder  -- ERR-001
  , checkMacAddressFormat  -- ERR-002
  , checkPrivateEntNum     -- ERR-003
  , checkBaseCertIdEnc     -- ERR-004
  , check48BitMacOids      -- ERR-005
  ) where

import Control.Applicative ((<|>))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Text (Text)
import qualified Data.Text as T
import Data.X509.AttCert (Holder(..))
import qualified Data.X509.AttCert as AC

import Data.X509.TCG.Platform (SignedPlatformCertificate, getPlatformCertificate)
import Data.X509.TCG.Platform (PlatformCertificateInfo(..))
import Data.X509.TCG.OID
  ( tcg_at_platformConfiguration
  , tcg_at_platformConfiguration_v2
  , tcg_address_ethernetmac
  , tcg_address_wlanmac
  , tcg_address_bluetoothmac
  )
import Data.X509.TCG.Utils (lookupAttributeByOID)

import Data.X509.TCG.Compliance.Types
import Data.X509.TCG.Compliance.ASN1
  ( ParsedComponent(..)
  , ParsedAddress(..)
  , parsePlatformComponents
  , formatOID
  )
import Data.X509.TCG.Compliance.Reference
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Internal (lookupRef, ComplianceCheck)

tshow :: Show a => a -> Text
tshow = T.pack . show

-- | Run all errata compliance checks
runErrataChecks :: SignedPlatformCertificate -> ReferenceDB -> IO [CheckResult]
runErrataChecks cert refDB = sequence
  [ checkComponentIdOrder cert refDB
  , checkMacAddressFormat cert refDB
  , checkPrivateEntNum cert refDB
  , checkBaseCertIdEnc cert refDB
  , check48BitMacOids cert refDB
  ]

-- | ERR-001: ComponentIdentifier order
-- Reference: Errata §3.1, line 164
-- "order in which ComponentIdentifier appears may differ from SMBIOS"
-- This is an informational note - no specific validation required
checkComponentIdOrder :: ComplianceCheck
checkComponentIdOrder _cert refDB = do
  let cid = CheckId Errata 1
      ref = lookupRef cid refDB
  -- This is informational - the spec clarifies that order doesn't matter
  -- We pass this check as there's no specific requirement to validate
  mkPass cid "ComponentIdentifier order (informational note acknowledged)" ref

-- | ERR-002: MAC address format support
-- Reference: Errata §2.4, line 109
-- "Verifiers need to support multiple MAC address formats"
-- This is a verifier requirement, not a certificate requirement
checkMacAddressFormat :: ComplianceCheck
checkMacAddressFormat _cert refDB = do
  let cid = CheckId Errata 2
      ref = lookupRef cid refDB
  -- This is a verifier capability note - our implementation supports
  -- multiple MAC formats. Pass this check.
  mkPass cid "MAC address format support (verifier capability)" ref

-- | ERR-003: PrivateEnterpriseNumber correction
-- Reference: Errata §3.9, line 291
-- "PrivateEnterpriseNumber type correction"
-- This is a type definition correction in the spec
checkPrivateEntNum :: ComplianceCheck
checkPrivateEntNum _cert refDB = do
  let cid = CheckId Errata 3
      ref = lookupRef cid refDB
  -- This is a spec type correction - certificates using the old definition
  -- are still valid. Pass this check.
  mkPass cid "PrivateEnterpriseNumber type (errata acknowledged)" ref

-- | ERR-004: baseCertificateID encoding
-- Reference: Errata §2.1, line 92
-- "TPM EK certificate's Issuer and Serial number must be included"
checkBaseCertIdEnc :: ComplianceCheck
checkBaseCertIdEnc cert refDB = do
  let cid = CheckId Errata 4
      ref = lookupRef cid refDB
      pci = getPlatformCertificate cert
      holder = pciHolder pci
  case holderBaseCertificateID holder of
    Nothing -> mkFail cid "baseCertificateID encoding" ref
      "Holder MUST use baseCertificateID with TPM EK certificate's Issuer and Serial"
    Just issuerSerial ->
      let issuerGNs = AC.issuer issuerSerial
          serialNum = AC.serial issuerSerial
      in if null issuerGNs
           then mkFail cid "baseCertificateID encoding" ref
             "baseCertificateID issuer GeneralNames is empty (must contain EK certificate issuer)"
           else if serialNum <= 0
             then mkFail cid "baseCertificateID encoding" ref
               "baseCertificateID serial must be a positive integer"
             else mkPass cid "baseCertificateID encoding (Issuer+Serial present)" ref

-- | ERR-005: 48-bit MAC address OIDs
-- Reference: Errata §3.6, line 226
-- "Current OIDs only support 48-bit MAC addresses"
-- This is an informational note about OID limitations
check48BitMacOids :: ComplianceCheck
check48BitMacOids cert refDB = do
  let cid = CheckId Errata 5
      ref = lookupRef cid refDB
      macTypeOids = [tcg_address_ethernetmac, tcg_address_wlanmac, tcg_address_bluetoothmac]
  case getPlatformComponents cert of
    Left err -> mkFail cid "48-bit MAC address OID constraints" ref err
    Right comps ->
      let macAddrs =
            [ (idx, paType addr, paValue addr)
            | (idx, ParsedComponent { pcAddresses = addrs }) <- zip [0 :: Int ..] comps
            , addr <- addrs
            , paType addr `elem` macTypeOids
            ]
          invalid =
            [ (idx, oid, val)
            | (idx, oid, val) <- macAddrs
            , not (isMac48Encoding val)
            ]
      in if null comps
           then mkSkip cid "48-bit MAC address OID constraints" ref "No components"
           else if null macAddrs
             then mkSkip cid "48-bit MAC address OID constraints" ref "No tcg-address-* MAC entries"
             else if null invalid
               then mkPass cid "48-bit MAC address OID constraints satisfied" ref
               else mkFail cid "48-bit MAC address OID constraints" ref $
                      "Non-48-bit or invalid MAC encoding for OID-index/value: "
                      <> mconcatWithComma [ "(" <> tshow i <> "," <> formatOID oid <> "," <> T.pack (show val) <> ")"
                                         | (i, oid, val) <- invalid
                                         ]

getPlatformComponents :: SignedPlatformCertificate -> Either Text [ParsedComponent]
getPlatformComponents cert =
  let attrs = pciAttributes $ getPlatformCertificate cert
      values = lookupAttributeByOID tcg_at_platformConfiguration_v2 attrs
        <|> lookupAttributeByOID tcg_at_platformConfiguration attrs
  in case values of
       Nothing -> Right []
       Just v -> parsePlatformComponents v

isMac48Encoding :: B.ByteString -> Bool
isMac48Encoding bs =
  let chars = BC.unpack bs
      isHex c = ('0' <= c && c <= '9')
             || ('a' <= c && c <= 'f')
             || ('A' <= c && c <= 'F')
      isDelimiter c = c == ':' || c == '-' || c == '.' || c == ' '
      allAllowed = all (\c -> isHex c || isDelimiter c) chars
      hexChars = filter isHex chars
  in allAllowed && length hexChars == 12

mconcatWithComma :: [Text] -> Text
mconcatWithComma [] = ""
mconcatWithComma (x:xs) = x <> foldMap (", " <>) xs
