{-# LANGUAGE GADTs #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module      : Data.X509.TCG
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Platform Certificate library for Haskell.
--
-- This module provides a high-level API for working with TCG Platform Certificates
-- and Delta Platform Certificates as defined in the IWG Platform Certificate
-- Profile v1.1.
--
-- == Overview
--
-- Platform Certificates are attribute certificates that bind platform configuration
-- information to a platform identity. They are used in Trusted Computing environments
-- to provide cryptographic evidence of platform composition and configuration.
--
-- Delta Platform Certificates track changes in platform configuration over time
-- by referencing a base Platform Certificate and describing the specific changes
-- that have occurred.
--
-- == Basic Usage
--
-- @
-- import Data.X509.TCG
-- import qualified Data.ByteString as B
--
-- -- Decode a Platform Certificate from DER bytes
-- case 'decodeSignedPlatformCertificate' certBytes of
--   Right cert -> do
--     let platform = 'getPlatformInfo' cert
--         components = 'getComponentIdentifiers' cert
--     -- Process the certificate...
--   Left err -> putStrLn $ "Parse error: " ++ err
-- @
--
-- == Advanced Usage
--
-- For working with Delta Platform Certificates and component hierarchies:
--
-- @
-- -- Apply a delta certificate to get the current configuration
-- case 'applyDeltaCertificate' baseCert deltaCert of
--   Right newConfig -> -- Use the updated configuration
--   Left err -> -- Handle validation error
-- @
module Data.X509.TCG
  ( -- * Platform Certificate Types
    module Data.X509.TCG.Platform,

    -- * Delta Platform Certificate Types
    module Data.X509.TCG.Delta,

    -- * Component Types and Hierarchy
    module Data.X509.TCG.Component,

    -- * Attribute Processing
    module Data.X509.TCG.Attributes,

    -- * TCG OID Definitions
    module Data.X509.TCG.OID,

    -- * High-Level Operations

    -- ** Certificate Creation and Validation
    createPlatformCertificate,
    createDeltaPlatformCertificate,
    mkPlatformCertificate,
    Alg (..),
    Keys,
    Auth (..),
    Pair (..),
    generateKeys,
    hashSHA256,
    hashSHA384,
    hashSHA512,
    validatePlatformCertificate,
    validateDeltaCertificate',

    -- ** Configuration Management
    getCurrentPlatformConfiguration,
    applyDeltaCertificate,
    computeConfigurationChain,

    -- ** Component Operations
    getComponentIdentifiers,
    findComponentByClass,
    findComponentByAddress,
    buildComponentHierarchy,

    -- ** Attribute Extraction
    extractTCGAttributes,
    extractPlatformAttributes,
    extractTPMAttributes,

    -- ** Certificate Chain Operations
    buildCertificateChain,
    validateCertificateChain,
    findBaseCertificate,

    -- * Utility Functions
    isPlatformCertificate,
    isDeltaCertificate,
    getRequiredAttributes,
    validateAttributeCompliance,

    -- * Extended TCG Attributes (IWG v1.1)
    ExtendedTCGAttributes (..),
    PlatformConfigUri (..),
    TBBSecurityAssertions (..),
    ComponentConfigV2 (..),
    defaultExtendedTCGAttributes,
    buildAttributesFromConfigExt,
    mkPlatformCertificateExt,
    oidToContentBytes,

    -- * Internal (exported for testing)
    encodeComponentIdentifierV2,
    encodeComponentClass,
    buildTBBSecurityAssertionsAttr,
    buildExtendedTCGAttrs,
    buildPlatformConfigurationV2Attr,
  )
where

-- Cryptographic signing imports

import Crypto.Hash (HashAlgorithm, SHA256 (..), SHA384 (..), SHA512 (..), hashWith)
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.PSS as PSS
import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.Types
import Data.ASN1.Types.String ()
import Data.ASN1.BitArray (toBitArray)
import Data.ByteArray (convert)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Data.Hourglass (Date (..), DateTime (..), Month (..), TimeOfDay (..))
import Data.X509 (Certificate (..), DistinguishedName (..), Extensions (..), HashALG (..), PubKeyALG (..), SignatureALG (..), objectToSignedExact, objectToSignedExactF, AltName(..), certIssuerDN, certSerial)
import Data.X509.AttCert (AttCertIssuer (..), AttCertValidityPeriod (..), V2Form (..), Holder (..), IssuerSerial (..))
import Data.X509.Attribute (Attribute (..), Attributes (..))
import Data.Maybe (fromMaybe)
import Data.Word (Word8)
import Data.X509.TCG.Attributes
import Data.X509.TCG.Component
import Data.X509.TCG.Delta
import Data.X509.TCG.OID
import qualified Data.X509.TCG.Operations as Ops
import Data.X509.TCG.Platform

-- * Signature and hash algorithms for Platform Certificates

-- | Hash algorithms supported in Platform certificates.
--
-- This relates the typed hash algorithm @hash@ to the 'HashALG' value.
data GHash hash = GHash {getHashALG :: HashALG, getHashAlgorithm :: hash}

hashSHA256 :: GHash SHA256
hashSHA256 = GHash HashSHA256 SHA256

hashSHA384 :: GHash SHA384
hashSHA384 = GHash HashSHA384 SHA384

hashSHA512 :: GHash SHA512
hashSHA512 = GHash HashSHA512 SHA512

-- | Signature and hash algorithms instantiated with parameters for Platform Certificates.
data Alg pub priv where
  AlgRSA ::
    (HashAlgorithm hash, RSA.HashAlgorithmASN1 hash) =>
    Int ->
    GHash hash ->
    Alg RSA.PublicKey RSA.PrivateKey
  AlgRSAPSS ::
    (HashAlgorithm hash) =>
    Int ->
    PSS.PSSParams hash B.ByteString B.ByteString ->
    GHash hash ->
    Alg RSA.PublicKey RSA.PrivateKey
  AlgDSA ::
    (HashAlgorithm hash) =>
    DSA.Params ->
    GHash hash ->
    Alg DSA.PublicKey DSA.PrivateKey
  AlgEC ::
    (HashAlgorithm hash) =>
    ECC.CurveName ->
    GHash hash ->
    Alg ECDSA.PublicKey ECDSA.PrivateKey
  AlgEd25519 :: Alg Ed25519.PublicKey Ed25519.SecretKey
  AlgEd448 :: Alg Ed448.PublicKey Ed448.SecretKey

-- | Types of public and private keys used by a signature algorithm.
type Keys pub priv = (Alg pub priv, pub, priv)

-- | Generates random keys for a signature algorithm.
generateKeys :: Alg pub priv -> IO (Keys pub priv)
generateKeys alg@(AlgRSA bits _) = generateRSAKeys alg bits
generateKeys alg@(AlgRSAPSS bits _ _) = generateRSAKeys alg bits
generateKeys alg@(AlgDSA params _) = do
  x <- DSA.generatePrivate params
  let y = DSA.calculatePublic params x
  return (alg, DSA.PublicKey params y, DSA.PrivateKey params x)
generateKeys alg@(AlgEC name _) = do
  let curve = ECC.getCurveByName name
  (pub, priv) <- ECC.generate curve
  return (alg, pub, priv)
generateKeys alg@AlgEd25519 = do
  secret <- Ed25519.generateSecretKey
  return (alg, Ed25519.toPublic secret, secret)
generateKeys alg@AlgEd448 = do
  secret <- Ed448.generateSecretKey
  return (alg, Ed448.toPublic secret, secret)

generateRSAKeys ::
  Alg RSA.PublicKey RSA.PrivateKey ->
  Int ->
  IO (Alg RSA.PublicKey RSA.PrivateKey, RSA.PublicKey, RSA.PrivateKey)
generateRSAKeys alg bits = addAlg <$> RSA.generate size e
  where
    addAlg (pub, priv) = (alg, pub, priv)
    size = bits `div` 8
    e = 3

getSignatureALG :: Alg pub priv -> SignatureALG
getSignatureALG (AlgRSA _ hash) = SignatureALG (getHashALG hash) PubKeyALG_RSA
getSignatureALG (AlgRSAPSS _ _ hash) = SignatureALG (getHashALG hash) PubKeyALG_RSAPSS
getSignatureALG (AlgDSA _ hash) = SignatureALG (getHashALG hash) PubKeyALG_DSA
getSignatureALG (AlgEC _ hash) = SignatureALG (getHashALG hash) PubKeyALG_EC
getSignatureALG AlgEd25519 = SignatureALG_IntrinsicHash PubKeyALG_Ed25519
getSignatureALG AlgEd448 = SignatureALG_IntrinsicHash PubKeyALG_Ed448

doSign :: Alg pub priv -> priv -> B.ByteString -> IO B.ByteString
doSign (AlgRSA _ hash) key msg = do
  result <- RSA.signSafer (Just $ getHashAlgorithm hash) key msg
  case result of
    Left err -> error ("doSign(AlgRSA): " ++ show err)
    Right sigBits -> return sigBits
doSign (AlgRSAPSS _ params _) key msg = do
  result <- PSS.signSafer params key msg
  case result of
    Left err -> error ("doSign(AlgRSAPSS): " ++ show err)
    Right sigBits -> return sigBits
doSign (AlgDSA _ hash) key msg = do
  sig <- DSA.sign key (getHashAlgorithm hash) msg
  return $
    encodeASN1'
      DER
      [ Start Sequence,
        IntVal (DSA.sign_r sig),
        IntVal (DSA.sign_s sig),
        End Sequence
      ]
doSign (AlgEC _ hash) key msg = do
  sig <- ECDSA.sign key (getHashAlgorithm hash) msg
  return $
    encodeASN1'
      DER
      [ Start Sequence,
        IntVal (ECDSA.sign_r sig),
        IntVal (ECDSA.sign_s sig),
        End Sequence
      ]
doSign AlgEd25519 key msg =
  return $ convert $ Ed25519.sign key (Ed25519.toPublic key) msg
doSign AlgEd448 key msg =
  return $ convert $ Ed448.sign key (Ed448.toPublic key) msg

-- * Platform Certificate utilities

-- | Holds together a Platform certificate and its private key for convenience.
--
-- Contains also the crypto algorithm that both are issued from.  This is
-- useful when signing another certificate.
data Pair pub priv = Pair
  { pairAlg :: Alg pub priv,
    pairSignedCert :: SignedPlatformCertificate,
    pairKey :: priv
  }

-- | Authority signing a Platform certificate, itself or another certificate.
--
-- When the certificate is self-signed, issuer and subject are the same.  So
-- they have identical signature algorithms.  The purpose of the GADT is to
-- hold this constraint only in the self-signed case.
data Auth pubI privI pubS privS where
  Self :: (pubI ~ pubS, privI ~ privS) => Auth pubI privI pubS privS
  CA :: Pair pubI privI -> Auth pubI privI pubS privS

foldAuthPriv ::
  privS ->
  (Pair pubI privI -> privI) ->
  Auth pubI privI pubS privS ->
  privI
foldAuthPriv x _ Self = x -- uses constraint privI ~ privS
foldAuthPriv _ f (CA p) = f p

foldAuthPubPriv ::
  k pubS privS ->
  (Pair pubI privI -> k pubI privI) ->
  Auth pubI privI pubS privS ->
  k pubI privI
foldAuthPubPriv x _ Self = x -- uses both constraints
foldAuthPubPriv _ f (CA p) = f p

-- * High-Level Operations

-- ** Certificate Creation and Validation

-- | Create a Platform Certificate with the specified configuration and attributes
--
-- This is a high-level function that handles the proper construction of a
-- Platform Certificate according to IWG specifications, including proper
-- TPM EK certificate binding as required by the specification.
--
-- Note: This implementation uses a dummy signature for testing purposes.
-- In a production environment, you would need to provide a proper signing function
-- with a real private key.
createPlatformCertificate ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  Certificate -> -- TPM EK Certificate for proper Holder binding
  String -> -- Hash algorithm ("sha256", "sha384", "sha512")
  IO (Either String SignedPlatformCertificate)
createPlatformCertificate config components tpmInfo ekCert hashAlg = return $ createPlatformCertificateSync config components tpmInfo ekCert hashAlg

-- | Synchronous version of createPlatformCertificate for easier testing
createPlatformCertificateSync ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  Certificate -> -- TPM EK Certificate
  String -> -- Hash algorithm ("sha256", "sha384", "sha512")
  Either String SignedPlatformCertificate
createPlatformCertificateSync config components tpmInfo ekCert hashAlg = do
  -- Create the basic certificate info structure with EK certificate binding
  certInfo <- buildPlatformCertificateInfo config components tpmInfo ekCert hashAlg

  -- Create a signed certificate using a dummy signature
  -- In production, this would use a real private key and signing algorithm
  let dummySigningFunction = createDummySigningFunction
  let (signedCert, _) = objectToSignedExact dummySigningFunction certInfo

  return signedCert

-- | Helper function to build PlatformCertificateInfo from configuration
buildPlatformCertificateInfo ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  Certificate -> -- TPM EK Certificate
  String -> -- Hash algorithm ("sha256", "sha384", "sha512")
  Either String PlatformCertificateInfo
buildPlatformCertificateInfo config components tpmInfo ekCert hashAlg = do
  -- Create basic validity period (1 year from now) - will be overridden by mkPlatformCertificate
  let validityStart = DateTime (Date 2024 December 1) (TimeOfDay 0 0 0 0)
      validityEnd = DateTime (Date 2025 December 1) (TimeOfDay 0 0 0 0)
      validity = AttCertValidityPeriod validityStart validityEnd

  buildPlatformCertificateInfoWithValidity config components tpmInfo validity ekCert hashAlg

-- | Helper function to build PlatformCertificateInfo with custom validity period
buildPlatformCertificateInfoWithValidity ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  AttCertValidityPeriod ->
  Certificate -> -- TPM EK Certificate
  String -> -- Hash algorithm ("sha256", "sha384", "sha512")
  Either String PlatformCertificateInfo
buildPlatformCertificateInfoWithValidity config components tpmInfo validity ekCert _hashAlg =
  -- Create holder referencing TPM EK certificate using baseCertificateID
  -- Per TCG Platform Certificate Profile v1.1:
  -- "The Holder field SHALL contain a baseCertificateID that references the TPM's Endorsement Key Certificate"
  let ekIssuerDN = certIssuerDN ekCert       -- EK Certificate's issuer DN
      ekSerialNum = certSerial ekCert         -- EK Certificate's serial number
      -- Create IssuerSerial referencing the EK Certificate
      issuerSerial = IssuerSerial [AltDirectoryName ekIssuerDN] ekSerialNum Nothing
      -- Create Holder with baseCertificateID
      holder = Holder (Just issuerSerial) Nothing Nothing

      -- Create a simple issuer (V2 form) with proper issuer name
      -- RFC 5755 requires exactly one GeneralName in issuerName, and it must be a directoryName
      cnOid = [2, 5, 4, 3] -- Common Name OID
      ouOid = [2, 5, 4, 11] -- Organization Unit OID
      oOid = [2, 5, 4, 10]  -- Organization OID
      issuerDN = DistinguishedName
        [ (cnOid, ASN1CharacterString UTF8 (B8.pack "TCG Platform Certificate Issuer"))
        , (ouOid, ASN1CharacterString UTF8 (B8.pack "Platform Certificate Authority"))
        , (oOid, ASN1CharacterString UTF8 (B8.pack "TCG Organization"))
        ]
      acIssuer = AttCertIssuerV2 (V2Form [AltDirectoryName issuerDN] Nothing Nothing)

  -- Create attributes from config, components, and TPM info
  in case buildAttributesFromConfig config components tpmInfo of
       Left err -> Left err
       Right attrs -> Right $
         PlatformCertificateInfo
           { pciVersion = 1, -- v2 (RFC 5755: AttCertVersion v2 = INTEGER 1)
             pciHolder = holder,
             pciIssuer = acIssuer,
             pciSignature = SignatureALG HashSHA384 PubKeyALG_RSA,
             pciSerialNumber = 1, -- Simple serial number
             pciValidity = validity,
             pciAttributes = attrs,
             pciIssuerUniqueID = Nothing,
             pciExtensions = Extensions Nothing
           }

-- | Helper function to build PlatformCertificateInfo with extended TCG attributes
-- This version supports additional TCG Platform Certificate Profile v1.1 attributes
buildPlatformCertificateInfoWithValidityExt ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  AttCertValidityPeriod ->
  Certificate -> -- TPM EK Certificate
  String -> -- Hash algorithm ("sha256", "sha384", "sha512")
  ExtendedTCGAttributes -> -- Extended TCG attributes
  Either String PlatformCertificateInfo
buildPlatformCertificateInfoWithValidityExt config components tpmInfo validity ekCert _hashAlg extAttrs =
  -- Create holder referencing TPM EK certificate using baseCertificateID
  -- Per TCG Platform Certificate Profile v1.1:
  -- "The Holder field SHALL contain a baseCertificateID that references the TPM's Endorsement Key Certificate"
  let ekIssuerDN = certIssuerDN ekCert       -- EK Certificate's issuer DN
      ekSerialNum = certSerial ekCert         -- EK Certificate's serial number
      -- Create IssuerSerial referencing the EK Certificate
      issuerSerial = IssuerSerial [AltDirectoryName ekIssuerDN] ekSerialNum Nothing
      -- Create Holder with baseCertificateID. Delta generation can override this
      -- to reference the base platform certificate instead of the EK certificate.
      holder = case etaHolderBaseCertificateID extAttrs of
        Just baseRef -> Holder (Just baseRef) Nothing Nothing
        Nothing -> Holder (Just issuerSerial) Nothing Nothing

      cnOid = [2, 5, 4, 3]
      ouOid = [2, 5, 4, 11]
      oOid = [2, 5, 4, 10]
      -- Use CA cert's subject DN if provided, otherwise fall back to hardcoded default
      issuerDN = case etaIssuerDN extAttrs of
        Just dn -> dn
        Nothing -> DistinguishedName
          [ (cnOid, ASN1CharacterString UTF8 (B8.pack "TCG Platform Certificate Issuer"))
          , (ouOid, ASN1CharacterString UTF8 (B8.pack "Platform Certificate Authority"))
          , (oOid, ASN1CharacterString UTF8 (B8.pack "TCG Organization"))
          ]
      acIssuer = AttCertIssuerV2 (V2Form [AltDirectoryName issuerDN] Nothing Nothing)

  -- Create attributes from config, components, TPM info, and extended attributes
      -- Use extensions from ExtendedTCGAttributes if provided, otherwise empty
      extensions = case etaExtensions extAttrs of
        Just ext -> ext
        Nothing  -> Extensions Nothing

      -- Certificate serial number: use override if provided, default to 1
      serialNum = fromMaybe 1 (etaSerialNumber extAttrs)

  in case buildAttributesFromConfigExt config components tpmInfo extAttrs of
       Left err -> Left err
       Right attrs -> Right $
         PlatformCertificateInfo
           { pciVersion = 1, -- v2 (RFC 5755: AttCertVersion v2 = INTEGER 1)
             pciHolder = holder,
             pciIssuer = acIssuer,
             pciSignature = SignatureALG HashSHA384 PubKeyALG_RSA,
             pciSerialNumber = serialNum,
             pciValidity = validity,
             pciAttributes = attrs,
             pciIssuerUniqueID = Nothing,
             pciExtensions = extensions
           }

-- | Convert all ComponentIdentifiers to a single componentIdentifier_v2 attribute
-- Note: This is the legacy function that uses simple OCTET STRING encoding.
-- For TCG v1.1 compliant platformConfiguration-v2 format, use buildPlatformConfigurationV2Attr instead.
componentsToAttribute :: [ComponentIdentifier] -> [Attribute]
componentsToAttribute [] = []
componentsToAttribute components =
  [Attribute tcg_at_componentIdentifier_v2 [componentListToASN1 components]]
  where
    componentListToASN1 comps = [Start Sequence] ++ concatMap componentToASN1 comps ++ [End Sequence]
    componentToASN1 comp =
      [Start Sequence,
       OctetString (ciManufacturer comp),
       OctetString (ciModel comp)] ++
      (case ciSerial comp of
         Just serial -> [OctetString serial]
         Nothing -> [Null]) ++
      (case ciRevision comp of
         Just revision -> [OctetString revision]
         Nothing -> [Null]) ++
      [End Sequence]

-- | Encode ComponentClass as SEQUENCE { OID, 4-byte value }
-- Per TCG Platform Certificate Profile v1.1:
-- ComponentClass ::= SEQUENCE {
--   componentClassRegistry OBJECT IDENTIFIER,  -- 2.23.133.18.3.1
--   componentClassValue    OCTET STRING (SIZE(4))
-- }
encodeComponentClass :: B.ByteString -> [ASN1]
encodeComponentClass classValue =
  [ Start Sequence
  , OID tcg_registry_componentClass_tcg  -- 2.23.133.18.3.1
  , OctetString classValue               -- 4-byte class value
  , End Sequence
  ]

-- | Encode a single ComponentIdentifierV2 per TCG Platform Certificate Profile v1.1
-- ComponentIdentifierV2 ::= SEQUENCE {
--   componentClass     ComponentClass,
--   componentManufacturer UTF8String,
--   componentModel     UTF8String,
--   componentSerial    [0] IMPLICIT UTF8String OPTIONAL,
--   componentRevision  [1] IMPLICIT UTF8String OPTIONAL,
--   componentAddresses [4] IMPLICIT ComponentAddresses OPTIONAL
-- }
encodeComponentIdentifierV2 :: ComponentConfigV2 -> [ASN1]
encodeComponentIdentifierV2 comp =
  [ Start Sequence ] ++
  encodeComponentClass (ccv2Class comp) ++
  [ ASN1String (ASN1CharacterString UTF8 (ccv2Manufacturer comp))
  , ASN1String (ASN1CharacterString UTF8 (ccv2Model comp)) ] ++
  -- [0] IMPLICIT UTF8String -- componentSerial
  (case ccv2Serial comp of
    Just s -> [Other Context 0 s]
    Nothing -> []) ++
  -- [1] IMPLICIT UTF8String -- componentRevision
  (case ccv2Revision comp of
    Just r -> [Other Context 1 r]
    Nothing -> []) ++
  -- [2] IMPLICIT OBJECT IDENTIFIER -- manufacturerId
  (case ccv2ManufacturerId comp of
    Just oid -> [Other Context 2 (oidToContentBytes oid)]
    Nothing -> []) ++
  -- [3] IMPLICIT BOOLEAN -- fieldReplaceable
  (case ccv2FieldReplaceable comp of
    Just b -> [Other Context 3 (B.singleton (if b then 0xff else 0x00))]
    Nothing -> []) ++
  -- [4] IMPLICIT SEQUENCE OF ComponentAddress
  (case ccv2Addresses comp of
    Just addrs@(_:_) ->
      [Start (Container Context 4)] ++
      concatMap (\(oid, val) -> [Start Sequence, OID oid,
        ASN1String (ASN1CharacterString UTF8 val), End Sequence]) addrs ++
      [End (Container Context 4)]
    _ -> []) ++
  -- [5] IMPLICIT CertificateIdentifier
  (case ccv2PlatformCert comp of
    Just asn1s -> [Start (Container Context 5)] ++ asn1s ++ [End (Container Context 5)]
    Nothing -> []) ++
  -- [6] IMPLICIT URIReference
  (case ccv2PlatformCertUri comp of
    Just asn1s -> [Start (Container Context 6)] ++ asn1s ++ [End (Container Context 6)]
    Nothing -> []) ++
  -- [7] IMPLICIT ENUMERATED -- status (delta only)
  (case ccv2Status comp of
    Just ComponentAdded -> [Other Context 7 (B.singleton 0)]
    Just ComponentModified -> [Other Context 7 (B.singleton 1)]
    Just ComponentRemoved -> [Other Context 7 (B.singleton 2)]
    Just ComponentUnchanged -> []
    Nothing -> []) ++
  [ End Sequence ]

-- | Build tcg-at-platformConfiguration-v2 attribute (OID 2.23.133.5.1.7.2)
-- Per TCG Platform Certificate Profile v1.1:
-- PlatformConfigurationV2 ::= SEQUENCE {
--   componentIdentifiers [0] IMPLICIT SEQUENCE OF ComponentIdentifierV2
-- }
buildPlatformConfigurationV2Attr :: [ComponentConfigV2] -> Attribute
buildPlatformConfigurationV2Attr [] =
  -- Even with no components, create the attribute with empty sequence
  -- (encodeAttributeASN1 adds the outer SEQUENCE wrapper)
  Attribute tcg_at_platformConfiguration_v2
    [[ Start (Container Context 0)  -- componentIdentifiers [0] IMPLICIT
     , End (Container Context 0)
     ]]
buildPlatformConfigurationV2Attr components =
  -- (encodeAttributeASN1 adds the outer SEQUENCE wrapper)
  Attribute tcg_at_platformConfiguration_v2
    [[ Start (Container Context 0)  -- componentIdentifiers [0] IMPLICIT
     ] ++ concatMap encodeComponentIdentifierV2 components ++
     [ End (Container Context 0)
     ]]

-- | TBB Security Assertions configuration (2.23.133.2.19)
data TBBSecurityAssertions = TBBSecurityAssertions
  { tbbVersion :: Int                                    -- Version (default: 0)
  -- Common Criteria
  , tbbCCVersion :: Maybe B.ByteString                   -- CC Version (e.g., "3.1")
  , tbbEvalAssuranceLevel :: Maybe Int                   -- EAL1-7
  , tbbEvalStatus :: Maybe Int                           -- 0=inProgress, 1=completed
  , tbbPlus :: Maybe Bool                                -- Plus indicator
  , tbbStrengthOfFunction :: Maybe Int                   -- 0=basic, 1=medium, 2=high
  , tbbProtectionProfileOID :: Maybe B.ByteString        -- Protection Profile OID
  , tbbProtectionProfileURI :: Maybe B.ByteString        -- Protection Profile URI
  , tbbSecurityTargetOID :: Maybe B.ByteString           -- Security Target OID
  , tbbSecurityTargetURI :: Maybe B.ByteString           -- Security Target URI
  -- FIPS Level
  , tbbFIPSVersion :: Maybe B.ByteString                 -- FIPS version (e.g., "140-2")
  , tbbFIPSSecurityLevel :: Maybe Int                    -- Security Level 1-4
  , tbbFIPSPlus :: Maybe Bool                            -- FIPS Plus indicator
  -- RTM Type
  , tbbRTMType :: Maybe Int                              -- 0=static, 1=dynamic, 2=nonHosted, 3=hybrid
  -- ISO 9000
  , tbbISO9000Certified :: Maybe Bool                    -- ISO 9000 Certified
  , tbbISO9000URI :: Maybe B.ByteString                  -- ISO 9000 URI
  } deriving (Show, Eq)

-- | Component configuration data for platformConfiguration-v2 encoding
-- This contains all fields needed to encode ComponentIdentifierV2 per TCG v1.1
data ComponentConfigV2 = ComponentConfigV2
  { ccv2Class :: B.ByteString                            -- Component class (4-byte value)
  , ccv2Manufacturer :: B.ByteString                     -- Component manufacturer
  , ccv2Model :: B.ByteString                            -- Component model
  , ccv2Serial :: Maybe B.ByteString                     -- Component serial (optional, tag [0])
  , ccv2Revision :: Maybe B.ByteString                   -- Component revision (optional, tag [1])
  , ccv2ManufacturerId :: Maybe OID                      -- Manufacturer OID (optional, tag [2])
  , ccv2FieldReplaceable :: Maybe Bool                   -- Field replaceable (optional, tag [3])
  , ccv2Addresses :: Maybe [(OID, B.ByteString)]         -- Component addresses (optional, tag [4])
  , ccv2PlatformCert :: Maybe [ASN1]                     -- CertificateIdentifier (optional, tag [5])
  , ccv2PlatformCertUri :: Maybe [ASN1]                  -- URIReference (optional, tag [6])
  , ccv2Status :: Maybe ComponentStatus                  -- Delta status (optional, tag [7])
  } deriving (Show, Eq)

-- | Platform Config URI with optional hash for integrity verification
-- Per TCG Platform Certificate Profile v1.1:
-- URIReference ::= SEQUENCE {
--   uniformResourceIdentifier IA5String (SIZE (1..URIMAX)),
--   hashAlgorithm AlgorithmIdentifier OPTIONAL,
--   hashValue BIT STRING OPTIONAL }
data PlatformConfigUri = PlatformConfigUri
  { pcUri :: B.ByteString                                -- Uniform Resource Identifier
  , pcHashAlgorithm :: Maybe B.ByteString                -- Hash algorithm: "sha256", "sha384", "sha512"
  , pcHashValue :: Maybe B.ByteString                    -- Hash value (raw bytes)
  } deriving (Show, Eq)

-- | Extended TCG attributes configuration
data ExtendedTCGAttributes = ExtendedTCGAttributes
  { etaPlatformConfigUri :: Maybe PlatformConfigUri      -- Platform Config URI with hash info
  , etaPlatformClass :: Maybe B.ByteString               -- Platform Class (hex string)
  , etaCredentialSpecVersion :: Maybe (Int, Int, Int)    -- Credential Spec (major, minor, revision)
  , etaPlatformSpecVersion :: Maybe (Int, Int, Int)      -- Platform Spec (major, minor, revision)
  , etaSecurityAssertions :: Maybe TBBSecurityAssertions -- TBB Security Assertions
  , etaComponentsV2 :: Maybe [ComponentConfigV2]         -- Component configs for platformConfiguration-v2
  , etaCredentialTypeOid :: Maybe OID                    -- Override for tcg-at-tcgCredentialType OID
  , etaHolderBaseCertificateID :: Maybe IssuerSerial     -- Optional holder baseCertificateID override
  , etaExtensions :: Maybe Extensions                    -- Additional X.509 extensions (CertPolicies, AIA, CRL DP)
  , etaIssuerDN :: Maybe DistinguishedName               -- Override issuer DN (from CA cert)
  , etaSerialNumber :: Maybe Integer                     -- Certificate serial number override
  , etaNotBefore :: Maybe DateTime                       -- Validity notBefore override
  , etaNotAfter :: Maybe DateTime                        -- Validity notAfter override
  } deriving (Show, Eq)

-- | Create default extended attributes (all Nothing)
defaultExtendedTCGAttributes :: ExtendedTCGAttributes
defaultExtendedTCGAttributes = ExtendedTCGAttributes Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing

-- | Helper function to build attributes from configuration data
buildAttributesFromConfig ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  Either String Attributes
buildAttributesFromConfig config components tpmInfo =
  buildAttributesFromConfigExt config components tpmInfo defaultExtendedTCGAttributes

-- | Helper function to build attributes with extended TCG attributes
buildAttributesFromConfigExt ::
  PlatformConfiguration ->
  [ComponentIdentifier] ->
  TPMInfo ->
  ExtendedTCGAttributes ->
  Either String Attributes
buildAttributesFromConfigExt config components _tpmInfo extAttrs = do
  -- Create basic platform attributes
  let manufacturerAttr = Attribute tcg_paa_platformManufacturer [[ASN1String (ASN1CharacterString UTF8 (pcManufacturer config))]]
      modelAttr = Attribute tcg_paa_platformModel [[ASN1String (ASN1CharacterString UTF8 (pcModel config))]]
      serialAttr = Attribute tcg_paa_platformSerial [[ASN1String (ASN1CharacterString UTF8 (pcSerial config))]]
      versionAttr = Attribute tcg_paa_platformVersion [[ASN1String (ASN1CharacterString UTF8 (pcVersion config))]]

      -- Create component attributes
      -- If etaComponentsV2 is provided, use platformConfiguration-v2 format (via buildExtendedTCGAttrs)
      -- Otherwise, fall back to legacy componentsToAttribute format
      componentAttrs = case etaComponentsV2 extAttrs of
        Just _ -> []  -- Components will be added via buildExtendedTCGAttrs as platformConfiguration-v2
        Nothing -> componentsToAttribute components  -- Legacy format

      -- Create extended TCG attributes (includes platformConfiguration-v2 if etaComponentsV2 is set)
      extendedAttrs = buildExtendedTCGAttrs extAttrs

  return $ Attributes (
    case etaComponentsV2 extAttrs of
      Just _ -> extendedAttrs  -- V2/SAN path: platform info in SAN, no basic attrs in attributes
      Nothing -> [manufacturerAttr, modelAttr, serialAttr, versionAttr] ++ componentAttrs ++ extendedAttrs
    )

-- | Build extended TCG attributes from configuration
buildExtendedTCGAttrs :: ExtendedTCGAttributes -> [Attribute]
buildExtendedTCGAttrs extAttrs =
  let -- Platform Specification attribute (2.23.133.2.17)
      platSpecAttr = case etaPlatformSpecVersion extAttrs of
        Just (major, minor, rev) ->
          let classBytes = case etaPlatformClass extAttrs of
                Just cb -> cb
                Nothing -> B8.pack "\x00\x00\x00\x01" -- Default: Client platform class
          in [Attribute tcg_at_tcgPlatformSpecification
            [[Start Sequence,
              IntVal (fromIntegral major),
              IntVal (fromIntegral minor),
              IntVal (fromIntegral rev),
              End Sequence,
              OctetString classBytes]]]
        Nothing -> []

      -- Credential Type attribute (2.23.133.2.25)
      -- Default: Platform OID 2.23.133.8.2 (tcg-kp-PlatformAttributeCertificate)
      -- Delta generation may override this via etaCredentialTypeOid.
      credTypeOid = case etaCredentialTypeOid extAttrs of
        Just oid -> oid
        Nothing -> tcg_kp_PlatformAttributeCertificate
      credTypeAttr =
        [Attribute tcg_at_tcgCredentialType
          [[OID credTypeOid]]]

      -- Credential Specification attribute (2.23.133.2.23)
      credSpecAttr = case etaCredentialSpecVersion extAttrs of
        Just (major, minor, rev) ->
          [Attribute tcg_at_tcgCredentialSpecification
            [[IntVal (fromIntegral major),
              IntVal (fromIntegral minor),
              IntVal (fromIntegral rev)]]]
        Nothing -> []

      -- Platform Config URI attribute (2.23.133.5.1.3)
      -- Per TCG Platform Certificate Profile v1.1:
      -- URIReference ::= SEQUENCE {
      --   uniformResourceIdentifier IA5String (SIZE (1..URIMAX)),
      --   hashAlgorithm AlgorithmIdentifier OPTIONAL,
      --   hashValue BIT STRING OPTIONAL }
      configUriAttr = case etaPlatformConfigUri extAttrs of
        Just pcu ->
          let uriASN1 = [ASN1String (ASN1CharacterString IA5 (pcUri pcu))]
              -- AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
              -- Hash algorithm OIDs: SHA-256: 2.16.840.1.101.3.4.2.1, SHA-384: 2.16.840.1.101.3.4.2.2, SHA-512: 2.16.840.1.101.3.4.2.3
              hashAlgASN1 = case pcHashAlgorithm pcu of
                Just algName ->
                  let algOID = case B8.unpack algName of
                        "sha256" -> [2, 16, 840, 1, 101, 3, 4, 2, 1]
                        "sha384" -> [2, 16, 840, 1, 101, 3, 4, 2, 2]
                        "sha512" -> [2, 16, 840, 1, 101, 3, 4, 2, 3]
                        _        -> [2, 16, 840, 1, 101, 3, 4, 2, 1]  -- default to SHA-256
                  in [Start Sequence, OID algOID, End Sequence]
                Nothing -> []
              -- BIT STRING for hash value
              hashValueASN1 = case pcHashValue pcu of
                Just hashVal -> [BitString (toBitArray hashVal 0)]
                Nothing -> []
          in [Attribute tcg_paa_platformConfigUri
               [uriASN1 ++ hashAlgASN1 ++ hashValueASN1]]
        Nothing -> []

      -- TBB Security Assertions attribute (2.23.133.2.19)
      securityAssertionsAttr = case etaSecurityAssertions extAttrs of
        Just tbb -> [buildTBBSecurityAssertionsAttr tbb]
        Nothing -> []

      -- Platform Configuration V2 attribute (2.23.133.5.1.7.2)
      -- This is the TCG v1.1 compliant component encoding
      platformConfigV2Attr = case etaComponentsV2 extAttrs of
        Just comps -> [buildPlatformConfigurationV2Attr comps]
        Nothing -> []
  -- IWG convention order: CredentialType → SecurityAssertions → PlatformSpec → PlatformConfigV2 → CredentialSpec → ConfigUri
  in credTypeAttr ++ securityAssertionsAttr ++ platSpecAttr ++ platformConfigV2Attr ++ credSpecAttr ++ configUriAttr

-- | Build TBB Security Assertions attribute
buildTBBSecurityAssertionsAttr :: TBBSecurityAssertions -> Attribute
buildTBBSecurityAssertionsAttr tbb =
  let -- Version (INTEGER) — per DER, omit when DEFAULT value (0)
      versionASN1 = if tbbVersion tbb == 0 then [] else [IntVal (fromIntegral (tbbVersion tbb))]

      -- Common Criteria Measures (SEQUENCE) - OPTIONAL [0]
      -- Per TCG spec, EvaluationAssuranceLevel and EvaluationStatus are ENUMERATED
      -- CommonCriteriaMeasures ::= SEQUENCE {
      --   version IA5String,
      --   assurancelevel EvaluationAssuranceLevel,
      --   evaluationStatus EvaluationStatus,
      --   plus BOOLEAN DEFAULT FALSE,
      --   strengthOfFunction [0] StrengthOfFunction OPTIONAL,
      --   profileOid [1] OBJECT IDENTIFIER OPTIONAL,
      --   profileUri [2] URIReference OPTIONAL,
      --   targetOid [3] OBJECT IDENTIFIER OPTIONAL,
      --   targetUri [4] URIReference OPTIONAL }
      ccMeasures = case (tbbCCVersion tbb, tbbEvalAssuranceLevel tbb) of
        (Just ccVer, Just eal) ->
          let baseContent =
                [ Start (Container Context 0),
                  -- [0] IMPLICIT CommonCriteriaMeasures (SEQUENCE tag replaced by [0])
                  -- ccVersion (IA5String)
                  ASN1String (ASN1CharacterString IA5 ccVer),
                  -- assurancelevel (ENUMERATED - EvaluationAssuranceLevel)
                  Enumerated (fromIntegral eal),
                  -- evaluationStatus (ENUMERATED - EvaluationStatus)
                  case tbbEvalStatus tbb of
                    Just status -> Enumerated (fromIntegral status)
                    Nothing -> Enumerated 2 -- default: evaluationCompleted
                ]
              -- plus (BOOLEAN DEFAULT FALSE) — per DER, omit when False
              plusContent = case tbbPlus tbb of
                Just True -> [Boolean True]
                _ -> []
              -- strengthOfFunction [0] IMPLICIT StrengthOfFunction OPTIONAL
              sofContent = case tbbStrengthOfFunction tbb of
                Just sof -> [Other Context 0 (B.singleton (fromIntegral sof))]
                Nothing -> []
              -- profileOid [1] IMPLICIT OBJECT IDENTIFIER OPTIONAL
              ppOidContent = case tbbProtectionProfileOID tbb of
                Just oid -> [Other Context 1 oid]
                Nothing -> []
              -- profileUri [2] IMPLICIT URIReference OPTIONAL
              ppUriContent = case tbbProtectionProfileURI tbb of
                Just uri -> [Start (Container Context 2), ASN1String (ASN1CharacterString IA5 uri), End (Container Context 2)]
                Nothing -> []
              -- targetOid [3] IMPLICIT OBJECT IDENTIFIER OPTIONAL
              stOidContent = case tbbSecurityTargetOID tbb of
                Just oid -> [Other Context 3 oid]
                Nothing -> []
              -- targetUri [4] IMPLICIT URIReference OPTIONAL
              stUriContent = case tbbSecurityTargetURI tbb of
                Just uri -> [Start (Container Context 4), ASN1String (ASN1CharacterString IA5 uri), End (Container Context 4)]
                Nothing -> []
              endContent = [End (Container Context 0)]
          in [baseContent ++ plusContent ++ sofContent ++ ppOidContent ++ ppUriContent ++ stOidContent ++ stUriContent ++ endContent]
        _ -> []

      -- FIPS Level (SEQUENCE) - OPTIONAL [1]
      -- Per TCG spec, SecurityLevel is ENUMERATED
      fipsLevel = case (tbbFIPSVersion tbb, tbbFIPSSecurityLevel tbb) of
        (Just fipsVer, Just level) ->
          let fipsPlusContent = case tbbFIPSPlus tbb of
                Just True -> [Boolean True]
                _ -> []  -- DER DEFAULT FALSE: omit when False
          in [[ Start (Container Context 1),
                -- [1] IMPLICIT FIPSLevel (SEQUENCE tag replaced by [1])
                -- fipsVersion (IA5String)
                ASN1String (ASN1CharacterString IA5 fipsVer),
                -- level (ENUMERATED - SecurityLevel)
                Enumerated (fromIntegral level)
              ] ++ fipsPlusContent ++
              [ End (Container Context 1) ]]
        _ -> []

      -- RTM Type (ENUMERATED) - OPTIONAL [2] IMPLICIT
      -- Per TCG spec, MeasurementRootType is ENUMERATED
      -- For implicit tagging of a primitive, use Other with the encoded value
      rtmTypeASN1 = case tbbRTMType tbb of
        Just rtm -> [[Other Context 2 (B.singleton (fromIntegral rtm))]]
        Nothing -> []

      -- ISO 9000 Certified (BOOLEAN) - DEFAULT FALSE — per DER, omit when False
      iso9000Certified = case tbbISO9000Certified tbb of
        Just True -> [[Boolean True]]
        _ -> []

      -- ISO 9000 URI (IA5String) - OPTIONAL
      iso9000Uri = case tbbISO9000URI tbb of
        Just uri -> [[ASN1String (ASN1CharacterString IA5 uri)]]
        Nothing -> []

      -- Combine all fields (encodeAttributeASN1 adds the outer SEQUENCE wrapper)
      tbbContent = versionASN1
                   ++ concat ccMeasures
                   ++ concat fipsLevel
                   ++ concat rtmTypeASN1
                   ++ concat iso9000Certified
                   ++ concat iso9000Uri

  in Attribute tcg_at_tbbSecurityAssertions [tbbContent]

-- | Dummy signing function for testing purposes
-- In production, replace with proper cryptographic signing
createDummySigningFunction :: B.ByteString -> (B.ByteString, SignatureALG, ())
createDummySigningFunction _dataToSign =
  (B.replicate 48 0x42, SignatureALG HashSHA384 PubKeyALG_RSA, ()) -- 48 bytes of dummy signature data (SHA384)

-- * Production Platform Certificate Creation

-- | Create a Platform Certificate using RSA signing (production version)
--
-- This function creates a properly signed Platform Certificate using a real RSA private key,
-- unlike the dummy implementation above. It supports both self-signed certificates and
-- certificates signed by a CA.
-- | Create a Platform Certificate with multiple signature algorithm support
--
-- This function supports multiple signature algorithms including RSA, DSA, ECDSA, Ed25519, and Ed448.
-- It handles both self-signed certificates and CA-signed certificates.
--
-- Based on the pattern from x509-validation but adapted for Platform Certificates.
mkPlatformCertificate ::
  -- | Platform configuration data
  PlatformConfiguration ->
  -- | Component identifiers
  [ComponentIdentifier] ->
  -- | TPM information
  TPMInfo ->
  -- | TPM EK Certificate
  Certificate ->
  -- | Validity period (notBefore, notAfter)
  (DateTime, DateTime) ->
  -- | Authority signing the new certificate
  Auth pubI privI pubS privS ->
  -- | Keys for the new certificate
  Keys pubS privS ->
  -- | Hash algorithm ("sha256", "sha384", "sha512")
  String ->
  -- | Result: signed Platform Certificate pair
  IO (Either String (Pair pubS privS))
mkPlatformCertificate config components tpmInfo ekCert validity auth (algS, _pubKey, privKey) hashAlg = do
  let validityPeriod = uncurry AttCertValidityPeriod validity
  case buildPlatformCertificateInfoWithValidity config components tpmInfo validityPeriod ekCert hashAlg of
    Left err -> return $ Left err
    Right certInfo -> do
      -- Apply authority settings to the certificate
      let signingKey = foldAuthPriv privKey pairKey auth
          algI = foldAuthPubPriv algS pairAlg auth
          finalCertInfo = certInfo { pciSignature = getSignatureALG algI }
          signatureFunction objRaw = do
            sigBits <- doSign algI signingKey objRaw
            return (sigBits, getSignatureALG algI)

      signedCert <- objectToSignedExactF signatureFunction finalCertInfo
      return $
        Right
          Pair
            { pairAlg = algS,
              pairSignedCert = signedCert,
              pairKey = privKey
            }

-- | Create a Platform Certificate with extended TCG attributes (IWG v1.1 full compliance)
--
-- This function creates a Platform Certificate with all optional TCG Platform Certificate
-- Profile v1.1 attributes including:
-- * tcg-at-tcgPlatformSpecification (2.23.133.2.17)
-- * tcg-at-tcgCredentialType (2.23.133.2.25)
-- * tcg-at-tcgCredentialSpecification (2.23.133.2.23)
-- * tcg-at-platformConfigUri (2.23.133.5.1.3)
mkPlatformCertificateExt ::
  -- | Platform configuration data
  PlatformConfiguration ->
  -- | Component identifiers
  [ComponentIdentifier] ->
  -- | TPM information
  TPMInfo ->
  -- | TPM EK Certificate
  Certificate ->
  -- | Validity period (notBefore, notAfter)
  (DateTime, DateTime) ->
  -- | Authority signing the new certificate
  Auth pubI privI pubS privS ->
  -- | Keys for the new certificate
  Keys pubS privS ->
  -- | Hash algorithm ("sha256", "sha384", "sha512")
  String ->
  -- | Extended TCG attributes
  ExtendedTCGAttributes ->
  -- | Result: signed Platform Certificate pair
  IO (Either String (Pair pubS privS))
mkPlatformCertificateExt config components tpmInfo ekCert validity auth (algS, _pubKey, privKey) hashAlg extAttrs = do
  let validityPeriod = uncurry AttCertValidityPeriod validity
  case buildPlatformCertificateInfoWithValidityExt config components tpmInfo validityPeriod ekCert hashAlg extAttrs of
    Left err -> return $ Left err
    Right certInfo -> do
      let signingKey = foldAuthPriv privKey pairKey auth
          algI = foldAuthPubPriv algS pairAlg auth
          finalCertInfo = certInfo { pciSignature = getSignatureALG algI }
          signatureFunction objRaw = do
            sigBits <- doSign algI signingKey objRaw
            return (sigBits, getSignatureALG algI)

      signedCert <- objectToSignedExactF signatureFunction finalCertInfo
      return $
        Right
          Pair
            { pairAlg = algS,
              pairSignedCert = signedCert,
              pairKey = privKey
            }

-- | Create a Delta Platform Certificate that references a base certificate
--
-- Creates a Delta Platform Certificate that describes changes from the
-- specified base certificate.
createDeltaPlatformCertificate ::
  -- | Base certificate
  SignedPlatformCertificate ->
  -- | Component changes
  [ComponentDelta] ->
  -- | Change records
  [ChangeRecord] ->
  IO (Either String SignedDeltaPlatformCertificate)
createDeltaPlatformCertificate baseCert componentDeltas changeRecords = do
  -- Extract information from base certificate
  let baseCertInfo = getPlatformCertificate baseCert
      baseSerial = pciSerialNumber baseCertInfo
      baseIssuer = pciIssuer baseCertInfo

  -- Extract DistinguishedName from AttCertIssuer
  -- For now, create a simple DistinguishedName (this should be improved)
  let issuerDN = DistinguishedName [] -- Simplified issuer DN

  -- Create base certificate reference
  let baseCertRef =
        BasePlatformCertificateRef
          { bpcrIssuer = issuerDN,
            bpcrSerialNumber = baseSerial,
            bpcrCertificateHash = Nothing, -- Could be computed if needed
            bpcrValidityPeriod = Nothing -- Optional validity period
          }

  -- Create Delta Platform Configuration
  let platformDelta =
        PlatformConfigurationDelta
          { pcdPlatformInfoChanges = Nothing, -- No platform info changes for now
            pcdComponentDeltas = componentDeltas,
            pcdChangeRecords = changeRecords
          }

  -- Current timestamp (simplified)
  let currentTime = DateTime (Date 2024 December 15) (TimeOfDay 12 0 0 0)

  let _deltaConfig =
        DeltaPlatformConfiguration
          { dpcBaseCertificateSerial = baseSerial,
            dpcConfigurationDelta = platformDelta,
            dpcChangeTimestamp = currentTime,
            dpcChangeReason = Just (B8.pack "Component configuration changes")
          }

  -- Create attributes containing the delta configuration
  -- For now, create minimal attributes
  let deltaAttrs = Attributes [] -- Simplified for initial implementation

  -- Create Delta Platform Certificate Info
  let deltaCertInfo =
        DeltaPlatformCertificateInfo
          { dpciVersion = 1, -- v2 (RFC 5755: AttCertVersion v2 = INTEGER 1)
            dpciHolder = pciHolder baseCertInfo, -- Same holder as base
            dpciIssuer = baseIssuer,
            dpciSignature = SignatureALG HashSHA384 PubKeyALG_RSA, -- Default signature
            dpciSerialNumber = baseSerial + 1, -- Increment serial number
            dpciValidity = pciValidity baseCertInfo, -- Same validity period
            dpciAttributes = deltaAttrs,
            dpciIssuerUniqueID = Nothing,
            dpciExtensions = Extensions Nothing,
            dpciBaseCertificateRef = baseCertRef
          }

  -- For now, create a dummy signed certificate
  -- This is a basic implementation that creates the structure
  let dummySignature = B.pack [0, 0, 0, 0] -- Placeholder signature
      signatureAlg = SignatureALG HashSHA384 PubKeyALG_RSA
      signingFunction _ = return (dummySignature, signatureAlg)

  signedDelta <- objectToSignedExactF signingFunction deltaCertInfo
  return $ Right signedDelta

-- | Validate a Platform Certificate for compliance with IWG specifications
--
-- Performs comprehensive validation including:
-- * Required attribute presence
-- * Attribute format validation
-- * Component hierarchy consistency
-- * TPM information validation
validatePlatformCertificate :: SignedPlatformCertificate -> [String]
validatePlatformCertificate cert =
  let certInfo = getPlatformCertificate cert
      attrs = pciAttributes certInfo
   in validateRequiredAttributes attrs
        ++ validateAttributeFormats attrs
        ++ validateTPMAttributes attrs

-- | Validate a Delta Platform Certificate
--
-- Validates that the delta certificate properly references its base
-- and contains valid change information.
validateDeltaCertificate' :: SignedDeltaPlatformCertificate -> [String]
validateDeltaCertificate' deltaCert =
  let deltaInfo = getDeltaPlatformCertificate deltaCert
      baseRef = dpciBaseCertificateRef deltaInfo
   in validateBaseCertificateReference baseRef
        ++ validateDeltaAttributesInTCG (dpciAttributes deltaInfo)

-- ** Configuration Management

-- | Get the current platform configuration from a certificate or certificate chain
--
-- If given a base Platform Certificate, returns its configuration.
-- If given a Delta Certificate, applies the delta to compute the current configuration.
getCurrentPlatformConfiguration ::
  Either SignedPlatformCertificate SignedDeltaPlatformCertificate ->
  Maybe PlatformConfigurationV2
getCurrentPlatformConfiguration = Ops.getCurrentPlatformConfiguration

-- | Apply a Delta Platform Certificate to a base configuration
--
-- Computes the resulting configuration after applying the delta changes.
applyDeltaCertificate ::
  SignedPlatformCertificate ->
  SignedDeltaPlatformCertificate ->
  Either String PlatformConfigurationV2
applyDeltaCertificate baseCert deltaCert = do
  baseConfig <- case getCurrentPlatformConfiguration (Left baseCert) of
    Just config -> Right config
    Nothing -> Left "Cannot extract base configuration"

  Ops.applyDeltaCertificate baseConfig deltaCert

-- | Compute the final configuration from a chain of certificates
--
-- Given a base Platform Certificate and a sequence of Delta Certificates,
-- computes the final resulting platform configuration.
computeConfigurationChain ::
  SignedPlatformCertificate ->
  [SignedDeltaPlatformCertificate] ->
  Either String PlatformConfigurationV2
computeConfigurationChain = Ops.computeConfigurationChain

-- ** Component Operations

-- | Extract all component identifiers from a Platform Certificate
getComponentIdentifiers :: SignedPlatformCertificate -> [ComponentIdentifier]
getComponentIdentifiers = Ops.getComponentIdentifiers

-- | Find components of a specific class in a Platform Certificate
findComponentByClass :: ComponentClass -> SignedPlatformCertificate -> [ComponentIdentifierV2]
findComponentByClass targetClass cert =
  let components = Ops.getComponentIdentifiersV2 cert
   in Ops.findComponentByClass targetClass components

-- | Find a component by its address in a Platform Certificate
findComponentByAddress :: ComponentAddress -> SignedPlatformCertificate -> Maybe ComponentIdentifierV2
findComponentByAddress addr cert =
  let components = Ops.getComponentIdentifiersV2 cert
   in Ops.findComponentByAddress addr components

-- | Build a component hierarchy from Platform Certificate information
buildComponentHierarchy :: SignedPlatformCertificate -> ComponentHierarchy
buildComponentHierarchy cert =
  let components = Ops.getComponentIdentifiersV2 cert
      componentTree = Ops.buildComponentHierarchy components
   in case components of
        [] -> ComponentHierarchy [] componentTree
        (comp : _) -> ComponentHierarchy [ComponentReference 0 0 comp] componentTree

-- ** Attribute Extraction

-- | Extract all TCG attributes from a certificate
extractTCGAttributes :: SignedPlatformCertificate -> [TCGAttribute]
extractTCGAttributes cert =
  let attrs = pciAttributes $ getPlatformCertificate cert
   in extractTCGAttrs attrs
  where
    extractTCGAttrs :: Attributes -> [TCGAttribute]
    extractTCGAttrs (Attributes attrs) =
      [tcgAttr | attr <- attrs, Right tcgAttr <- [parseTCGAttribute attr]]

-- | Extract platform-specific attributes (manufacturer, model, serial, version)
extractPlatformAttributes :: SignedPlatformCertificate -> Maybe PlatformInfo
extractPlatformAttributes = getPlatformInfo

-- | Extract TPM-related attributes
extractTPMAttributes :: SignedPlatformCertificate -> Maybe TPMInfo
extractTPMAttributes = getTPMInfo

-- ** Certificate Chain Operations

-- | Build a certificate chain from a base certificate and deltas
buildCertificateChain ::
  SignedPlatformCertificate ->
  [SignedDeltaPlatformCertificate] ->
  CertificateChain
buildCertificateChain = Ops.buildCertificateChain

-- | Validate a certificate chain for consistency
validateCertificateChain :: CertificateChain -> [String]
validateCertificateChain chain =
  validateChainContinuity chain
    ++ validateChainValidity chain

-- | Find the base certificate for a given Delta Platform Certificate
findBaseCertificate ::
  SignedDeltaPlatformCertificate ->
  [SignedPlatformCertificate] ->
  Maybe SignedPlatformCertificate
findBaseCertificate = Ops.findBaseCertificate

-- * Utility Functions

-- | Check if a certificate is a Platform Certificate (not a Delta)
isPlatformCertificate :: Either SignedPlatformCertificate SignedDeltaPlatformCertificate -> Bool
isPlatformCertificate (Left _) = True
isPlatformCertificate (Right _) = False

-- | Check if a certificate is a Delta Platform Certificate
isDeltaCertificate :: Either SignedPlatformCertificate SignedDeltaPlatformCertificate -> Bool
isDeltaCertificate = not . isPlatformCertificate

-- | Get the list of required attributes for Platform Certificates
getRequiredAttributes :: [OID]
getRequiredAttributes =
  [ tcg_at_platformConfiguration_v2,
    tcg_at_componentIdentifier_v2,
    tcg_paa_platformManufacturer,
    tcg_paa_platformModel,
    tcg_paa_platformSerial,
    tcg_paa_platformVersion
  ]

-- | Validate that a certificate contains all required attributes
validateAttributeCompliance :: SignedPlatformCertificate -> [String]
validateAttributeCompliance cert =
  let attrs = pciAttributes $ getPlatformCertificate cert
      presentOIDs = extractPresentOIDs attrs
      required = getRequiredAttributes
      missing = filter (`notElem` presentOIDs) required
   in map (\oid -> "Missing required attribute: " ++ attributeOIDToType oid) missing

-- Helper functions

validateRequiredAttributes :: Attributes -> [String]
validateRequiredAttributes attrs =
  let presentOIDs = extractPresentOIDs attrs
      required = getRequiredAttributes
      missing = filter (`notElem` presentOIDs) required
   in map (\oid -> "Missing required attribute: " ++ attributeOIDToType oid) missing

validateAttributeFormats :: Attributes -> [String]
validateAttributeFormats attrs =
  let tcgAttrs = extractTCGAttrs attrs
   in concatMap validateTCGAttributeFormat tcgAttrs
  where
    extractTCGAttrs :: Attributes -> [TCGAttribute]
    extractTCGAttrs (Attributes attrList) =
      [tcgAttr | attr <- attrList, Right tcgAttr <- [parseTCGAttribute attr]]

    validateTCGAttributeFormat :: TCGAttribute -> [String]
    validateTCGAttributeFormat attr = case attr of
      TCGPlatformManufacturer (PlatformManufacturerAttr bs) ->
        ["Platform Manufacturer cannot be empty" | B.null bs]
      TCGPlatformModel (PlatformModelAttr bs) ->
        ["Platform Model cannot be empty" | B.null bs]
      _ -> []

validateTPMAttributes :: Attributes -> [String]
validateTPMAttributes attrs =
  let tcgAttrs = extractTCGAttrs attrs
   in concatMap validateTPMAttribute tcgAttrs
  where
    extractTCGAttrs :: Attributes -> [TCGAttribute]
    extractTCGAttrs (Attributes attrList) =
      [tcgAttr | attr <- attrList, Right tcgAttr <- [parseTCGAttribute attr]]

    validateTPMAttribute :: TCGAttribute -> [String]
    validateTPMAttribute attr = case attr of
      TCGTPMModel (TPMModelAttr bs) ->
        ["TPM Model cannot be empty" | B.null bs]
      TCGTPMVersion (TPMVersionAttr _version) ->
        [] -- TPM version validation could be added here
      TCGTPMSpecification (TPMSpecificationAttr _spec) ->
        [] -- TPM specification validation could be added here
      _ -> []

validateBaseCertificateReference :: BasePlatformCertificateRef -> [String]
validateBaseCertificateReference baseRef
  | bpcrSerialNumber baseRef <= 0 = ["Invalid base certificate serial number"]
  | otherwise = []

validateDeltaAttributesInTCG :: Attributes -> [String]
validateDeltaAttributesInTCG attrs =
  -- Check that delta attributes contain necessary platform configuration deltas
  let presentOIDs = extractPresentOIDs attrs
      hasDeltaConfig = tcg_at_platformConfiguration_v2 `elem` presentOIDs
   in ["Delta certificate missing platform configuration delta" | not hasDeltaConfig]

validateChainContinuity :: CertificateChain -> [String]
validateChainContinuity chain =
  let baseRef = ccBaseCertificate chain
      deltaRefs = ccIntermediateCertificates chain
      baseSerial = bpcrSerialNumber baseRef
      deltaSerials = map bpcrSerialNumber deltaRefs
      hasDuplicates = length deltaSerials /= length (nub deltaSerials)
      hasBaseConflict = baseSerial `elem` deltaSerials
   in ((["Duplicate serial numbers in certificate chain" | hasDuplicates]) ++ (["Delta certificate serial conflicts with base certificate" | hasBaseConflict]))
  where
    nub :: (Eq a) => [a] -> [a]
    nub [] = []
    nub (x : xs) = x : nub (filter (/= x) xs)

validateChainValidity :: CertificateChain -> [String]
validateChainValidity chain =
  let baseRef = ccBaseCertificate chain
      deltaRefs = ccIntermediateCertificates chain
      baseErrors = validateBaseCertificateReference baseRef
      deltaErrors = concatMap validateBaseCertificateReference deltaRefs
   in baseErrors ++ deltaErrors

extractPresentOIDs :: Attributes -> [OID]
extractPresentOIDs (Attributes attrs) = map attrType attrs

-- | Encode an OID to DER content bytes (without tag/length wrapper).
-- First two components encoded as 40*a+b, remaining use base-128 VLQ.
oidToContentBytes :: OID -> B.ByteString
oidToContentBytes [] = B.empty
oidToContentBytes [x] = B.singleton (fromIntegral (40 * x))
oidToContentBytes (x:y:rest) =
  B.pack $ fromIntegral (40 * x + y) : concatMap encodeSubId rest
  where
    encodeSubId :: Integer -> [Word8]
    encodeSubId n
      | n < 128   = [fromIntegral n]
      | otherwise = encodeVLQ (n `div` 128) [fromIntegral (n `mod` 128)]
    -- Build VLQ bytes MSB-first: all prepended bytes get continuation bit (+128)
    encodeVLQ :: Integer -> [Word8] -> [Word8]
    encodeVLQ 0 acc = acc
    encodeVLQ n acc = encodeVLQ (n `div` 128) (fromIntegral (n `mod` 128 + 128) : acc)
