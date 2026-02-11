{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Use =<<" #-}

-- |
-- Module      : Data.X509.TCG.Delta
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Delta Platform Certificate support.
--
-- This module implements Delta Platform Certificates as defined in the IWG Platform
-- Certificate Profile v1.1. Delta Platform Certificates track changes in platform
-- configuration over time by referencing a base Platform Certificate.
module Data.X509.TCG.Delta
  ( -- * Delta Platform Certificate Types
    DeltaPlatformCertificateInfo (..),
    SignedDeltaPlatformCertificate,

    -- * Delta Configuration
    DeltaPlatformConfiguration (..),
    DeltaConfiguration (..),
    ComponentChange (..),
    PlatformConfigurationDelta (..),
    PlatformInfoDelta (..),
    ComponentDelta (..),
    DeltaOperation (..),

    -- * Base Certificate References
    BasePlatformCertificateRef (..),
    CertificateChain (..),

    -- * Change Tracking
    ChangeRecord (..),
    ChangeType (..),
    ChangeMetadata (..),

    -- * Marshalling Operations
    encodeSignedDeltaPlatformCertificate,
    decodeSignedDeltaPlatformCertificate,
    decodeSignedDeltaPlatformCertificateWithLimit,

    -- * Accessor Functions
    getDeltaPlatformCertificate,
    getBaseCertificateReference,
    getPlatformConfigurationDelta,
    getComponentDeltas,
    getChangeRecords,

    -- * Validation Functions
    validateDeltaCertificate,
    applyDeltaToBase,
    computeResultingConfiguration,

    -- * Parsing Functions (TODO)
    parseDeltaPlatformConfiguration,
    validateDeltaAttributes,
  )
where

import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.Types
import qualified Data.ByteString as B
import Data.Hourglass (DateTime)
import Data.List (find)
import Data.X509 (DistinguishedName, Extensions (..), SignatureALG, SignedExact, decodeSignedObject, encodeSignedObject, getSigned, signedObject)
import Data.X509.AttCert (AttCertIssuer(..), AttCertValidityPeriod, Holder, UniqueID, V2Form(..))
import Data.X509.Attribute (Attribute (..), Attributes (..), attrType, attrValues, encodeGeneralName)
import Data.X509.TCG.Component (ComponentIdentifier, ComponentIdentifierV2)
import Data.X509.TCG.OID (tcg_at_componentIdentifier_v2, tcg_at_platformConfiguration_v2, tcg_at_tpmSpecification, tcg_at_tpmVersion)
import Data.X509.TCG.Platform (ComponentStatus (..), PlatformConfigurationV2 (..))

-- | Delta Platform Certificate Information structure.
--
-- Similar to 'Data.X509.AttCert.PlatformCertificateInfo' but specifically for
-- Delta Platform Certificates that track changes from a base Platform Certificate.
-- See TCG PCP v2.1, Section 5 for delta certificate semantics.
data DeltaPlatformCertificateInfo = DeltaPlatformCertificateInfo
  { dpciVersion :: Int,
    -- ^ Attribute certificate version. Must be 2 (v2) per RFC 5755.
    dpciHolder :: Holder,
    -- ^ Holder of the attribute certificate, identifying the platform.
    dpciIssuer :: AttCertIssuer,
    -- ^ Issuer of the delta certificate (typically the CA).
    dpciSignature :: SignatureALG,
    -- ^ Signature algorithm used to sign this certificate.
    dpciSerialNumber :: Integer,
    -- ^ Unique serial number assigned by the issuer.
    dpciValidity :: AttCertValidityPeriod,
    -- ^ Validity period of this delta certificate.
    dpciAttributes :: Attributes,
    -- ^ Attributes containing delta platform configuration data.
    dpciIssuerUniqueID :: Maybe UniqueID,
    -- ^ Optional unique identifier for the issuer.
    dpciExtensions :: Extensions,
    -- ^ X.509 extensions (e.g., Authority Key Identifier, Subject Alternative Name).
    dpciBaseCertificateRef :: BasePlatformCertificateRef
    -- ^ Reference to the base Platform Certificate this delta applies to.
  }
  deriving (Show, Eq)

-- | ASN.1 serialization and deserialization for 'DeltaPlatformCertificateInfo'.
instance ASN1Object DeltaPlatformCertificateInfo where
  toASN1 (DeltaPlatformCertificateInfo dciVer dciHolder dciIssuer dciSig dciSn dciValid dciAttrs dciUid dciExts dciBase) xs =
    [IntVal $ fromIntegral dciVer]
      ++ toASN1 dciHolder []
      ++ encodeIssuerCompat dciIssuer
      ++ toASN1 dciSig []
      ++ [IntVal dciSn]
      ++ toASN1 dciValid []
      ++ toASN1 dciAttrs []
      ++ maybe [] (\u -> [BitString u]) dciUid
      ++ toASN1 dciExts []
      ++ toASN1 dciBase []
      ++ xs
  fromASN1 [] = Left "DeltaPlatformCertificateInfo: empty input"
  fromASN1 (Start Sequence : IntVal ver : rest) = parseDCIContent ver rest True
  fromASN1 (IntVal ver : rest) = parseDCIContent ver rest False
  fromASN1 _ = Left "DeltaPlatformCertificateInfo: Invalid ASN1 structure"

-- | Parse the inner content of a 'DeltaPlatformCertificateInfo' from an ASN.1 stream.
-- The @hasOuterSequence@ flag indicates whether an outer SEQUENCE wrapper was consumed.
parseDCIContent :: Integer -> [ASN1] -> Bool -> Either String (DeltaPlatformCertificateInfo, [ASN1])
parseDCIContent ver rest hasOuterSequence = do
    (holder, rest1) <- fromASN1 rest
    (issuer, rest2) <- fromASN1 rest1
    (signature, rest3) <- fromASN1 rest2
    case rest3 of
      (IntVal serialNum : rest4) -> do
        (validity, rest5) <- fromASN1 rest4
        (attributes, rest6) <- fromASN1 rest5
        let (uid, rest7) = extractUID rest6
            (extensions, rest8) = extractExtensions rest7
        (baseRef, rest9) <- fromASN1 rest8
        if hasOuterSequence
          then case rest9 of
            (End Sequence : remaining) ->
              Right (DeltaPlatformCertificateInfo (fromIntegral ver) holder issuer signature serialNum validity attributes uid extensions baseRef, remaining)
            _ -> Left "DeltaPlatformCertificateInfo: Invalid ASN1 sequence termination"
          else Right (DeltaPlatformCertificateInfo (fromIntegral ver) holder issuer signature serialNum validity attributes uid extensions baseRef, rest9)
      _ -> Left "DeltaPlatformCertificateInfo: Missing serial number"

-- | Encode an 'AttCertIssuer' with compatibility handling for the V2Form case.
-- When the issuer contains only issuer names (no baseCertificateID or objectDigestInfo),
-- it is encoded directly with explicit CONTEXT [0] tagging.
encodeIssuerCompat :: AttCertIssuer -> [ASN1]
encodeIssuerCompat (AttCertIssuerV2 (V2Form issuerNames Nothing Nothing)) =
  [Start (Container Context 0), Start Sequence]
    ++ concatMap encodeGeneralName issuerNames
    ++ [End Sequence, End (Container Context 0)]
encodeIssuerCompat issuer = toASN1 issuer []

-- | Extract an optional issuer unique ID (BitString) from the ASN.1 stream.
extractUID :: [ASN1] -> (Maybe UniqueID, [ASN1])
extractUID (BitString uid : rest) = (Just uid, rest)
extractUID rest = (Nothing, rest)

-- | Extract optional X.509 extensions from the ASN.1 stream.
-- Returns @Extensions Nothing@ if no extensions are present.
extractExtensions :: [ASN1] -> (Extensions, [ASN1])
extractExtensions asn1 = case fromASN1 asn1 of
  Right (exts, rest) -> (exts, rest)
  Left _ -> (Extensions Nothing, asn1) -- No extensions present

-- | Extract an optional certificate hash (OctetString) from the ASN.1 stream.
extractHash :: [ASN1] -> (Maybe B.ByteString, [ASN1])
extractHash (OctetString hash : rest) = (Just hash, rest)
extractHash rest = (Nothing, rest)

-- | Extract an optional validity period from the ASN.1 stream.
extractValidity :: [ASN1] -> (Maybe AttCertValidityPeriod, [ASN1])
extractValidity asn1 = case fromASN1 asn1 of
  Right (validity, rest) -> (Just validity, rest)
  Left _ -> (Nothing, asn1)

-- | A signed Delta Platform Certificate, containing a DER-encoded
-- 'DeltaPlatformCertificateInfo' with its cryptographic signature.
type SignedDeltaPlatformCertificate = SignedExact DeltaPlatformCertificateInfo

-- | Delta Platform Configuration structure.
--
-- Contains the changes to be applied to a base platform configuration,
-- including the base certificate serial number, the configuration delta,
-- and metadata about when and why the change was made.
data DeltaPlatformConfiguration = DeltaPlatformConfiguration
  { dpcBaseCertificateSerial :: Integer,
    -- ^ Serial number of the base Platform Certificate this delta references.
    dpcConfigurationDelta :: PlatformConfigurationDelta,
    -- ^ The configuration delta describing what changed.
    dpcChangeTimestamp :: DateTime,
    -- ^ Timestamp when the platform change occurred.
    dpcChangeReason :: Maybe B.ByteString
    -- ^ Optional human-readable reason for the change.
  }
  deriving (Show, Eq)

-- | Delta Configuration structure for YAML integration.
--
-- Simplified delta configuration structure that can be parsed from YAML
-- and converted to the full 'DeltaPlatformConfiguration'.
data DeltaConfiguration = DeltaConfiguration
  { dcBaseCertificateSerial :: String,
    -- ^ Serial number of the base certificate (as a hex or decimal string).
    dcDeltaSequenceNumber :: Maybe Int,
    -- ^ Optional sequence number for ordering multiple deltas.
    dcChangeDescription :: Maybe String,
    -- ^ Optional human-readable description of the change.
    dcComponentChanges :: [ComponentChange]
    -- ^ List of component changes included in this delta.
  }
  deriving (Show, Eq)

-- | Component Change structure for YAML integration.
--
-- Represents a single component change in a format suitable for YAML parsing.
data ComponentChange = ComponentChange
  { chChangeType :: String,
    -- ^ Type of change: @\"added\"@, @\"removed\"@, or @\"modified\"@.
    chComponentClass :: String,
    -- ^ Component class identifier (hex string).
    chManufacturer :: String,
    -- ^ Component manufacturer name.
    chModel :: String,
    -- ^ Component model name or number.
    chSerial :: String,
    -- ^ Component serial number.
    chRevision :: String,
    -- ^ Component revision or firmware version.
    chPreviousRevision :: Maybe String
    -- ^ Previous revision, present only for modification changes.
  }
  deriving (Show, Eq)

-- | Platform Configuration Delta structure.
--
-- Represents the specific changes to platform configuration, including
-- optional platform-level information changes, a list of component deltas,
-- and audit change records.
data PlatformConfigurationDelta = PlatformConfigurationDelta
  { pcdPlatformInfoChanges :: Maybe PlatformInfoDelta,
    -- ^ Optional changes to platform-level information (manufacturer, model, etc.).
    pcdComponentDeltas :: [ComponentDelta],
    -- ^ List of individual component changes (additions, removals, modifications).
    pcdChangeRecords :: [ChangeRecord]
    -- ^ Audit records documenting each change with timestamps and metadata.
  }
  deriving (Show, Eq)

-- | Platform Information Delta structure.
--
-- Tracks changes to platform-level properties such as manufacturer,
-- model, serial number, and version string.
data PlatformInfoDelta = PlatformInfoDelta
  { pidManufacturerChange :: Maybe B.ByteString,
    -- ^ New manufacturer name, if changed.
    pidModelChange :: Maybe B.ByteString,
    -- ^ New model identifier, if changed.
    pidSerialChange :: Maybe B.ByteString,
    -- ^ New serial number, if changed.
    pidVersionChange :: Maybe B.ByteString
    -- ^ New version string, if changed.
  }
  deriving (Show, Eq)

-- | Component Delta structure.
--
-- Represents a change to an individual component in the platform,
-- pairing a 'DeltaOperation' with the affected component identifiers
-- and change metadata.
data ComponentDelta = ComponentDelta
  { cdOperation :: DeltaOperation,
    -- ^ The delta operation to perform (add, remove, modify, replace, or update).
    cdComponent :: ComponentIdentifierV2,
    -- ^ The component being changed (new component for add\/replace, target for others).
    cdPreviousComponent :: Maybe ComponentIdentifierV2,
    -- ^ The previous component state, present for replace operations.
    cdChangeMetadata :: ChangeMetadata
    -- ^ Metadata about this change (initiator, approver, ticket reference, etc.).
  }
  deriving (Show, Eq)

-- | Delta Operation enumeration.
--
-- Types of operations that can be performed on components in a
-- Delta Platform Certificate. See TCG PCP v2.1, Section 5.
data DeltaOperation
  = -- | Component was added to the platform.
    DeltaAdd
  | -- | Component was removed from the platform.
    DeltaRemove
  | -- | Component was modified (firmware update, etc.).
    DeltaModify
  | -- | Component was replaced with another component.
    DeltaReplace
  | -- | Component configuration or properties were updated.
    DeltaUpdate
  deriving (Show, Eq, Enum)

-- | Base Platform Certificate Reference structure.
--
-- References the base Platform Certificate that this Delta applies to.
-- Used to link a delta certificate back to the original platform certificate
-- it modifies. See TCG PCP v2.1, Section 5.
data BasePlatformCertificateRef = BasePlatformCertificateRef
  { bpcrIssuer :: DistinguishedName,
    -- ^ Distinguished Name of the base certificate issuer.
    bpcrSerialNumber :: Integer,
    -- ^ Serial number of the base Platform Certificate.
    bpcrCertificateHash :: Maybe B.ByteString,
    -- ^ Optional hash of the base certificate for integrity verification.
    bpcrValidityPeriod :: Maybe AttCertValidityPeriod
    -- ^ Optional validity period of the base certificate for additional matching.
  }
  deriving (Show, Eq)

-- | ASN.1 serialization and deserialization for 'BasePlatformCertificateRef'.
-- Encodes as a SEQUENCE of issuer DN, serial number, optional hash, and optional validity.
instance ASN1Object BasePlatformCertificateRef where
  toASN1 (BasePlatformCertificateRef issuer serial hash validity) xs =
    ( [Start Sequence]
        ++ toASN1 issuer []
        ++ [IntVal serial]
        ++ maybe [] (\h -> [OctetString h]) hash
        ++ maybe [] (`toASN1` []) validity
        ++ [End Sequence]
    )
      ++ xs
  fromASN1 (Start Sequence : rest) = do
    (issuer, rest1) <- fromASN1 rest
    case rest1 of
      (IntVal serial : rest2) -> do
        let (hash, rest3) = extractHash rest2
            (validity, rest4) = extractValidity rest3
        case rest4 of
          (End Sequence : remaining) ->
            Right (BasePlatformCertificateRef issuer serial hash validity, remaining)
          _ -> Left "BasePlatformCertificateRef: Invalid ASN1 sequence termination"
      _ -> Left "BasePlatformCertificateRef: Missing serial number"
  fromASN1 _ = Left "BasePlatformCertificateRef: Invalid ASN1 structure"

-- | Certificate Chain structure.
--
-- Represents a chain of Platform Certificates leading to this Delta,
-- including the base certificate, any intermediate deltas, and the
-- overall validity period of the chain.
data CertificateChain = CertificateChain
  { ccBaseCertificate :: BasePlatformCertificateRef,
    -- ^ Reference to the original base Platform Certificate.
    ccIntermediateCertificates :: [BasePlatformCertificateRef],
    -- ^ Ordered list of intermediate delta certificate references.
    ccChainValidityPeriod :: AttCertValidityPeriod
    -- ^ Overall validity period covering the entire certificate chain.
  }
  deriving (Show, Eq)

-- | Change Record structure.
--
-- Records detailed information about a specific change made to the platform,
-- including a unique identifier, change type, timestamp, description,
-- affected components, and associated metadata.
data ChangeRecord = ChangeRecord
  { crChangeId :: B.ByteString,
    -- ^ Unique identifier for this change record.
    crChangeType :: ChangeType,
    -- ^ Classification of the change (hardware addition, firmware update, etc.).
    crTimestamp :: DateTime,
    -- ^ Timestamp when the change was recorded.
    crDescription :: Maybe B.ByteString,
    -- ^ Optional human-readable description of the change.
    crAffectedComponents :: [ComponentIdentifier],
    -- ^ List of components affected by this change.
    crChangeMetadata :: ChangeMetadata
    -- ^ Additional metadata (initiator, approver, ticket reference, etc.).
  }
  deriving (Show, Eq)

-- | Change Type enumeration.
--
-- Classifies the nature of a platform change for auditing and tracking purposes.
data ChangeType
  = ChangeHardwareAddition
    -- ^ A new hardware component was added to the platform.
  | ChangeHardwareRemoval
    -- ^ An existing hardware component was removed from the platform.
  | ChangeHardwareReplacement
    -- ^ A hardware component was replaced with a different one.
  | ChangeFirmwareUpdate
    -- ^ Firmware on a component was updated to a new version.
  | ChangeSoftwareInstallation
    -- ^ New software was installed on the platform.
  | ChangeSoftwareRemoval
    -- ^ Existing software was removed from the platform.
  | ChangeConfigurationUpdate
    -- ^ Platform or component configuration settings were changed.
  | ChangeSecurityUpdate
    -- ^ A security-related update was applied.
  | ChangeMaintenance
    -- ^ Routine maintenance was performed.
  | ChangeOther B.ByteString
    -- ^ Other change type with a custom description.
  deriving (Show, Eq)

-- | Change Metadata structure.
--
-- Additional metadata about changes, including who initiated and approved
-- the change, a reference to a change management ticket, rollback information,
-- and arbitrary key-value pairs.
data ChangeMetadata = ChangeMetadata
  { -- | Who initiated the change.
    cmInitiator :: Maybe B.ByteString,
    -- | Who approved the change.
    cmApprover :: Maybe B.ByteString,
    -- | Reference to a change management system ticket.
    cmChangeTicket :: Maybe B.ByteString,
    -- | Information for rolling back the change.
    cmRollbackInfo :: Maybe B.ByteString,
    -- | Additional key-value pairs for extensibility.
    cmAdditionalInfo :: [(B.ByteString, B.ByteString)]
  }
  deriving (Show, Eq)

-- * Marshalling Operations

-- | Encode a 'SignedDeltaPlatformCertificate' to a DER-encoded bytestring.
encodeSignedDeltaPlatformCertificate :: SignedDeltaPlatformCertificate -> B.ByteString
encodeSignedDeltaPlatformCertificate = encodeSignedObject

-- | Decode a DER-encoded bytestring to a 'SignedDeltaPlatformCertificate'.
decodeSignedDeltaPlatformCertificate :: B.ByteString -> Either String SignedDeltaPlatformCertificate
decodeSignedDeltaPlatformCertificate = decodeSignedObject

-- | Decode a DER-encoded bytestring with a size limit.
-- Returns @Left@ if the input exceeds the provided maximum size in bytes.
decodeSignedDeltaPlatformCertificateWithLimit :: Int -> B.ByteString -> Either String SignedDeltaPlatformCertificate
decodeSignedDeltaPlatformCertificateWithLimit maxBytes bs
  | B.length bs > maxBytes =
      Left ("DER input exceeds maximum size: " ++ show maxBytes)
  | otherwise = decodeSignedDeltaPlatformCertificate bs

-- * Accessor Functions

-- | Extract the 'DeltaPlatformCertificateInfo' from a 'SignedDeltaPlatformCertificate'.
getDeltaPlatformCertificate :: SignedDeltaPlatformCertificate -> DeltaPlatformCertificateInfo
getDeltaPlatformCertificate = signedObject . getSigned

-- | Extract the base certificate reference from a Delta Platform Certificate.
--
-- Retrieves the 'BasePlatformCertificateRef' identifying the base Platform Certificate
-- that this Delta Certificate applies to. The reference includes the issuer DN,
-- serial number, and optionally a certificate hash and validity period for
-- additional verification.
--
-- The base certificate reference is essential for:
--
-- * Validating that the Delta Certificate applies to the correct base certificate
-- * Building certificate chains from base to current state
-- * Ensuring continuity in platform configuration tracking
getBaseCertificateReference :: SignedDeltaPlatformCertificate -> BasePlatformCertificateRef
getBaseCertificateReference cert = dpciBaseCertificateRef $ getDeltaPlatformCertificate cert

-- | Extract 'PlatformConfigurationDelta' from a Delta Platform Certificate.
--
-- Searches for the @tcg-at-platformConfigurationV2@ attribute (OID 2.23.133.2.23)
-- and parses it into a structured 'PlatformConfigurationDelta'.
--
-- Returns @Just@ the parsed delta if the attribute is found and valid,
-- or @Nothing@ if the attribute is missing or malformed.
getPlatformConfigurationDelta :: SignedDeltaPlatformCertificate -> Maybe PlatformConfigurationDelta
getPlatformConfigurationDelta cert =
  maybe
    Nothing
    parseDeltaPlatformConfiguration
    ( lookupDeltaAttribute
        "2.23.133.2.23"
        (dpciAttributes $ getDeltaPlatformCertificate cert)
    )

-- | Extract the list of 'ComponentDelta' entries from a Delta Platform Certificate.
-- Returns an empty list if no delta configuration is present.
getComponentDeltas :: SignedDeltaPlatformCertificate -> [ComponentDelta]
getComponentDeltas cert =
  maybe [] pcdComponentDeltas (getPlatformConfigurationDelta cert)

-- | Extract the list of 'ChangeRecord' entries from a Delta Platform Certificate.
-- Returns an empty list if no delta configuration is present.
getChangeRecords :: SignedDeltaPlatformCertificate -> [ChangeRecord]
getChangeRecords cert =
  maybe [] pcdChangeRecords (getPlatformConfigurationDelta cert)

-- * Validation Functions

-- | Validate a Delta Platform Certificate.
--
-- Checks that the certificate is properly formed and references a valid base certificate.
-- Returns an empty list if validation passes, or a list of error messages otherwise.
validateDeltaCertificate :: SignedDeltaPlatformCertificate -> [String]
validateDeltaCertificate cert =
  let deltaInfo = getDeltaPlatformCertificate cert
      baseRef = dpciBaseCertificateRef deltaInfo
   in validateBaseCertificateRef baseRef
        ++ validateDeltaAttributes (dpciAttributes deltaInfo)

-- | Apply a Delta Platform Certificate to a base configuration.
--
-- Computes the resulting platform configuration after applying all component
-- deltas to the given base configuration. Operations are processed sequentially
-- using a left fold over the component delta list.
--
-- Supported delta operations: 'DeltaAdd', 'DeltaRemove', 'DeltaModify',
-- 'DeltaReplace', and 'DeltaUpdate'.
applyDeltaToBase :: PlatformConfigurationV2 -> PlatformConfigurationDelta -> Either String PlatformConfigurationV2
applyDeltaToBase baseConfig delta =
  Right $ foldl applyComponentDelta baseConfig (pcdComponentDeltas delta)
  where
    applyComponentDelta :: PlatformConfigurationV2 -> ComponentDelta -> PlatformConfigurationV2
    applyComponentDelta config compDelta =
      case cdOperation compDelta of
        DeltaAdd -> addComponent config (cdComponent compDelta)
        DeltaRemove -> removeComponent config (cdComponent compDelta)
        DeltaModify -> modifyComponent config (cdComponent compDelta)
        DeltaReplace -> replaceComponent config (cdPreviousComponent compDelta) (cdComponent compDelta)
        DeltaUpdate -> updateComponent config (cdComponent compDelta)

-- | Compute the resulting configuration after applying a sequence of delta certificates.
-- Each delta is applied in order; the computation short-circuits on the first error.
computeResultingConfiguration :: PlatformConfigurationV2 -> [PlatformConfigurationDelta] -> Either String PlatformConfigurationV2
computeResultingConfiguration baseConfig = foldl (\acc delta -> acc >>= \config -> applyDeltaToBase config delta) (Right baseConfig)

-- | Look up a delta-specific attribute value by its OID string representation.
-- The OID string is given in dotted notation (e.g., @\"2.23.133.2.23\"@).
-- Returns the first OctetString value found, or @Nothing@.
lookupDeltaAttribute :: String -> Attributes -> Maybe B.ByteString
lookupDeltaAttribute oidStr (Attributes attrs) =
  case parseOIDString oidStr of
    Just targetOid ->
      case find (\attr -> attrType attr == targetOid) attrs of
        Just attr -> case attrValues attr of
          [[OctetString value]] -> Just value -- Expecting single OctetString value
          (values : _) -> case values of -- Take first value from first set
            (value : _) -> case value of
              OctetString bs -> Just bs
              _ -> Nothing
            [] -> Nothing
          _ -> Nothing
        Nothing -> Nothing
    Nothing -> Nothing
  where
    parseOIDString :: String -> Maybe OID
    parseOIDString str =
      let parts = words $ map (\c -> if c == '.' then ' ' else c) str
       in traverse readMaybe parts

    readMaybe :: String -> Maybe Integer
    readMaybe s = case reads s of
      [(x, "")] -> Just x
      _ -> Nothing

-- | Parse a 'PlatformConfigurationDelta' from a DER-encoded attribute value.
--
-- Decodes the ASN.1 structure and extracts platform info changes, component
-- deltas, and change records. Returns @Nothing@ if decoding or parsing fails.
--
-- /Note:/ This is currently a simplified implementation; platform info changes,
-- component deltas, and change records are parsed as empty placeholders.
parseDeltaPlatformConfiguration :: B.ByteString -> Maybe PlatformConfigurationDelta
parseDeltaPlatformConfiguration bs =
  case decodeASN1' DER bs of
    Left _ -> Nothing -- Invalid ASN.1 structure
    Right asn1List -> parseDeltaFromASN1 asn1List
  where
    parseDeltaFromASN1 :: [ASN1] -> Maybe PlatformConfigurationDelta
    parseDeltaFromASN1 (Start Sequence : rest) =
      case parseOptionalPlatformInfo rest of
        Just (platformInfo, rest') ->
          case parseComponentDeltas rest' of
            Just (componentDeltas, rest'') ->
              case parseChangeRecords rest'' of
                Just (changeRecords, End Sequence : _) ->
                  Just $ PlatformConfigurationDelta platformInfo componentDeltas changeRecords
                _ -> Nothing
            Nothing -> Nothing
        Nothing -> Nothing
    parseDeltaFromASN1 _ = Nothing

    parseOptionalPlatformInfo :: [ASN1] -> Maybe (Maybe PlatformInfoDelta, [ASN1])
    parseOptionalPlatformInfo asn1List =
      -- For now, assume no platform info changes (simplified implementation)
      Just (Nothing, asn1List)

    parseComponentDeltas :: [ASN1] -> Maybe ([ComponentDelta], [ASN1])
    parseComponentDeltas asn1List =
      -- For now, return empty component deltas (simplified implementation)
      Just ([], asn1List)

    parseChangeRecords :: [ASN1] -> Maybe ([ChangeRecord], [ASN1])
    parseChangeRecords asn1List =
      -- For now, return empty change records (simplified implementation)
      Just ([], asn1List)

-- | Validate a 'BasePlatformCertificateRef'.
-- Checks that the serial number is positive. Returns a list of error messages.
validateBaseCertificateRef :: BasePlatformCertificateRef -> [String]
validateBaseCertificateRef baseRef
  | bpcrSerialNumber baseRef <= 0 = ["Invalid base certificate serial number"]
  | otherwise = []

-- | Validate the attributes of a Delta Platform Certificate.
-- Ensures at least one attribute is present and that all attribute OIDs
-- are recognized TCG attribute types. Returns a list of error messages.
validateDeltaAttributes :: Attributes -> [String]
validateDeltaAttributes (Attributes attrs)
  | null attrs = ["Delta certificate must have at least one attribute"]
  | otherwise = concatMap validateDeltaAttribute attrs
  where
    validateDeltaAttribute attr =
      case attrType attr of
        -- Platform Configuration Delta attribute is required
        oid | oid == tcg_at_platformConfiguration_v2 -> []
        -- Component identifiers are valid in delta certificates
        oid | oid == tcg_at_componentIdentifier_v2 -> []
        -- TPM version/spec can be included
        oid | oid == tcg_at_tpmVersion -> []
        oid | oid == tcg_at_tpmSpecification -> []
        -- Other attributes should be validated based on specification
        _ -> ["Unknown or invalid attribute in delta certificate: " ++ show (attrType attr)]

-- | Add a component to the platform configuration with 'ComponentAdded' status.
addComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
addComponent config component =
  config {pcv2Components = pcv2Components config ++ [(component, ComponentAdded)]}

-- | Remove a component from the platform configuration by filtering it out.
removeComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
removeComponent config component =
  config {pcv2Components = filter ((/= component) . fst) (pcv2Components config)}

-- | Mark a matching component as 'ComponentModified' in the platform configuration.
modifyComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
modifyComponent config component =
  config {pcv2Components = map updateStatus (pcv2Components config)}
  where
    updateStatus (comp, status)
      | comp == component = (comp, ComponentModified)
      | otherwise = (comp, status)

-- | Replace a component in the platform configuration.
-- If the old component is @Nothing@, this is equivalent to adding the new component.
-- Otherwise, the old component is removed and the new one is added.
replaceComponent :: PlatformConfigurationV2 -> Maybe ComponentIdentifierV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
replaceComponent config Nothing newComp = addComponent config newComp
replaceComponent config (Just oldComp) newComp =
  addComponent (removeComponent config oldComp) newComp

-- | Update a component's status to 'ComponentModified' in the platform configuration.
updateComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
updateComponent config component =
  config {pcv2Components = map updateStatus (pcv2Components config)}
  where
    updateStatus (comp, status)
      | comp == component = (comp, ComponentModified)
      | otherwise = (comp, status)

-- | ASN.1 serialization for 'DeltaOperation'. Encodes as an INTEGER (0..4).
instance ASN1Object DeltaOperation where
  toASN1 op xs = IntVal (fromIntegral $ fromEnum op) : xs
  fromASN1 (IntVal n : xs)
    | n >= 0 && n <= 4 = Right (toEnum (fromIntegral n), xs)
    | otherwise = Left "DeltaOperation: Invalid enum value"
  fromASN1 _ = Left "DeltaOperation: Invalid ASN1 structure"

-- | ASN.1 serialization for 'ChangeType'. Standard types encode as INTEGER (0..8);
-- 'ChangeOther' encodes as INTEGER 99 followed by an OctetString description.
instance ASN1Object ChangeType where
  toASN1 ct xs = case ct of
    ChangeHardwareAddition -> IntVal 0 : xs
    ChangeHardwareRemoval -> IntVal 1 : xs
    ChangeHardwareReplacement -> IntVal 2 : xs
    ChangeFirmwareUpdate -> IntVal 3 : xs
    ChangeSoftwareInstallation -> IntVal 4 : xs
    ChangeSoftwareRemoval -> IntVal 5 : xs
    ChangeConfigurationUpdate -> IntVal 6 : xs
    ChangeSecurityUpdate -> IntVal 7 : xs
    ChangeMaintenance -> IntVal 8 : xs
    ChangeOther desc -> [IntVal 99, OctetString desc] ++ xs

  fromASN1 (IntVal 99 : OctetString desc : xs) = Right (ChangeOther desc, xs)
  fromASN1 (IntVal n : xs) = case n of
    0 -> Right (ChangeHardwareAddition, xs)
    1 -> Right (ChangeHardwareRemoval, xs)
    2 -> Right (ChangeHardwareReplacement, xs)
    3 -> Right (ChangeFirmwareUpdate, xs)
    4 -> Right (ChangeSoftwareInstallation, xs)
    5 -> Right (ChangeSoftwareRemoval, xs)
    6 -> Right (ChangeConfigurationUpdate, xs)
    7 -> Right (ChangeSecurityUpdate, xs)
    8 -> Right (ChangeMaintenance, xs)
    _ -> Left "ChangeType: Invalid enum value"
  fromASN1 _ = Left "ChangeType: Invalid ASN1 structure"
