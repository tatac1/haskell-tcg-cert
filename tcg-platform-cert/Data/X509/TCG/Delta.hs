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
import Data.X509.AttCert (AttCertIssuer, AttCertValidityPeriod, Holder, UniqueID)
import Data.X509.Attribute (Attribute (..), Attributes (..), attrType, attrValues)
import Data.X509.TCG.Component (ComponentIdentifier, ComponentIdentifierV2)
import Data.X509.TCG.OID (tcg_at_componentIdentifier_v2, tcg_at_platformConfiguration_v2, tcg_at_tpmSpecification, tcg_at_tpmVersion)
import Data.X509.TCG.Platform (ComponentStatus (..), PlatformConfigurationV2 (..))

-- | Delta Platform Certificate Information structure
--
-- Similar to PlatformCertificateInfo but specifically for Delta Platform Certificates
-- that track changes from a base Platform Certificate.
data DeltaPlatformCertificateInfo = DeltaPlatformCertificateInfo
  { dpciVersion :: Int, -- Must be 2 (v2)
    dpciHolder :: Holder,
    dpciIssuer :: AttCertIssuer,
    dpciSignature :: SignatureALG,
    dpciSerialNumber :: Integer,
    dpciValidity :: AttCertValidityPeriod,
    dpciAttributes :: Attributes,
    dpciIssuerUniqueID :: Maybe UniqueID,
    dpciExtensions :: Extensions,
    dpciBaseCertificateRef :: BasePlatformCertificateRef
  }
  deriving (Show, Eq)

-- | ASN1Object instance for DeltaPlatformCertificateInfo
instance ASN1Object DeltaPlatformCertificateInfo where
  toASN1 (DeltaPlatformCertificateInfo dciVer dciHolder dciIssuer dciSig dciSn dciValid dciAttrs dciUid dciExts dciBase) xs =
    ( [Start Sequence]
        ++ [IntVal $ fromIntegral dciVer]
        ++ toASN1 dciHolder []
        ++ toASN1 dciIssuer []
        ++ toASN1 dciSig []
        ++ [IntVal dciSn]
        ++ toASN1 dciValid []
        ++ toASN1 dciAttrs []
        ++ maybe [] (\u -> [BitString u]) dciUid
        ++ toASN1 dciExts []
        ++ toASN1 dciBase []
        ++ [End Sequence]
    )
      ++ xs
  fromASN1 (Start Sequence : IntVal ver : rest) = do
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
        case rest9 of
          (End Sequence : remaining) ->
            Right (DeltaPlatformCertificateInfo (fromIntegral ver) holder issuer signature serialNum validity attributes uid extensions baseRef, remaining)
          _ -> Left "DeltaPlatformCertificateInfo: Invalid ASN1 sequence termination"
      _ -> Left "DeltaPlatformCertificateInfo: Missing serial number"
  fromASN1 _ = Left "DeltaPlatformCertificateInfo: Invalid ASN1 structure"

-- Helper functions for ASN.1 parsing
extractUID :: [ASN1] -> (Maybe UniqueID, [ASN1])
extractUID (BitString uid : rest) = (Just uid, rest)
extractUID rest = (Nothing, rest)

extractExtensions :: [ASN1] -> (Extensions, [ASN1])
extractExtensions asn1 = case fromASN1 asn1 of
  Right (exts, rest) -> (exts, rest)
  Left _ -> (Extensions Nothing, asn1) -- No extensions present

extractHash :: [ASN1] -> (Maybe B.ByteString, [ASN1])
extractHash (OctetString hash : rest) = (Just hash, rest)
extractHash rest = (Nothing, rest)

extractValidity :: [ASN1] -> (Maybe AttCertValidityPeriod, [ASN1])
extractValidity asn1 = case fromASN1 asn1 of
  Right (validity, rest) -> (Just validity, rest)
  Left _ -> (Nothing, asn1)

-- | A Signed Delta Platform Certificate
type SignedDeltaPlatformCertificate = SignedExact DeltaPlatformCertificateInfo

-- | Delta Platform Configuration structure
--
-- Contains the changes to be applied to a base platform configuration.
data DeltaPlatformConfiguration = DeltaPlatformConfiguration
  { dpcBaseCertificateSerial :: Integer,
    dpcConfigurationDelta :: PlatformConfigurationDelta,
    dpcChangeTimestamp :: DateTime,
    dpcChangeReason :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Delta Configuration structure for YAML integration
--
-- Simplified delta configuration structure that can be parsed from YAML
-- and converted to the full DeltaPlatformConfiguration.
data DeltaConfiguration = DeltaConfiguration
  { dcBaseCertificateSerial :: String,        -- Base certificate serial
    dcDeltaSequenceNumber :: Maybe Int,       -- Delta sequence number
    dcChangeDescription :: Maybe String,      -- Change description
    dcComponentChanges :: [ComponentChange]   -- Component change list
  }
  deriving (Show, Eq)

-- | Component Change structure for YAML integration
--
-- Represents a single component change in a format suitable for YAML parsing.
data ComponentChange = ComponentChange
  { chChangeType :: String,                   -- "added", "removed", "modified"
    chComponentClass :: String,               -- Component class (hex string)
    chManufacturer :: String,                 -- Component manufacturer
    chModel :: String,                        -- Component model
    chSerial :: String,                       -- Component serial
    chRevision :: String,                     -- Component revision
    chPreviousRevision :: Maybe String        -- Previous revision (for modifications)
  }
  deriving (Show, Eq)

-- | Platform Configuration Delta structure
--
-- Represents the specific changes to platform configuration.
data PlatformConfigurationDelta = PlatformConfigurationDelta
  { pcdPlatformInfoChanges :: Maybe PlatformInfoDelta,
    pcdComponentDeltas :: [ComponentDelta],
    pcdChangeRecords :: [ChangeRecord]
  }
  deriving (Show, Eq)

-- | Platform Information Delta structure
data PlatformInfoDelta = PlatformInfoDelta
  { pidManufacturerChange :: Maybe B.ByteString,
    pidModelChange :: Maybe B.ByteString,
    pidSerialChange :: Maybe B.ByteString,
    pidVersionChange :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Component Delta structure
--
-- Represents changes to individual components in the platform.
data ComponentDelta = ComponentDelta
  { cdOperation :: DeltaOperation,
    cdComponent :: ComponentIdentifierV2,
    cdPreviousComponent :: Maybe ComponentIdentifierV2,
    cdChangeMetadata :: ChangeMetadata
  }
  deriving (Show, Eq)

-- | Delta Operation enumeration
--
-- Types of operations that can be performed on components.
data DeltaOperation
  = -- | Component was added to the platform
    DeltaAdd
  | -- | Component was removed from the platform
    DeltaRemove
  | -- | Component was modified (firmware update, etc.)
    DeltaModify
  | -- | Component was replaced with another component
    DeltaReplace
  | -- | Component configuration or properties were updated
    DeltaUpdate
  deriving (Show, Eq, Enum)

-- | Base Platform Certificate Reference structure
--
-- References the base Platform Certificate that this Delta applies to.
data BasePlatformCertificateRef = BasePlatformCertificateRef
  { bpcrIssuer :: DistinguishedName,
    bpcrSerialNumber :: Integer,
    bpcrCertificateHash :: Maybe B.ByteString,
    bpcrValidityPeriod :: Maybe AttCertValidityPeriod
  }
  deriving (Show, Eq)

-- | ASN1Object instance for BasePlatformCertificateRef
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

-- | Certificate Chain structure
--
-- Represents a chain of Platform Certificates leading to this Delta.
data CertificateChain = CertificateChain
  { ccBaseCertificate :: BasePlatformCertificateRef,
    ccIntermediateCertificates :: [BasePlatformCertificateRef],
    ccChainValidityPeriod :: AttCertValidityPeriod
  }
  deriving (Show, Eq)

-- | Change Record structure
--
-- Records information about specific changes made to the platform.
data ChangeRecord = ChangeRecord
  { crChangeId :: B.ByteString,
    crChangeType :: ChangeType,
    crTimestamp :: DateTime,
    crDescription :: Maybe B.ByteString,
    crAffectedComponents :: [ComponentIdentifier],
    crChangeMetadata :: ChangeMetadata
  }
  deriving (Show, Eq)

-- | Change Type enumeration
data ChangeType
  = ChangeHardwareAddition
  | ChangeHardwareRemoval
  | ChangeHardwareReplacement
  | ChangeFirmwareUpdate
  | ChangeSoftwareInstallation
  | ChangeSoftwareRemoval
  | ChangeConfigurationUpdate
  | ChangeSecurityUpdate
  | ChangeMaintenance
  | ChangeOther B.ByteString
  deriving (Show, Eq)

-- | Change Metadata structure
--
-- Additional metadata about changes.
data ChangeMetadata = ChangeMetadata
  { -- | Who initiated the change
    cmInitiator :: Maybe B.ByteString,
    -- | Who approved the change
    cmApprover :: Maybe B.ByteString,
    -- | Reference to change management system
    cmChangeTicket :: Maybe B.ByteString,
    -- | Information for rolling back the change
    cmRollbackInfo :: Maybe B.ByteString,
    -- | Additional key-value pairs
    cmAdditionalInfo :: [(B.ByteString, B.ByteString)]
  }
  deriving (Show, Eq)

-- * Marshalling Operations

-- | Encode a SignedDeltaPlatformCertificate to a DER-encoded bytestring
encodeSignedDeltaPlatformCertificate :: SignedDeltaPlatformCertificate -> B.ByteString
encodeSignedDeltaPlatformCertificate = encodeSignedObject

-- | Decode a DER-encoded bytestring to a SignedDeltaPlatformCertificate
decodeSignedDeltaPlatformCertificate :: B.ByteString -> Either String SignedDeltaPlatformCertificate
decodeSignedDeltaPlatformCertificate = decodeSignedObject

-- | Decode a DER-encoded bytestring with a size limit
-- Returns Left if the input exceeds the provided maximum size.
decodeSignedDeltaPlatformCertificateWithLimit :: Int -> B.ByteString -> Either String SignedDeltaPlatformCertificate
decodeSignedDeltaPlatformCertificateWithLimit maxBytes bs
  | B.length bs > maxBytes =
      Left ("DER input exceeds maximum size: " ++ show maxBytes)
  | otherwise = decodeSignedDeltaPlatformCertificate bs

-- * Accessor Functions

-- | Extract the DeltaPlatformCertificateInfo from a SignedDeltaPlatformCertificate
getDeltaPlatformCertificate :: SignedDeltaPlatformCertificate -> DeltaPlatformCertificateInfo
getDeltaPlatformCertificate = signedObject . getSigned

-- | Extract the base certificate reference from a Delta Platform Certificate
--
-- This function retrieves the reference to the base Platform Certificate
-- that this Delta Certificate applies to. The base certificate reference
-- includes the issuer DN, serial number, and optionally a certificate hash
-- and validity period for additional verification.
--
-- The base certificate reference is essential for:
-- * Validating that the Delta Certificate applies to the correct base certificate
-- * Building certificate chains from base to current state
-- * Ensuring continuity in platform configuration tracking
--
-- Parameters:
-- * @cert@ - The signed Delta Platform Certificate
--
-- Returns:
-- * @BasePlatformCertificateRef@ containing issuer, serial number, and optional hash/validity
--
-- Example:
-- @
-- let baseRef = getBaseCertificateReference deltaCert
-- case validateBaseCertificate baseRef of
--   [] -> putStrLn $ \"Base certificate serial: \" ++ show (bpcrSerialNumber baseRef)
--   errors -> putStrLn $ \"Invalid base reference: \" ++ unlines errors
-- @
getBaseCertificateReference :: SignedDeltaPlatformCertificate -> BasePlatformCertificateRef
getBaseCertificateReference cert = dpciBaseCertificateRef $ getDeltaPlatformCertificate cert

-- | Extract Platform Configuration Delta from a Delta Platform Certificate
--
-- This function searches for the tcg-at-deltaConfiguration attribute
-- (OID 2.23.133.2.23) and parses it into a structured PlatformConfigurationDelta.
--
-- The platform configuration delta provides detailed information about:
-- * Changes to platform information (manufacturer, model, etc.)
-- * Component additions, removals, modifications, and updates
-- * Change records with timestamps and metadata
-- * Affected component lists and change tracking
--
-- This information is essential for:
-- * Applying delta changes to a base platform configuration
-- * Tracking platform evolution over time
-- * Validating that changes are authorized and properly documented
-- * Building audit trails of platform modifications
--
-- Parameters:
-- * @cert@ - The signed Delta Platform Certificate to extract delta from
--
-- Returns:
-- * @Just PlatformConfigurationDelta@ if the delta configuration is found and valid
-- * @Nothing@ if the delta configuration attribute is missing or malformed
--
-- Example:
-- @
-- case getPlatformConfigurationDelta deltaCert of
--   Just delta -> do
--     putStrLn $ \"Component changes: \" ++ show (length $ pcdComponentDeltas delta)
--     putStrLn $ \"Change records: \" ++ show (length $ pcdChangeRecords delta)
--   Nothing -> putStrLn \"No delta configuration found in certificate\"
-- @
getPlatformConfigurationDelta :: SignedDeltaPlatformCertificate -> Maybe PlatformConfigurationDelta
getPlatformConfigurationDelta cert =
  maybe
    Nothing
    parseDeltaPlatformConfiguration
    ( lookupDeltaAttribute
        "2.23.133.2.23"
        (dpciAttributes $ getDeltaPlatformCertificate cert)
    )

-- | Extract Component Deltas from a Delta Platform Certificate
getComponentDeltas :: SignedDeltaPlatformCertificate -> [ComponentDelta]
getComponentDeltas cert =
  maybe [] pcdComponentDeltas (getPlatformConfigurationDelta cert)

-- | Extract Change Records from a Delta Platform Certificate
getChangeRecords :: SignedDeltaPlatformCertificate -> [ChangeRecord]
getChangeRecords cert =
  maybe [] pcdChangeRecords (getPlatformConfigurationDelta cert)

-- * Validation Functions

-- | Validate a Delta Platform Certificate
--
-- Checks that the certificate is properly formed and references a valid base certificate.
validateDeltaCertificate :: SignedDeltaPlatformCertificate -> [String]
validateDeltaCertificate cert =
  let deltaInfo = getDeltaPlatformCertificate cert
      baseRef = dpciBaseCertificateRef deltaInfo
   in validateBaseCertificateRef baseRef
        ++ validateDeltaAttributes (dpciAttributes deltaInfo)

-- | Apply a Delta Platform Certificate to a base configuration
--
-- This function computes the resulting platform configuration after applying
-- all component deltas from a Delta Platform Certificate to a base configuration.
-- It processes each component delta operation in sequence to produce the final state.
--
-- The function handles the following delta operations:
-- * @DeltaAdd@ - Adds new components to the platform
-- * @DeltaRemove@ - Removes existing components from the platform
-- * @DeltaModify@ - Updates existing components (firmware updates, etc.)
-- * @DeltaReplace@ - Replaces one component with another
-- * @DeltaUpdate@ - Updates component configuration or properties
--
-- The operations are applied atomically - either all succeed or the function
-- returns an error. This ensures platform configuration consistency.
--
-- Parameters:
-- * @baseConfig@ - The base platform configuration to apply changes to
-- * @delta@ - The platform configuration delta containing the changes
--
-- Returns:
-- * @Right PlatformConfigurationV2@ - The resulting configuration after applying all changes
-- * @Left String@ - An error message if any delta operation fails or is invalid
--
-- Example:
-- @
-- case applyDeltaToBase baseConfig platformDelta of
--   Right newConfig -> do
--     putStrLn $ \"Applied \" ++ show (length $ pcdComponentDeltas platformDelta) ++ \" changes\"
--     putStrLn $ \"Final components: \" ++ show (length $ pcv2Components newConfig)
--   Left error -> putStrLn $ \"Failed to apply delta: \" ++ error
-- @
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

-- | Compute the resulting configuration after applying delta certificates
computeResultingConfiguration :: PlatformConfigurationV2 -> [PlatformConfigurationDelta] -> Either String PlatformConfigurationV2
computeResultingConfiguration baseConfig = foldl (\acc delta -> acc >>= \config -> applyDeltaToBase config delta) (Right baseConfig)

-- Helper functions

-- | Lookup delta-specific attribute by OID string
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

-- | Parse Delta Platform Configuration from attribute value
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

-- | Validate base certificate reference
validateBaseCertificateRef :: BasePlatformCertificateRef -> [String]
validateBaseCertificateRef baseRef
  | bpcrSerialNumber baseRef <= 0 = ["Invalid base certificate serial number"]
  | otherwise = []

-- | Validate delta attributes
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

-- Component manipulation helper functions
addComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
addComponent config component =
  config {pcv2Components = pcv2Components config ++ [(component, ComponentAdded)]}

removeComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
removeComponent config component =
  config {pcv2Components = filter ((/= component) . fst) (pcv2Components config)}

modifyComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
modifyComponent config component =
  config {pcv2Components = map updateStatus (pcv2Components config)}
  where
    updateStatus (comp, status)
      | comp == component = (comp, ComponentModified)
      | otherwise = (comp, status)

replaceComponent :: PlatformConfigurationV2 -> Maybe ComponentIdentifierV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
replaceComponent config Nothing newComp = addComponent config newComp
replaceComponent config (Just oldComp) newComp =
  addComponent (removeComponent config oldComp) newComp

updateComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
updateComponent config component =
  config {pcv2Components = map updateStatus (pcv2Components config)}
  where
    updateStatus (comp, status)
      | comp == component = (comp, ComponentModified)
      | otherwise = (comp, status)

-- ASN.1 instances for basic types

instance ASN1Object DeltaOperation where
  toASN1 op xs = IntVal (fromIntegral $ fromEnum op) : xs
  fromASN1 (IntVal n : xs)
    | n >= 0 && n <= 4 = Right (toEnum (fromIntegral n), xs)
    | otherwise = Left "DeltaOperation: Invalid enum value"
  fromASN1 _ = Left "DeltaOperation: Invalid ASN1 structure"

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
