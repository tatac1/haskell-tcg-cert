{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Data.X509.TCG.Component
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG Component identification and hierarchy structures.
--
-- This module implements component identification as defined in the IWG Platform
-- Certificate Profile v1.1. Components represent hardware and software elements
-- that make up a platform configuration.
module Data.X509.TCG.Component
  ( -- * Component Identification
    ComponentIdentifier (..),
    ComponentIdentifierV2 (..),
    ComponentClass (..),
    ComponentAddress (..),
    ComponentAddressType (..),

    -- * Component Hierarchy
    ComponentHierarchy (..),
    ComponentTree (..),
    ComponentReference (..),

    -- * Component Properties
    ComponentProperties (..),
    ComponentMeasurement (..),
    ComponentDescriptor (..),

    -- * Component Relationships
    ComponentRelation (..),
    ComponentDependency (..),

    -- * Utility Functions
    isComponentClass,
    getComponentByAddress,
    buildComponentTree,
    validateComponentHierarchy,
  )
where

import Data.ASN1.Types
import qualified Data.ByteString as B

-- | Component Identifier structure (v1)
--
-- Basic component identification without hierarchical relationships.
data ComponentIdentifier = ComponentIdentifier
  { ciManufacturer :: B.ByteString,
    -- ^ Manufacturer name (UTF8String).
    ciModel :: B.ByteString,
    -- ^ Model identifier (UTF8String).
    ciSerial :: Maybe B.ByteString,
    -- ^ Serial number, if available.
    ciRevision :: Maybe B.ByteString,
    -- ^ Hardware revision, if available.
    ciManufacturerSerial :: Maybe B.ByteString,
    -- ^ Manufacturer-assigned serial number, if available.
    ciManufacturerRevision :: Maybe B.ByteString
    -- ^ Manufacturer-assigned revision, if available.
  }
  deriving (Show, Eq)

-- | Component Identifier structure (v2)
--
-- Enhanced component identification with class and address information.
data ComponentIdentifierV2 = ComponentIdentifierV2
  { ci2Manufacturer :: B.ByteString,
    -- ^ Manufacturer name (UTF8String).
    ci2Model :: B.ByteString,
    -- ^ Model identifier (UTF8String).
    ci2Serial :: Maybe B.ByteString,
    -- ^ Serial number, if available.
    ci2Revision :: Maybe B.ByteString,
    -- ^ Hardware revision, if available.
    ci2ManufacturerSerial :: Maybe B.ByteString,
    -- ^ Manufacturer-assigned serial number, if available.
    ci2ManufacturerRevision :: Maybe B.ByteString,
    -- ^ Manufacturer-assigned revision, if available.
    ci2ComponentClass :: ComponentClass,
    -- ^ Component class category (see TCG PCP v2.1, Section 6.1).
    ci2ComponentAddress :: Maybe ComponentAddress
    -- ^ Physical or logical address within the platform, if available.
  }
  deriving (Show, Eq)

-- | Component Class enumeration
--
-- Defines the type/category of a platform component.
data ComponentClass
  = ComponentMotherboard
  -- ^ Motherboard or mainboard (value 1).
  | ComponentCPU
  -- ^ Central processing unit (value 2).
  | ComponentMemory
  -- ^ RAM or other memory module (value 3).
  | ComponentHardDrive
  -- ^ Hard disk drive or solid-state drive (value 4).
  | ComponentNetworkInterface
  -- ^ Network interface controller (value 5).
  | ComponentGraphicsCard
  -- ^ Graphics or video adapter (value 6).
  | ComponentSoundCard
  -- ^ Sound or audio adapter (value 7).
  | ComponentOpticalDrive
  -- ^ Optical disc drive (value 8).
  | ComponentKeyboard
  -- ^ Keyboard input device (value 9).
  | ComponentMouse
  -- ^ Mouse or pointing device (value 10).
  | ComponentDisplay
  -- ^ Display or monitor (value 11).
  | ComponentSpeaker
  -- ^ Speaker or audio output device (value 12).
  | ComponentMicrophone
  -- ^ Microphone or audio input device (value 13).
  | ComponentCamera
  -- ^ Camera or imaging device (value 14).
  | ComponentTouchscreen
  -- ^ Touchscreen input device (value 15).
  | ComponentFingerprint
  -- ^ Fingerprint reader or biometric sensor (value 16).
  | ComponentBluetooth
  -- ^ Bluetooth wireless interface (value 21).
  | ComponentWifi
  -- ^ Wi-Fi wireless network interface (value 22).
  | ComponentEthernet
  -- ^ Wired Ethernet network interface (value 23).
  | ComponentUSB
  -- ^ USB bus controller (value 31).
  | ComponentFireWire
  -- ^ IEEE 1394 FireWire bus controller (value 32).
  | ComponentSCSI
  -- ^ SCSI bus controller (value 33).
  | ComponentIDE
  -- ^ IDE\/ATA bus controller (value 34).
  | ComponentOther OID
  -- ^ Custom component class identified by OID.
  deriving (Show, Eq)

-- | Component Address structure
--
-- Physical or logical address of a component within the platform.
data ComponentAddress = ComponentAddress
  { caAddressType :: ComponentAddressType,
    -- ^ The type of address (PCI, USB, MAC, etc.).
    caAddress :: B.ByteString
    -- ^ The raw address value as an octet string.
  }
  deriving (Show, Eq)

-- | Component Address Type enumeration
data ComponentAddressType
  = AddressPCI
  -- ^ PCI bus address (value 1).
  | AddressUSB
  -- ^ USB bus address (value 2).
  | AddressSATA
  -- ^ SATA bus address (value 3).
  | AddressI2C
  -- ^ I2C bus address (value 4).
  | AddressSPI
  -- ^ SPI bus address (value 5).
  | AddressMAC
  -- ^ MAC (Ethernet hardware) address (value 6).
  | AddressLogical
  -- ^ Logical or software-defined address (value 7).
  | AddressOther B.ByteString
  -- ^ Other address type with a custom descriptor (value 99).
  deriving (Show, Eq)

-- | Component Hierarchy structure
--
-- Represents the hierarchical relationship between components.
data ComponentHierarchy = ComponentHierarchy
  { chRootComponents :: [ComponentReference],
    -- ^ Top-level component references at the root of the hierarchy.
    chComponentTree :: ComponentTree
    -- ^ Tree structure describing component parent-child relationships.
  }
  deriving (Show, Eq)

-- | Component Tree structure
--
-- Tree representation of component relationships.
data ComponentTree = ComponentTree
  { ctComponent :: ComponentIdentifierV2,
    -- ^ The component at this tree node.
    ctChildren :: [ComponentTree],
    -- ^ Child component subtrees.
    ctProperties :: ComponentProperties
    -- ^ Properties associated with this component node.
  }
  deriving (Show, Eq)

-- | Component Reference structure
--
-- Reference to a component in the hierarchy.
data ComponentReference = ComponentReference
  { crCertificateSerial :: Integer,
    -- ^ Serial number of the certificate containing this component.
    crComponentIndex :: Int,
    -- ^ Zero-based index of the component within the certificate.
    crComponentIdentifier :: ComponentIdentifierV2
    -- ^ Full component identifier for the referenced component.
  }
  deriving (Show, Eq)

-- | Component Properties structure
--
-- Additional properties and metadata for components.
data ComponentProperties = ComponentProperties
  { cpMeasurements :: [ComponentMeasurement],
    -- ^ Cryptographic measurements of the component state.
    cpDescriptor :: Maybe ComponentDescriptor,
    -- ^ Human-readable descriptor, if available.
    cpRelations :: [ComponentRelation]
    -- ^ Relationships this component has with other components.
  }
  deriving (Show, Eq)

-- | Component Measurement structure
--
-- Cryptographic measurements of component state.
data ComponentMeasurement = ComponentMeasurement
  { cmDigestAlgorithm :: OID,
    -- ^ OID of the digest algorithm used (e.g. SHA-256).
    cmDigestValue :: B.ByteString,
    -- ^ The digest value (hash) of the measured component.
    cmMeasurementType :: MeasurementType
    -- ^ Category of this measurement.
  }
  deriving (Show, Eq)

-- | Measurement Type enumeration
data MeasurementType
  = MeasurementFirmware
  -- ^ Firmware measurement (e.g. BIOS, UEFI).
  | MeasurementSoftware
  -- ^ Software measurement (e.g. OS loader).
  | MeasurementConfiguration
  -- ^ Configuration data measurement.
  | MeasurementIdentity
  -- ^ Identity or attestation measurement.
  | MeasurementOther B.ByteString
  -- ^ Other measurement type with a custom descriptor.
  deriving (Show, Eq)

-- | Component Descriptor structure
--
-- Human-readable description and metadata.
data ComponentDescriptor = ComponentDescriptor
  { cdDescription :: B.ByteString,
    -- ^ Human-readable description of the component.
    cdVendorInfo :: Maybe B.ByteString,
    -- ^ Vendor-specific information, if available.
    cdProperties :: [(B.ByteString, B.ByteString)]
    -- ^ Key-value pairs of additional component properties.
  }
  deriving (Show, Eq)

-- | Component Relation structure
--
-- Describes relationships between components.
data ComponentRelation = ComponentRelation
  { crRelationType :: ComponentRelationType,
    -- ^ The type of relationship (parent, child, dependency, etc.).
    crTargetComponent :: ComponentReference,
    -- ^ The other component involved in this relationship.
    crRelationProperties :: [(B.ByteString, B.ByteString)]
    -- ^ Key-value pairs of additional relationship metadata.
  }
  deriving (Show, Eq)

-- | Component Relation Type enumeration
data ComponentRelationType
  = RelationParentOf
  -- ^ This component is the parent of the target.
  | RelationChildOf
  -- ^ This component is a child of the target.
  | RelationDependsOn
  -- ^ This component depends on the target.
  | RelationConflictsWith
  -- ^ This component conflicts with the target.
  | RelationReplaces
  -- ^ This component replaces the target.
  | RelationReplacedBy
  -- ^ This component is replaced by the target.
  | RelationOther B.ByteString
  -- ^ Other relationship type with a custom descriptor.
  deriving (Show, Eq)

-- | Component Dependency structure
--
-- Describes dependency relationships between components.
data ComponentDependency = ComponentDependency
  { cdDependentComponent :: ComponentReference,
    -- ^ The component that has the dependency.
    cdRequiredComponent :: ComponentReference,
    -- ^ The component that is depended upon.
    cdDependencyType :: DependencyType,
    -- ^ The nature of the dependency relationship.
    cdVersionConstraints :: Maybe B.ByteString
    -- ^ Version constraint expression, if applicable.
  }
  deriving (Show, Eq)

-- | Dependency Type enumeration
data DependencyType
  = DependencyRequired
  -- ^ The dependent component cannot function without the required component.
  | DependencyOptional
  -- ^ The dependent component can function without the required component.
  | DependencyConditional
  -- ^ The dependency applies only under certain conditions.
  | DependencyIncompatible
  -- ^ The two components are mutually incompatible.
  deriving (Show, Eq, Enum)

-- | Check if a component belongs to a specific class.
isComponentClass :: ComponentClass -> ComponentIdentifierV2 -> Bool
isComponentClass targetClass component = ci2ComponentClass component == targetClass

-- | Get a component by address from a component hierarchy.
getComponentByAddress :: ComponentAddress -> ComponentHierarchy -> Maybe ComponentIdentifierV2
getComponentByAddress addr hierarchy = searchInTree addr (chComponentTree hierarchy)
  where
    searchInTree :: ComponentAddress -> ComponentTree -> Maybe ComponentIdentifierV2
    searchInTree target tree =
      case ci2ComponentAddress (ctComponent tree) of
        Just compAddr | compAddr == target -> Just (ctComponent tree)
        _ -> searchInChildren target (ctChildren tree)

    searchInChildren :: ComponentAddress -> [ComponentTree] -> Maybe ComponentIdentifierV2
    searchInChildren target trees =
      case trees of
        [] -> Nothing
        (t : ts) -> case searchInTree target t of
          Just result -> Just result
          Nothing -> searchInChildren target ts

-- | Build a component tree from a list of components.
-- The first element is used as the root node.
buildComponentTree :: [ComponentIdentifierV2] -> ComponentTree
buildComponentTree components =
  case components of
    [] -> error "Cannot build tree from empty component list"
    (root : _) -> ComponentTree root [] defaultProperties
  where
    defaultProperties = ComponentProperties [] Nothing []

-- | Validate a component hierarchy for consistency.
-- Returns a list of error messages; an empty list indicates a valid hierarchy.
validateComponentHierarchy :: ComponentHierarchy -> [String]
validateComponentHierarchy hierarchy =
  validateTree (chComponentTree hierarchy)
  where
    validateTree :: ComponentTree -> [String]
    validateTree tree =
      validateComponent (ctComponent tree)
        ++ concatMap validateTree (ctChildren tree)

    validateComponent :: ComponentIdentifierV2 -> [String]
    validateComponent component
      | B.null (ci2Manufacturer component) = ["Component missing manufacturer"]
      | B.null (ci2Model component) = ["Component missing model"]
      | otherwise = []

-- $asn1
-- ASN.1 encoding and decoding instances for component types.

instance ASN1Object ComponentIdentifier where
  toASN1 (ComponentIdentifier manufacturer model serial revision mfgSerial mfgRevision) xs =
    [ Start Sequence
    , ASN1String (ASN1CharacterString UTF8 manufacturer)
    , ASN1String (ASN1CharacterString UTF8 model)
    ]
      ++ maybe [] (\s -> [ASN1String (ASN1CharacterString UTF8 s)]) serial
      ++ maybe [] (\r -> [ASN1String (ASN1CharacterString UTF8 r)]) revision
      ++ maybe [] (\ms -> [ASN1String (ASN1CharacterString UTF8 ms)]) mfgSerial
      ++ maybe [] (\mr -> [ASN1String (ASN1CharacterString UTF8 mr)]) mfgRevision
      ++ [End Sequence]
      ++ xs
  fromASN1 (Start Sequence : mfgASN1 : mdlASN1 : rest) = do
    manufacturer <- parseComponentString "ComponentIdentifier manufacturer" mfgASN1
    model <- parseComponentString "ComponentIdentifier model" mdlASN1
    parseOptionalFields rest manufacturer model Nothing Nothing Nothing Nothing
    where
      parseOptionalFields (End Sequence : remaining) mfg mdl ser rev mfgSer mfgRev =
        Right (ComponentIdentifier mfg mdl ser rev mfgSer mfgRev, remaining)
      parseOptionalFields (value : rest') mfg mdl Nothing Nothing Nothing Nothing = do
        v <- parseOptionalString value
        parseOptionalFields rest' mfg mdl v Nothing Nothing Nothing
      parseOptionalFields (value : rest') mfg mdl (Just ser) Nothing Nothing Nothing = do
        v <- parseOptionalString value
        parseOptionalFields rest' mfg mdl (Just ser) v Nothing Nothing
      parseOptionalFields (value : rest') mfg mdl (Just ser) (Just rev) Nothing Nothing = do
        v <- parseOptionalString value
        parseOptionalFields rest' mfg mdl (Just ser) (Just rev) v Nothing
      parseOptionalFields (value : rest') mfg mdl (Just ser) (Just rev) (Just mfgSer) Nothing = do
        v <- parseOptionalString value
        parseOptionalFields rest' mfg mdl (Just ser) (Just rev) (Just mfgSer) v
      parseOptionalFields _ _ _ _ _ _ _ = Left "ComponentIdentifier: Invalid ASN1 structure"
  fromASN1 _ = Left "ComponentIdentifier: Invalid ASN1 structure"

-- | Parse the optional fields of a 'ComponentIdentifierV2' from an ASN.1 stream.
parseComponentIdentifierV2Fields ::
  B.ByteString ->
  B.ByteString ->
  [ASN1] ->
  Either String (ComponentIdentifierV2, [ASN1])
parseComponentIdentifierV2Fields manufacturer model (serialField : revisionField : mfgSerialField : mfgRevisionField : rest) =
  let serial = parseOptionalStringValue serialField
      revision = parseOptionalStringValue revisionField
      mfgSerial = parseOptionalStringValue mfgSerialField
      mfgRevision = parseOptionalStringValue mfgRevisionField
   in do
        (compClass, rest') <- fromASN1 rest
        case rest' of
          End Sequence : xs ->
            Right (ComponentIdentifierV2 manufacturer model serial revision mfgSerial mfgRevision compClass Nothing, xs)
          _ -> do
            (compAddr, rest'') <- fromASN1 rest'
            case rest'' of
              End Sequence : xs ->
                Right (ComponentIdentifierV2 manufacturer model serial revision mfgSerial mfgRevision compClass (Just compAddr), xs)
              _ -> Left "ComponentIdentifierV2: Expected End Sequence"
parseComponentIdentifierV2Fields _ _ _ =
  Left "ComponentIdentifierV2: Expected exactly 4 optional fields (serial, revision, mfgSerial, mfgRevision)"

instance ASN1Object ComponentIdentifierV2 where
  toASN1 (ComponentIdentifierV2 manufacturer model serial revision mfgSerial mfgRevision compClass compAddr) xs =
    [ Start Sequence
    , ASN1String (ASN1CharacterString UTF8 manufacturer)
    , ASN1String (ASN1CharacterString UTF8 model)
    ]
      ++ [maybe Null (ASN1String . ASN1CharacterString UTF8) serial]
      ++ [maybe Null (ASN1String . ASN1CharacterString UTF8) revision]
      ++ [maybe Null (ASN1String . ASN1CharacterString UTF8) mfgSerial]
      ++ [maybe Null (ASN1String . ASN1CharacterString UTF8) mfgRevision]
      ++ toASN1 compClass []
      ++ maybe [] (`toASN1` []) compAddr
      ++ [End Sequence]
      ++ xs
  fromASN1 (Start Sequence : mfg : mdl : xs) = do
    manufacturer <- parseComponentString "ComponentIdentifierV2 manufacturer" mfg
    model <- parseComponentString "ComponentIdentifierV2 model" mdl
    parseComponentIdentifierV2Fields manufacturer model xs
  fromASN1 _ = Left "ComponentIdentifierV2: Expected Start Sequence followed by two UTF8Strings"

-- | Parse a required component string (UTF8String or OctetString).
parseComponentString :: String -> ASN1 -> Either String B.ByteString
parseComponentString _ (OctetString bs) = Right bs
parseComponentString _ (ASN1String (ASN1CharacterString _ bs)) = Right bs
parseComponentString label _ = Left (label ++ ": expected UTF8String")

-- | Try to extract a 'B.ByteString' from an ASN.1 value, returning 'Nothing' for 'Null'.
parseOptionalStringValue :: ASN1 -> Maybe B.ByteString
parseOptionalStringValue Null = Nothing
parseOptionalStringValue (OctetString bs) = Just bs
parseOptionalStringValue (ASN1String (ASN1CharacterString _ bs)) = Just bs
parseOptionalStringValue _ = Nothing

-- | Parse an optional string field, wrapping the result in 'Right'.
parseOptionalString :: ASN1 -> Either String (Maybe B.ByteString)
parseOptionalString v = Right (parseOptionalStringValue v)

instance ASN1Object ComponentClass where
  toASN1 ComponentMotherboard xs = IntVal 1 : xs
  toASN1 ComponentCPU xs = IntVal 2 : xs
  toASN1 ComponentMemory xs = IntVal 3 : xs
  toASN1 ComponentHardDrive xs = IntVal 4 : xs
  toASN1 ComponentNetworkInterface xs = IntVal 5 : xs
  toASN1 ComponentGraphicsCard xs = IntVal 6 : xs
  toASN1 ComponentSoundCard xs = IntVal 7 : xs
  toASN1 ComponentOpticalDrive xs = IntVal 8 : xs
  toASN1 ComponentKeyboard xs = IntVal 9 : xs
  toASN1 ComponentMouse xs = IntVal 10 : xs
  toASN1 ComponentDisplay xs = IntVal 11 : xs
  toASN1 ComponentSpeaker xs = IntVal 12 : xs
  toASN1 ComponentMicrophone xs = IntVal 13 : xs
  toASN1 ComponentCamera xs = IntVal 14 : xs
  toASN1 ComponentTouchscreen xs = IntVal 15 : xs
  toASN1 ComponentFingerprint xs = IntVal 16 : xs
  toASN1 ComponentBluetooth xs = IntVal 21 : xs
  toASN1 ComponentWifi xs = IntVal 22 : xs
  toASN1 ComponentEthernet xs = IntVal 23 : xs
  toASN1 ComponentUSB xs = IntVal 31 : xs
  toASN1 ComponentFireWire xs = IntVal 32 : xs
  toASN1 ComponentSCSI xs = IntVal 33 : xs
  toASN1 ComponentIDE xs = IntVal 34 : xs
  toASN1 (ComponentOther oid) xs = OID oid : xs
  fromASN1 (IntVal n : xs) = case n of
    1 -> Right (ComponentMotherboard, xs)
    2 -> Right (ComponentCPU, xs)
    3 -> Right (ComponentMemory, xs)
    4 -> Right (ComponentHardDrive, xs)
    5 -> Right (ComponentNetworkInterface, xs)
    6 -> Right (ComponentGraphicsCard, xs)
    7 -> Right (ComponentSoundCard, xs)
    8 -> Right (ComponentOpticalDrive, xs)
    9 -> Right (ComponentKeyboard, xs)
    10 -> Right (ComponentMouse, xs)
    11 -> Right (ComponentDisplay, xs)
    12 -> Right (ComponentSpeaker, xs)
    13 -> Right (ComponentMicrophone, xs)
    14 -> Right (ComponentCamera, xs)
    15 -> Right (ComponentTouchscreen, xs)
    16 -> Right (ComponentFingerprint, xs)
    21 -> Right (ComponentBluetooth, xs)
    22 -> Right (ComponentWifi, xs)
    23 -> Right (ComponentEthernet, xs)
    31 -> Right (ComponentUSB, xs)
    32 -> Right (ComponentFireWire, xs)
    33 -> Right (ComponentSCSI, xs)
    34 -> Right (ComponentIDE, xs)
    _ -> Left "ComponentClass: Invalid enum value"
  fromASN1 (OID oid : xs) = Right (ComponentOther oid, xs)
  fromASN1 _ = Left "ComponentClass: Invalid ASN1 structure"

instance ASN1Object ComponentAddress where
  toASN1 (ComponentAddress addrType addr) xs =
    [Start Sequence] ++ toASN1 addrType [] ++ [OctetString addr, End Sequence] ++ xs
  fromASN1 (Start Sequence : xs) = do
    (addrType, xs') <- fromASN1 xs
    case xs' of
      (OctetString addr : End Sequence : xs'') ->
        Right (ComponentAddress addrType addr, xs'')
      _ -> Left "ComponentAddress: Expected OctetString followed by End Sequence"
  fromASN1 _ = Left "ComponentAddress: Expected Start Sequence"

instance ASN1Object ComponentAddressType where
  toASN1 AddressPCI xs = IntVal 1 : xs
  toASN1 AddressUSB xs = IntVal 2 : xs
  toASN1 AddressSATA xs = IntVal 3 : xs
  toASN1 AddressI2C xs = IntVal 4 : xs
  toASN1 AddressSPI xs = IntVal 5 : xs
  toASN1 AddressMAC xs = IntVal 6 : xs
  toASN1 AddressLogical xs = IntVal 7 : xs
  toASN1 (AddressOther desc) xs = [IntVal 99, OctetString desc] ++ xs
  fromASN1 (IntVal 99 : OctetString desc : xs) = Right (AddressOther desc, xs)
  fromASN1 (IntVal n : xs) = case n of
    1 -> Right (AddressPCI, xs)
    2 -> Right (AddressUSB, xs)
    3 -> Right (AddressSATA, xs)
    4 -> Right (AddressI2C, xs)
    5 -> Right (AddressSPI, xs)
    6 -> Right (AddressMAC, xs)
    7 -> Right (AddressLogical, xs)
    _ -> Left "AddressType: Invalid enum value"
  fromASN1 _ = Left "AddressType: Invalid ASN1 structure"
