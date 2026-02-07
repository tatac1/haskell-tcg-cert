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
import Data.ASN1.Types.String (ASN1CharacterString(..), ASN1StringEncoding(..))
import qualified Data.ByteString as B

-- | Component Identifier structure (v1)
--
-- Basic component identification without hierarchical relationships.
data ComponentIdentifier = ComponentIdentifier
  { ciManufacturer :: B.ByteString,
    ciModel :: B.ByteString,
    ciSerial :: Maybe B.ByteString,
    ciRevision :: Maybe B.ByteString,
    ciManufacturerSerial :: Maybe B.ByteString,
    ciManufacturerRevision :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Component Identifier structure (v2)
--
-- Enhanced component identification with class and address information.
data ComponentIdentifierV2 = ComponentIdentifierV2
  { ci2Manufacturer :: B.ByteString,
    ci2Model :: B.ByteString,
    ci2Serial :: Maybe B.ByteString,
    ci2Revision :: Maybe B.ByteString,
    ci2ManufacturerSerial :: Maybe B.ByteString,
    ci2ManufacturerRevision :: Maybe B.ByteString,
    ci2ComponentClass :: ComponentClass,
    ci2ComponentAddress :: Maybe ComponentAddress
  }
  deriving (Show, Eq)

-- | Component Class enumeration
--
-- Defines the type/category of a platform component.
data ComponentClass
  = ComponentMotherboard
  | ComponentCPU
  | ComponentMemory
  | ComponentHardDrive
  | ComponentNetworkInterface
  | ComponentGraphicsCard
  | ComponentSoundCard
  | ComponentOpticalDrive
  | ComponentKeyboard
  | ComponentMouse
  | ComponentDisplay
  | ComponentSpeaker
  | ComponentMicrophone
  | ComponentCamera
  | ComponentTouchscreen
  | ComponentFingerprint
  | ComponentBluetooth
  | ComponentWifi
  | ComponentEthernet
  | ComponentUSB
  | ComponentFireWire
  | ComponentSCSI
  | ComponentIDE
  | -- | For custom component classes
    ComponentOther OID
  deriving (Show, Eq)

-- | Component Address structure
--
-- Physical or logical address of a component within the platform.
data ComponentAddress = ComponentAddress
  { caAddressType :: ComponentAddressType,
    caAddress :: B.ByteString
  }
  deriving (Show, Eq)

-- | Component Address Type enumeration
data ComponentAddressType
  = AddressPCI
  | AddressUSB
  | AddressSATA
  | AddressI2C
  | AddressSPI
  | AddressMAC
  | AddressLogical
  | AddressOther B.ByteString
  deriving (Show, Eq)

-- | Component Hierarchy structure
--
-- Represents the hierarchical relationship between components.
data ComponentHierarchy = ComponentHierarchy
  { chRootComponents :: [ComponentReference],
    chComponentTree :: ComponentTree
  }
  deriving (Show, Eq)

-- | Component Tree structure
--
-- Tree representation of component relationships.
data ComponentTree = ComponentTree
  { ctComponent :: ComponentIdentifierV2,
    ctChildren :: [ComponentTree],
    ctProperties :: ComponentProperties
  }
  deriving (Show, Eq)

-- | Component Reference structure
--
-- Reference to a component in the hierarchy.
data ComponentReference = ComponentReference
  { crCertificateSerial :: Integer,
    crComponentIndex :: Int,
    crComponentIdentifier :: ComponentIdentifierV2
  }
  deriving (Show, Eq)

-- | Component Properties structure
--
-- Additional properties and metadata for components.
data ComponentProperties = ComponentProperties
  { cpMeasurements :: [ComponentMeasurement],
    cpDescriptor :: Maybe ComponentDescriptor,
    cpRelations :: [ComponentRelation]
  }
  deriving (Show, Eq)

-- | Component Measurement structure
--
-- Cryptographic measurements of component state.
data ComponentMeasurement = ComponentMeasurement
  { cmDigestAlgorithm :: OID,
    cmDigestValue :: B.ByteString,
    cmMeasurementType :: MeasurementType
  }
  deriving (Show, Eq)

-- | Measurement Type enumeration
data MeasurementType
  = MeasurementFirmware
  | MeasurementSoftware
  | MeasurementConfiguration
  | MeasurementIdentity
  | MeasurementOther B.ByteString
  deriving (Show, Eq)

-- | Component Descriptor structure
--
-- Human-readable description and metadata.
data ComponentDescriptor = ComponentDescriptor
  { cdDescription :: B.ByteString,
    cdVendorInfo :: Maybe B.ByteString,
    -- | Key-value pairs
    cdProperties :: [(B.ByteString, B.ByteString)]
  }
  deriving (Show, Eq)

-- | Component Relation structure
--
-- Describes relationships between components.
data ComponentRelation = ComponentRelation
  { crRelationType :: ComponentRelationType,
    crTargetComponent :: ComponentReference,
    crRelationProperties :: [(B.ByteString, B.ByteString)]
  }
  deriving (Show, Eq)

-- | Component Relation Type enumeration
data ComponentRelationType
  = RelationParentOf
  | RelationChildOf
  | RelationDependsOn
  | RelationConflictsWith
  | RelationReplaces
  | RelationReplacedBy
  | RelationOther B.ByteString
  deriving (Show, Eq)

-- | Component Dependency structure
--
-- Describes dependency relationships between components.
data ComponentDependency = ComponentDependency
  { cdDependentComponent :: ComponentReference,
    cdRequiredComponent :: ComponentReference,
    cdDependencyType :: DependencyType,
    cdVersionConstraints :: Maybe B.ByteString
  }
  deriving (Show, Eq)

-- | Dependency Type enumeration
data DependencyType
  = DependencyRequired
  | DependencyOptional
  | DependencyConditional
  | DependencyIncompatible
  deriving (Show, Eq, Enum)

-- * Utility Functions

-- | Check if a component belongs to a specific class
isComponentClass :: ComponentClass -> ComponentIdentifierV2 -> Bool
isComponentClass targetClass component = ci2ComponentClass component == targetClass

-- | Get component by address from a component hierarchy
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

-- | Build a component tree from a list of components
buildComponentTree :: [ComponentIdentifierV2] -> ComponentTree
buildComponentTree components =
  case components of
    [] -> error "Cannot build tree from empty component list"
    (root : _) -> ComponentTree root [] defaultProperties
  where
    defaultProperties = ComponentProperties [] Nothing []

-- | Validate component hierarchy for consistency
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

-- ASN.1 instances

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
  fromASN1 (Start Sequence : mfg : mdl : rest) = do
    manufacturer <- parseComponentString "ComponentIdentifier manufacturer" mfg
    model <- parseComponentString "ComponentIdentifier model" mdl
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

-- Helper function to parse ComponentIdentifierV2 optional fields
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

parseOptionalStringValue :: ASN1 -> Maybe B.ByteString
parseOptionalStringValue Null = Nothing
parseOptionalStringValue (OctetString bs) = Just bs
parseOptionalStringValue (ASN1String (ASN1CharacterString _ bs)) = Just bs
parseOptionalStringValue _ = Nothing

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
