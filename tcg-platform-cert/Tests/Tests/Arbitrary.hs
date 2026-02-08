{-# LANGUAGE FlexibleInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- |
-- Module      : Tests.Arbitrary
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Library
-- Stability   : experimental
-- Portability : unknown
--
-- QuickCheck Arbitrary instances for TCG Platform Certificate types.
-- These instances generate meaningful test data for property-based testing.

module Tests.Arbitrary where

import Test.QuickCheck
import qualified Data.ByteString.Char8 as B
import Data.X509.TCG.Platform
import Data.X509.TCG.Component
import Data.X509.TCG.Delta
import Data.X509.TCG.Attributes()
import Data.X509.TCG (TBBSecurityAssertions(..), ComponentConfigV2(..))

-- * Helper generators

-- | Generate a non-empty ByteString suitable for identifiers
genIdentifier :: Gen B.ByteString
genIdentifier = B.pack <$> listOf1 (choose ('A', 'Z'))

-- | Generate a serial number ByteString
genSerial :: Gen B.ByteString
genSerial = B.pack <$> listOf1 (choose ('0', '9'))

-- | Generate a version string
genVersion :: Gen B.ByteString
genVersion = do
  major <- choose (1, 9) :: Gen Int
  minor <- choose (0, 9) :: Gen Int
  return $ B.pack $ show major ++ "." ++ show minor

-- * Platform Certificate Types

instance Arbitrary PlatformInfo where
  arbitrary = PlatformInfo
    <$> genIdentifier  -- manufacturer
    <*> genIdentifier  -- model  
    <*> genSerial      -- serial
    <*> genVersion     -- version

instance Arbitrary TPMVersion where
  arbitrary = TPMVersion
    <$> choose (1, 2)      -- major
    <*> choose (0, 9)      -- minor
    <*> choose (1, 9)      -- revMajor
    <*> choose (0, 99)     -- revMinor

instance Arbitrary TPMSpecification where
  arbitrary = TPMSpecification
    <$> genVersion           -- family
    <*> choose (100, 200)    -- level
    <*> choose (1, 10)       -- revision

instance Arbitrary TPMInfo where
  arbitrary = TPMInfo
    <$> genIdentifier      -- model
    <*> arbitrary          -- version
    <*> arbitrary          -- specification

instance Arbitrary ComponentStatus where
  arbitrary = elements [ComponentAdded, ComponentModified, ComponentRemoved]

instance Arbitrary PlatformConfiguration where
  arbitrary = PlatformConfiguration
    <$> genIdentifier      -- manufacturer
    <*> genIdentifier      -- model
    <*> genVersion         -- version
    <*> genSerial          -- serial
    <*> listOf arbitrary   -- components

instance Arbitrary PlatformConfigurationV2 where
  arbitrary = PlatformConfigurationV2
    <$> genIdentifier      -- manufacturer
    <*> genIdentifier      -- model
    <*> genVersion         -- version
    <*> genSerial          -- serial
    <*> listOf ((,) <$> arbitrary <*> arbitrary)  -- components with status

-- * Component Types

instance Arbitrary ComponentClass where
  arbitrary = elements
    [ ComponentMotherboard, ComponentCPU, ComponentMemory, ComponentHardDrive
    , ComponentNetworkInterface, ComponentGraphicsCard, ComponentSoundCard
    , ComponentOpticalDrive, ComponentKeyboard, ComponentMouse, ComponentDisplay
    , ComponentSpeaker, ComponentMicrophone, ComponentCamera, ComponentTouchscreen
    , ComponentFingerprint, ComponentBluetooth, ComponentWifi, ComponentEthernet
    , ComponentUSB, ComponentFireWire, ComponentSCSI, ComponentIDE
    ]

instance Arbitrary ComponentAddressType where
  arbitrary = elements
    [ AddressPCI, AddressUSB, AddressSATA, AddressI2C
    , AddressSPI, AddressMAC, AddressLogical
    ]

instance Arbitrary ComponentAddress where
  arbitrary = ComponentAddress
    <$> arbitrary          -- addressType
    <*> genIdentifier      -- address

instance Arbitrary ComponentIdentifier where
  arbitrary = ComponentIdentifier
    <$> genIdentifier      -- manufacturer
    <*> genIdentifier      -- model
    <*> oneof [pure Nothing, Just <$> genSerial]      -- serial
    <*> oneof [pure Nothing, Just <$> genVersion]     -- revision
    <*> oneof [pure Nothing, Just <$> genSerial]      -- manufacturerSerial
    <*> oneof [pure Nothing, Just <$> genVersion]     -- manufacturerRevision

instance Arbitrary ComponentIdentifierV2 where
  arbitrary = ComponentIdentifierV2
    <$> genIdentifier      -- manufacturer
    <*> genIdentifier      -- model
    <*> oneof [pure Nothing, Just <$> genSerial]      -- serial
    <*> oneof [pure Nothing, Just <$> genVersion]     -- revision
    <*> oneof [pure Nothing, Just <$> genSerial]      -- manufacturerSerial
    <*> oneof [pure Nothing, Just <$> genVersion]     -- manufacturerRevision
    <*> arbitrary          -- componentClass
    <*> oneof [pure Nothing, Just <$> arbitrary]      -- componentAddress

-- * Delta Types

instance Arbitrary DeltaOperation where
  arbitrary = elements [DeltaAdd, DeltaRemove, DeltaModify, DeltaReplace, DeltaUpdate]

instance Arbitrary ChangeType where
  arbitrary = elements
    [ ChangeHardwareAddition, ChangeHardwareRemoval, ChangeHardwareReplacement
    , ChangeFirmwareUpdate, ChangeSoftwareInstallation, ChangeSoftwareRemoval
    , ChangeConfigurationUpdate, ChangeSecurityUpdate, ChangeMaintenance
    ]

instance Arbitrary ChangeMetadata where
  arbitrary = ChangeMetadata
    <$> oneof [pure Nothing, Just <$> genIdentifier]  -- initiator
    <*> oneof [pure Nothing, Just <$> genIdentifier]  -- approver
    <*> oneof [pure Nothing, Just <$> genIdentifier]  -- changeTicket
    <*> oneof [pure Nothing, Just <$> genIdentifier]  -- rollbackInfo
    <*> listOf ((,) <$> genIdentifier <*> genIdentifier)  -- additionalInfo

-- * Extended TCG Types (IWG v1.1)

-- | Generate a short IA5String (ASCII) bytestring
genIA5String :: Gen B.ByteString
genIA5String = B.pack <$> listOf1 (choose ('0', '9'))

instance Arbitrary TBBSecurityAssertions where
  arbitrary = do
    ver     <- elements [0, 1]
    ccVer   <- oneof [pure Nothing, Just <$> genIA5String]
    eal     <- oneof [pure Nothing, Just <$> choose (1, 7)]
    evalSt  <- oneof [pure Nothing, Just <$> choose (0, 2)]
    plus'   <- oneof [pure Nothing, Just <$> arbitrary]
    sof     <- oneof [pure Nothing, Just <$> choose (0, 2)]
    fipsVer <- oneof [pure Nothing, Just <$> genIA5String]
    fipsLvl <- oneof [pure Nothing, Just <$> choose (1, 4)]
    fipsP   <- oneof [pure Nothing, Just <$> arbitrary]
    rtm     <- oneof [pure Nothing, Just <$> choose (0, 3)]
    iso     <- oneof [pure Nothing, Just <$> arbitrary]
    return TBBSecurityAssertions
      { tbbVersion              = ver
      , tbbCCVersion            = ccVer
      , tbbEvalAssuranceLevel   = eal
      , tbbEvalStatus           = evalSt
      , tbbPlus                 = plus'
      , tbbStrengthOfFunction   = sof
      , tbbProtectionProfileOID = Nothing
      , tbbProtectionProfileURI = Nothing
      , tbbSecurityTargetOID    = Nothing
      , tbbSecurityTargetURI    = Nothing
      , tbbFIPSVersion          = fipsVer
      , tbbFIPSSecurityLevel    = fipsLvl
      , tbbFIPSPlus             = fipsP
      , tbbRTMType              = rtm
      , tbbISO9000Certified     = iso
      , tbbISO9000URI           = Nothing
      }

instance Arbitrary ComponentConfigV2 where
  arbitrary = do
    cls   <- B.pack <$> vectorOf 4 arbitrary
    mfg   <- genIdentifier
    mdl   <- genIdentifier
    ser   <- oneof [pure Nothing, Just <$> genSerial]
    rev'  <- oneof [pure Nothing, Just <$> genVersion]
    fr    <- oneof [pure Nothing, Just <$> arbitrary]
    st    <- oneof [pure Nothing, Just <$> arbitrary]
    return ComponentConfigV2
      { ccv2Class           = cls
      , ccv2Manufacturer    = mfg
      , ccv2Model           = mdl
      , ccv2Serial          = ser
      , ccv2Revision        = rev'
      , ccv2ManufacturerId  = Nothing   -- OID, complex to generate
      , ccv2FieldReplaceable = fr
      , ccv2Addresses       = Nothing   -- complex nested type
      , ccv2PlatformCert    = Nothing   -- Maybe [ASN1], hard to generate
      , ccv2PlatformCertUri = Nothing   -- Maybe [ASN1], hard to generate
      , ccv2Status          = st
      }
