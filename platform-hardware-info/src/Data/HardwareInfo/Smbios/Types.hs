{-# LANGUAGE DeriveGeneric #-}
-- |
-- Module      : Data.HardwareInfo.Smbios.Types
-- Description : SMBIOS data structure types
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module defines types for representing raw SMBIOS structures
-- as defined in the DMTF SMBIOS Specification.

module Data.HardwareInfo.Smbios.Types
  ( -- * Raw SMBIOS structures
    SmbiosTable(..)
  , SmbiosStructure(..)
  , SmbiosHeader(..)
    -- * SMBIOS Type constants
  , SmbiosType(..)
  , smbiosTypeValue
    -- * Entry point
  , SmbiosEntryPoint(..)
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word8, Word16, Word32)
import GHC.Generics (Generic)

-- | SMBIOS Entry Point information
data SmbiosEntryPoint = SmbiosEntryPoint
  { epMajorVersion :: !Word8
    -- ^ SMBIOS major version
  , epMinorVersion :: !Word8
    -- ^ SMBIOS minor version
  , epRevision     :: !Word8
    -- ^ SMBIOS revision (for 3.0+)
  , epTableLength  :: !Word32
    -- ^ Total length of SMBIOS table
  , epTableAddress :: !Word32
    -- ^ Physical address of SMBIOS table (32-bit entry point)
  , epIs64Bit      :: !Bool
    -- ^ True if 64-bit entry point (_SM3_)
  } deriving (Show, Eq, Generic)

-- | Complete SMBIOS table
data SmbiosTable = SmbiosTable
  { tableEntryPoint :: !SmbiosEntryPoint
    -- ^ Entry point information
  , tableStructures :: ![SmbiosStructure]
    -- ^ List of SMBIOS structures
  } deriving (Show, Eq, Generic)

-- | Individual SMBIOS structure
data SmbiosStructure = SmbiosStructure
  { structHeader    :: !SmbiosHeader
    -- ^ 4-byte structure header
  , structFormatted :: !ByteString
    -- ^ Formatted data (after header, before strings)
  , structStrings   :: ![ByteString]
    -- ^ String table (null-terminated strings)
  } deriving (Show, Eq, Generic)

-- | SMBIOS structure header (4 bytes)
data SmbiosHeader = SmbiosHeader
  { headerType   :: !Word8
    -- ^ Structure type
  , headerLength :: !Word8
    -- ^ Length of formatted section (including header)
  , headerHandle :: !Word16
    -- ^ Unique handle for this structure
  } deriving (Show, Eq, Generic)

-- | SMBIOS structure types
data SmbiosType
  = TypeBiosInfo           -- ^ Type 0: BIOS Information
  | TypeSystemInfo         -- ^ Type 1: System Information
  | TypeBaseboard          -- ^ Type 2: Baseboard Information
  | TypeChassis            -- ^ Type 3: System Enclosure
  | TypeProcessor          -- ^ Type 4: Processor Information
  | TypeMemoryController   -- ^ Type 5: Memory Controller (obsolete)
  | TypeMemoryModule       -- ^ Type 6: Memory Module (obsolete)
  | TypeCache              -- ^ Type 7: Cache Information
  | TypePortConnector      -- ^ Type 8: Port Connector
  | TypeSystemSlots        -- ^ Type 9: System Slots
  | TypeOnboardDevices     -- ^ Type 10: On Board Devices (obsolete)
  | TypeOemStrings         -- ^ Type 11: OEM Strings
  | TypeSysConfigOptions   -- ^ Type 12: System Configuration Options
  | TypeBiosLanguage       -- ^ Type 13: BIOS Language
  | TypeGroupAssociations  -- ^ Type 14: Group Associations
  | TypeEventLog           -- ^ Type 15: System Event Log
  | TypePhysicalMemArray   -- ^ Type 16: Physical Memory Array
  | TypeMemoryDevice       -- ^ Type 17: Memory Device
  | Type32BitMemError      -- ^ Type 18: 32-bit Memory Error
  | TypeMemArrayMapped     -- ^ Type 19: Memory Array Mapped Address
  | TypeMemDeviceMapped    -- ^ Type 20: Memory Device Mapped Address
  | TypeBuiltinPointing    -- ^ Type 21: Built-in Pointing Device
  | TypePortableBattery    -- ^ Type 22: Portable Battery
  | TypeSystemReset        -- ^ Type 23: System Reset
  | TypeHardwareSecurity   -- ^ Type 24: Hardware Security
  | TypeSystemPowerCtrl    -- ^ Type 25: System Power Controls
  | TypeVoltageProbe       -- ^ Type 26: Voltage Probe
  | TypeCoolingDevice      -- ^ Type 27: Cooling Device
  | TypeTempProbe          -- ^ Type 28: Temperature Probe
  | TypeElectricalCurrent  -- ^ Type 29: Electrical Current Probe
  | TypeOOBRemoteAccess    -- ^ Type 30: Out-of-Band Remote Access
  | TypeBIS                -- ^ Type 31: Boot Integrity Services
  | TypeSystemBoot         -- ^ Type 32: System Boot Information
  | Type64BitMemError      -- ^ Type 33: 64-bit Memory Error
  | TypeManagementDevice   -- ^ Type 34: Management Device
  | TypeMgmtDevComponent   -- ^ Type 35: Management Device Component
  | TypeMgmtDevThreshold   -- ^ Type 36: Management Device Threshold
  | TypeMemoryChannel      -- ^ Type 37: Memory Channel
  | TypeIpmiDevice         -- ^ Type 38: IPMI Device Information
  | TypePowerSupply        -- ^ Type 39: System Power Supply
  | TypeAdditionalInfo     -- ^ Type 40: Additional Information
  | TypeOnboardDevicesExt  -- ^ Type 41: Onboard Devices Extended
  | TypeMgmtCtrlHostIface  -- ^ Type 42: Management Controller Host Interface
  | TypeTpm                -- ^ Type 43: TPM Device
  | TypeProcessorAdditional -- ^ Type 44: Processor Additional Information
  | TypeFirmwareInventory  -- ^ Type 45: Firmware Inventory Information
  | TypeStringProperty     -- ^ Type 46: String Property
  | TypeInactive           -- ^ Type 126: Inactive
  | TypeEndOfTable         -- ^ Type 127: End-of-Table
  | TypeUnknown !Word8     -- ^ Unknown type
  deriving (Show, Eq, Generic)

-- | Convert SmbiosType to its numeric value
smbiosTypeValue :: SmbiosType -> Word8
smbiosTypeValue t = case t of
  TypeBiosInfo           -> 0
  TypeSystemInfo         -> 1
  TypeBaseboard          -> 2
  TypeChassis            -> 3
  TypeProcessor          -> 4
  TypeMemoryController   -> 5
  TypeMemoryModule       -> 6
  TypeCache              -> 7
  TypePortConnector      -> 8
  TypeSystemSlots        -> 9
  TypeOnboardDevices     -> 10
  TypeOemStrings         -> 11
  TypeSysConfigOptions   -> 12
  TypeBiosLanguage       -> 13
  TypeGroupAssociations  -> 14
  TypeEventLog           -> 15
  TypePhysicalMemArray   -> 16
  TypeMemoryDevice       -> 17
  Type32BitMemError      -> 18
  TypeMemArrayMapped     -> 19
  TypeMemDeviceMapped    -> 20
  TypeBuiltinPointing    -> 21
  TypePortableBattery    -> 22
  TypeSystemReset        -> 23
  TypeHardwareSecurity   -> 24
  TypeSystemPowerCtrl    -> 25
  TypeVoltageProbe       -> 26
  TypeCoolingDevice      -> 27
  TypeTempProbe          -> 28
  TypeElectricalCurrent  -> 29
  TypeOOBRemoteAccess    -> 30
  TypeBIS                -> 31
  TypeSystemBoot         -> 32
  Type64BitMemError      -> 33
  TypeManagementDevice   -> 34
  TypeMgmtDevComponent   -> 35
  TypeMgmtDevThreshold   -> 36
  TypeMemoryChannel      -> 37
  TypeIpmiDevice         -> 38
  TypePowerSupply        -> 39
  TypeAdditionalInfo     -> 40
  TypeOnboardDevicesExt  -> 41
  TypeMgmtCtrlHostIface  -> 42
  TypeTpm                -> 43
  TypeProcessorAdditional -> 44
  TypeFirmwareInventory  -> 45
  TypeStringProperty     -> 46
  TypeInactive           -> 126
  TypeEndOfTable         -> 127
  TypeUnknown v          -> v