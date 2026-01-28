{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Data.HardwareInfo.Types
-- Description : Common data types for hardware information
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module defines common data types used to represent hardware
-- information collected from the system. These types are designed
-- to be compatible with TCG Platform Certificate specifications.
--
-- Component class values are based on TCG Component Class Registry
-- Version 1.0 Revision 14 (May 31, 2023).

module Data.HardwareInfo.Types
  ( -- * Main types
    HardwareInfo(..)
  , PlatformInfo(..)
  , Component(..)
    -- * Component classification
  , ComponentClass(..)
  , componentClassToTcgValue
  , tcgComponentClassRegistry
  , componentClassFromTcgValue
    -- * Component addresses
  , ComponentAddress(..)
    -- * SMBIOS types
  , SmbiosVersion(..)
    -- * Errors
  , HardwareError(..)
    -- * Helper functions
  , emptyHardwareInfo
  , emptyPlatformInfo
  ) where

import Data.Text (Text)
import Data.Word (Word8, Word32)
import GHC.Generics (Generic)

-- | Complete hardware information collected from the system
data HardwareInfo = HardwareInfo
  { hwPlatform   :: !PlatformInfo
    -- ^ Platform-level information (system, chassis)
  , hwComponents :: ![Component]
    -- ^ List of hardware components
  , hwSmbiosVersion :: !(Maybe SmbiosVersion)
    -- ^ SMBIOS version if available
  } deriving (Show, Eq, Generic)

-- | Platform-level information
data PlatformInfo = PlatformInfo
  { platformManufacturer :: !Text
    -- ^ System manufacturer (e.g., "Dell Inc.", "Lenovo")
  , platformModel        :: !Text
    -- ^ System model/product name
  , platformVersion      :: !Text
    -- ^ System version
  , platformSerial       :: !(Maybe Text)
    -- ^ System serial number (may require elevated privileges)
  , platformUUID         :: !(Maybe Text)
    -- ^ System UUID
  , platformSKU          :: !(Maybe Text)
    -- ^ SKU number
  , platformFamily       :: !(Maybe Text)
    -- ^ Product family
  } deriving (Show, Eq, Generic)

-- | Individual hardware component
data Component = Component
  { componentClass        :: !ComponentClass
    -- ^ TCG component class
  , componentManufacturer :: !Text
    -- ^ Component manufacturer
  , componentModel        :: !Text
    -- ^ Component model/product name
  , componentSerial       :: !(Maybe Text)
    -- ^ Serial number (optional)
  , componentRevision     :: !(Maybe Text)
    -- ^ Revision/version (optional)
  , componentFieldReplaceable :: !(Maybe Bool)
    -- ^ Whether the component is field-replaceable
  , componentAddresses    :: ![ComponentAddress]
    -- ^ Network addresses (MAC, etc.)
  } deriving (Show, Eq, Generic)

-- | TCG Component Class Registry values
-- Based on TCG Component Class Registry Version 1.0 Revision 14
-- OID: 2.23.133.18.3.1
data ComponentClass
  -- Uncategorized Components (0x0000xxxx)
  = ClassGenericComponent
    -- ^ General Component (0x00000000) - known class but type not described

  -- Microprocessor Components (0x0001xxxx)
  | ClassGeneralProcessor
    -- ^ General Processor (0x00010000)
  | ClassCPU
    -- ^ Central Processing Unit (0x00010002)
  | ClassDSP
    -- ^ Digital Signal Processor (0x00010004)
  | ClassVideoProcessor
    -- ^ Video Processor (0x00010005)
  | ClassGPU
    -- ^ Graphics Processing Unit (0x00010006)
  | ClassDPU
    -- ^ Data Processing Unit (0x00010007)
  | ClassEmbeddedProcessor
    -- ^ Embedded Processor (0x00010008)
  | ClassSoC
    -- ^ System-on-a-Chip (0x00010009)

  -- Container Components (0x0002xxxx)
  | ClassGeneralContainer
    -- ^ General Container (0x00020000)
  | ClassDesktop
    -- ^ Desktop chassis (0x00020002)
  | ClassLaptop
    -- ^ Laptop chassis (0x00020008)
  | ClassNotebook
    -- ^ Notebook chassis (0x00020009)
  | ClassAllInOne
    -- ^ All-in-One chassis (0x0002000C)
  | ClassMainServerChassis
    -- ^ Main Server Chassis (0x00020010)
  | ClassSubChassis
    -- ^ Sub Chassis (0x00020012)
  | ClassRAIDChassis
    -- ^ RAID Chassis (0x00020015)
  | ClassRackMountChassis
    -- ^ Rack Mount Chassis (0x00020016)
  | ClassMultiSystemChassis
    -- ^ Multi-system Chassis (0x00020018)
  | ClassBlade
    -- ^ Blade (0x0002001B)
  | ClassBladeEnclosure
    -- ^ Blade Enclosure (0x0002001C)
  | ClassTablet
    -- ^ Tablet (0x0002001D)
  | ClassConvertible
    -- ^ Convertible (0x0002001E)
  | ClassIoT
    -- ^ IoT Device (0x00020020)
  | ClassStickPC
    -- ^ Stick PC (0x00020023)

  -- IC Board Components (0x0003xxxx)
  | ClassGeneralICBoard
    -- ^ General IC Board (0x00030000)
  | ClassDaughterBoard
    -- ^ Daughter Board (0x00030002)
  | ClassBaseboard
    -- ^ Motherboard (0x00030003)
  | ClassRiserCard
    -- ^ Riser Card (0x00030004)

  -- Module Components (0x0004xxxx)
  | ClassGeneralModule
    -- ^ General Module (0x00040000)
  | ClassTPM
    -- ^ Trusted Platform Module (0x00040009)

  -- Controller Components (0x0005xxxx)
  | ClassGeneralController
    -- ^ General Controller (0x00050000)
  | ClassVideoController
    -- ^ Video Controller (0x00050002)
  | ClassSCSIController
    -- ^ SCSI Controller (0x00050003)
  | ClassEthernetController
    -- ^ Ethernet Controller (0x00050004)
  | ClassAudioController
    -- ^ Audio/Sound Controller (0x00050006)
  | ClassSATAController
    -- ^ SATA Controller (0x00050008)
  | ClassSASController
    -- ^ SAS Controller (0x00050009)
  | ClassRAIDController
    -- ^ RAID Controller (0x0005000B)
  | ClassUSBController
    -- ^ USB Controller (0x0005000D)
  | ClassMultiFunctionStorageController
    -- ^ Multi-function Storage Controller (0x0005000E)
  | ClassMultiFunctionNetworkController
    -- ^ Multi-function Network Controller (0x0005000F)
  | ClassSmartIOController
    -- ^ Smart IO Controller (0x00050010)
  | ClassBMC
    -- ^ Baseboard Management Controller (0x00050012)
  | ClassDMAController
    -- ^ DMA Controller (0x00050013)

  -- Memory Components (0x0006xxxx)
  | ClassGeneralMemory
    -- ^ General Memory (0x00060000)
  | ClassDRAM
    -- ^ DRAM Memory (0x00060004)
  | ClassFlashMemory
    -- ^ FLASH Memory (0x0006000A)
  | ClassSDRAM
    -- ^ SDRAM Memory (0x00060010)
  | ClassNVRAM
    -- ^ NVRAM Memory (0x0006001B)
  | Class3DXPoint
    -- ^ 3D XPoint Memory (0x0006001C)
  | ClassDDR5
    -- ^ DDR5 Memory (0x0006001D)
  | ClassLPDDR5
    -- ^ LPDDR5 Memory (0x0006001E)

  -- Storage Components (0x0007xxxx)
  | ClassGeneralStorage
    -- ^ General Storage Device (0x00070000)
  | ClassStorageDrive
    -- ^ Storage Drive (0x00070002)
  | ClassSSD
    -- ^ Solid State Drive (0x00070003)
  | ClassM2Drive
    -- ^ M.2 Drive (0x00070004)
  | ClassHDD
    -- ^ Hard Disk Drive (0x00070005)
  | ClassNVMe
    -- ^ NVMe Subsystem (0x00070006)

  -- Media Drive Components (0x0008xxxx)
  | ClassGeneralMediaDrive
    -- ^ General Media Drive (0x00080000)
  | ClassTapeDrive
    -- ^ Tape Drive (0x00080003)
  | ClassDVDDrive
    -- ^ DVD Drive (0x00080006)
  | ClassBluRayDrive
    -- ^ Blu-Ray Drive (0x00080007)

  -- Network Adapter Components (0x0009xxxx)
  | ClassGeneralNetworkAdapter
    -- ^ General Network Adapter (0x00090000)
  | ClassEthernetAdapter
    -- ^ Ethernet Adapter (0x00090002)
  | ClassWiFiAdapter
    -- ^ Wi-Fi Adapter (0x00090003)
  | ClassBluetoothAdapter
    -- ^ Bluetooth Adapter (0x00090004)
  | ClassZigBeeAdapter
    -- ^ ZigBee Adapter (0x00090006)
  | Class3GCellular
    -- ^ 3G Cellular Adapter (0x00090007)
  | Class4GCellular
    -- ^ 4G Cellular Adapter (0x00090008)
  | Class5GCellular
    -- ^ 5G Cellular Adapter (0x00090009)
  | ClassNetworkSwitch
    -- ^ Network Switch (0x0009000A)
  | ClassNetworkRouter
    -- ^ Network Router (0x0009000B)

  -- Energy Object Components (0x000Axxxx)
  | ClassGeneralEnergyObject
    -- ^ General Energy Object (0x000A0000)
  | ClassPowerSupply
    -- ^ Power Supply (0x000A0002)
  | ClassBattery
    -- ^ Battery (0x000A0003)

  -- Cooling Components (0x000Dxxxx)
  | ClassGeneralCooling
    -- ^ General Cooling Device (0x000D0000)
  | ClassChassisFan
    -- ^ Chassis Fan (0x000D0004)
  | ClassSocketFan
    -- ^ Socket/CPU Fan (0x000D0005)

  -- Input Components (0x000Exxxx)
  | ClassGeneralInput
    -- ^ General Input Device (0x000E0000)

  -- Firmware Components (0x0013xxxx)
  | ClassGeneralFirmware
    -- ^ General Firmware (0x00130000)
  | ClassSystemFirmware
    -- ^ System Firmware/UEFI (0x00130003)
  | ClassDriveFirmware
    -- ^ Drive Firmware (0x00130004)
  | ClassBootloader
    -- ^ Bootloader (0x00130005)
  | ClassSMM
    -- ^ System Management Module (0x00130006)
  | ClassNICFirmware
    -- ^ NIC Firmware (0x00130007)

  -- Other/Custom
  | ClassOther !Text !Word32
    -- ^ Other component with custom class value

  -- Legacy aliases (for backward compatibility)
  | ClassChassis
    -- ^ Alias for ClassGeneralContainer (legacy)
  | ClassRAM
    -- ^ Alias for ClassGeneralMemory (legacy)
  | ClassNIC
    -- ^ Alias for ClassEthernetAdapter (legacy)
  | ClassBIOS
    -- ^ Alias for ClassSystemFirmware (legacy)

  deriving (Show, Eq, Generic)

-- | Convert ComponentClass to TCG Component Class Registry value
-- Values are from TCG Component Class Registry v1.0 rev14
componentClassToTcgValue :: ComponentClass -> Word32
componentClassToTcgValue cls = case cls of
  -- Uncategorized (0x0000xxxx)
  ClassGenericComponent -> 0x00000000

  -- Microprocessor (0x0001xxxx)
  ClassGeneralProcessor -> 0x00010000
  ClassCPU              -> 0x00010002
  ClassDSP              -> 0x00010004
  ClassVideoProcessor   -> 0x00010005
  ClassGPU              -> 0x00010006
  ClassDPU              -> 0x00010007
  ClassEmbeddedProcessor -> 0x00010008
  ClassSoC              -> 0x00010009

  -- Container (0x0002xxxx)
  ClassGeneralContainer -> 0x00020000
  ClassDesktop          -> 0x00020002
  ClassLaptop           -> 0x00020008
  ClassNotebook         -> 0x00020009
  ClassAllInOne         -> 0x0002000C
  ClassMainServerChassis -> 0x00020010
  ClassSubChassis       -> 0x00020012
  ClassRAIDChassis      -> 0x00020015
  ClassRackMountChassis -> 0x00020016
  ClassMultiSystemChassis -> 0x00020018
  ClassBlade            -> 0x0002001B
  ClassBladeEnclosure   -> 0x0002001C
  ClassTablet           -> 0x0002001D
  ClassConvertible      -> 0x0002001E
  ClassIoT              -> 0x00020020
  ClassStickPC          -> 0x00020023

  -- IC Board (0x0003xxxx)
  ClassGeneralICBoard   -> 0x00030000
  ClassDaughterBoard    -> 0x00030002
  ClassBaseboard        -> 0x00030003
  ClassRiserCard        -> 0x00030004

  -- Module (0x0004xxxx)
  ClassGeneralModule    -> 0x00040000
  ClassTPM              -> 0x00040009

  -- Controller (0x0005xxxx)
  ClassGeneralController -> 0x00050000
  ClassVideoController  -> 0x00050002
  ClassSCSIController   -> 0x00050003
  ClassEthernetController -> 0x00050004
  ClassAudioController  -> 0x00050006
  ClassSATAController   -> 0x00050008
  ClassSASController    -> 0x00050009
  ClassRAIDController   -> 0x0005000B
  ClassUSBController    -> 0x0005000D
  ClassMultiFunctionStorageController -> 0x0005000E
  ClassMultiFunctionNetworkController -> 0x0005000F
  ClassSmartIOController -> 0x00050010
  ClassBMC              -> 0x00050012
  ClassDMAController    -> 0x00050013

  -- Memory (0x0006xxxx)
  ClassGeneralMemory    -> 0x00060000
  ClassDRAM             -> 0x00060004
  ClassFlashMemory      -> 0x0006000A
  ClassSDRAM            -> 0x00060010
  ClassNVRAM            -> 0x0006001B
  Class3DXPoint         -> 0x0006001C
  ClassDDR5             -> 0x0006001D
  ClassLPDDR5           -> 0x0006001E

  -- Storage (0x0007xxxx)
  ClassGeneralStorage   -> 0x00070000
  ClassStorageDrive     -> 0x00070002
  ClassSSD              -> 0x00070003
  ClassM2Drive          -> 0x00070004
  ClassHDD              -> 0x00070005
  ClassNVMe             -> 0x00070006

  -- Media Drive (0x0008xxxx)
  ClassGeneralMediaDrive -> 0x00080000
  ClassTapeDrive        -> 0x00080003
  ClassDVDDrive         -> 0x00080006
  ClassBluRayDrive      -> 0x00080007

  -- Network Adapter (0x0009xxxx)
  ClassGeneralNetworkAdapter -> 0x00090000
  ClassEthernetAdapter  -> 0x00090002
  ClassWiFiAdapter      -> 0x00090003
  ClassBluetoothAdapter -> 0x00090004
  ClassZigBeeAdapter    -> 0x00090006
  Class3GCellular       -> 0x00090007
  Class4GCellular       -> 0x00090008
  Class5GCellular       -> 0x00090009
  ClassNetworkSwitch    -> 0x0009000A
  ClassNetworkRouter    -> 0x0009000B

  -- Energy Object (0x000Axxxx)
  ClassGeneralEnergyObject -> 0x000A0000
  ClassPowerSupply      -> 0x000A0002
  ClassBattery          -> 0x000A0003

  -- Cooling (0x000Dxxxx)
  ClassGeneralCooling   -> 0x000D0000
  ClassChassisFan       -> 0x000D0004
  ClassSocketFan        -> 0x000D0005

  -- Input (0x000Exxxx)
  ClassGeneralInput     -> 0x000E0000

  -- Firmware (0x0013xxxx)
  ClassGeneralFirmware  -> 0x00130000
  ClassSystemFirmware   -> 0x00130003
  ClassDriveFirmware    -> 0x00130004
  ClassBootloader       -> 0x00130005
  ClassSMM              -> 0x00130006
  ClassNICFirmware      -> 0x00130007

  -- Other
  ClassOther _ v        -> v

  -- Legacy aliases
  ClassChassis          -> 0x00020000  -- General Container
  ClassRAM              -> 0x00060000  -- General Memory
  ClassNIC              -> 0x00090002  -- Ethernet Adapter
  ClassBIOS             -> 0x00130003  -- System Firmware

-- | Convert TCG Component Class Registry value to ComponentClass
componentClassFromTcgValue :: Word32 -> ComponentClass
componentClassFromTcgValue v = case v of
  -- Uncategorized
  0x00000000 -> ClassGenericComponent

  -- Microprocessor
  0x00010000 -> ClassGeneralProcessor
  0x00010002 -> ClassCPU
  0x00010004 -> ClassDSP
  0x00010005 -> ClassVideoProcessor
  0x00010006 -> ClassGPU
  0x00010007 -> ClassDPU
  0x00010008 -> ClassEmbeddedProcessor
  0x00010009 -> ClassSoC

  -- Container
  0x00020000 -> ClassGeneralContainer
  0x00020002 -> ClassDesktop
  0x00020008 -> ClassLaptop
  0x00020009 -> ClassNotebook
  0x0002000C -> ClassAllInOne
  0x00020010 -> ClassMainServerChassis
  0x00020012 -> ClassSubChassis
  0x00020015 -> ClassRAIDChassis
  0x00020016 -> ClassRackMountChassis
  0x00020018 -> ClassMultiSystemChassis
  0x0002001B -> ClassBlade
  0x0002001C -> ClassBladeEnclosure
  0x0002001D -> ClassTablet
  0x0002001E -> ClassConvertible
  0x00020020 -> ClassIoT
  0x00020023 -> ClassStickPC

  -- IC Board
  0x00030000 -> ClassGeneralICBoard
  0x00030002 -> ClassDaughterBoard
  0x00030003 -> ClassBaseboard
  0x00030004 -> ClassRiserCard

  -- Module
  0x00040000 -> ClassGeneralModule
  0x00040009 -> ClassTPM

  -- Controller
  0x00050000 -> ClassGeneralController
  0x00050002 -> ClassVideoController
  0x00050003 -> ClassSCSIController
  0x00050004 -> ClassEthernetController
  0x00050006 -> ClassAudioController
  0x00050008 -> ClassSATAController
  0x00050009 -> ClassSASController
  0x0005000B -> ClassRAIDController
  0x0005000D -> ClassUSBController
  0x0005000E -> ClassMultiFunctionStorageController
  0x0005000F -> ClassMultiFunctionNetworkController
  0x00050010 -> ClassSmartIOController
  0x00050012 -> ClassBMC
  0x00050013 -> ClassDMAController

  -- Memory
  0x00060000 -> ClassGeneralMemory
  0x00060004 -> ClassDRAM
  0x0006000A -> ClassFlashMemory
  0x00060010 -> ClassSDRAM
  0x0006001B -> ClassNVRAM
  0x0006001C -> Class3DXPoint
  0x0006001D -> ClassDDR5
  0x0006001E -> ClassLPDDR5

  -- Storage
  0x00070000 -> ClassGeneralStorage
  0x00070002 -> ClassStorageDrive
  0x00070003 -> ClassSSD
  0x00070004 -> ClassM2Drive
  0x00070005 -> ClassHDD
  0x00070006 -> ClassNVMe

  -- Media Drive
  0x00080000 -> ClassGeneralMediaDrive
  0x00080003 -> ClassTapeDrive
  0x00080006 -> ClassDVDDrive
  0x00080007 -> ClassBluRayDrive

  -- Network Adapter
  0x00090000 -> ClassGeneralNetworkAdapter
  0x00090002 -> ClassEthernetAdapter
  0x00090003 -> ClassWiFiAdapter
  0x00090004 -> ClassBluetoothAdapter
  0x00090006 -> ClassZigBeeAdapter
  0x00090007 -> Class3GCellular
  0x00090008 -> Class4GCellular
  0x00090009 -> Class5GCellular
  0x0009000A -> ClassNetworkSwitch
  0x0009000B -> ClassNetworkRouter

  -- Energy Object
  0x000A0000 -> ClassGeneralEnergyObject
  0x000A0002 -> ClassPowerSupply
  0x000A0003 -> ClassBattery

  -- Cooling
  0x000D0000 -> ClassGeneralCooling
  0x000D0004 -> ClassChassisFan
  0x000D0005 -> ClassSocketFan

  -- Input
  0x000E0000 -> ClassGeneralInput

  -- Firmware
  0x00130000 -> ClassGeneralFirmware
  0x00130003 -> ClassSystemFirmware
  0x00130004 -> ClassDriveFirmware
  0x00130005 -> ClassBootloader
  0x00130006 -> ClassSMM
  0x00130007 -> ClassNICFirmware

  -- Unknown
  _ -> ClassOther "Unknown" v

-- | TCG Component Class Registry OID
-- OID: 2.23.133.18.3.1 (tcg-registry-componentClass-tcg)
tcgComponentClassRegistry :: Text
tcgComponentClassRegistry = "2.23.133.18.3.1"

-- | Component network addresses
data ComponentAddress
  = EthernetMAC !Text
    -- ^ Ethernet MAC address (e.g., "AA:BB:CC:DD:EE:FF")
  | WirelessMAC !Text
    -- ^ Wireless LAN MAC address
  | BluetoothMAC !Text
    -- ^ Bluetooth MAC address
  deriving (Show, Eq, Generic)

-- | SMBIOS version information
data SmbiosVersion = SmbiosVersion
  { smbiosMajor    :: !Word8
  , smbiosMinor    :: !Word8
  , smbiosRevision :: !Word8
  } deriving (Show, Eq, Generic)

-- | Errors that can occur during hardware information collection
data HardwareError
  = SmbiosNotAvailable !Text
    -- ^ SMBIOS data is not available
  | PermissionDenied !Text
    -- ^ Insufficient permissions to read hardware info
  | ParseError !Text
    -- ^ Failed to parse hardware data
  | UnsupportedPlatform !Text
    -- ^ Platform is not supported
  | IOError !Text
    -- ^ I/O error occurred
  deriving (Show, Eq, Generic)

-- | Create an empty HardwareInfo
emptyHardwareInfo :: HardwareInfo
emptyHardwareInfo = HardwareInfo
  { hwPlatform = emptyPlatformInfo
  , hwComponents = []
  , hwSmbiosVersion = Nothing
  }

-- | Create an empty PlatformInfo
emptyPlatformInfo :: PlatformInfo
emptyPlatformInfo = PlatformInfo
  { platformManufacturer = ""
  , platformModel = ""
  , platformVersion = ""
  , platformSerial = Nothing
  , platformUUID = Nothing
  , platformSKU = Nothing
  , platformFamily = Nothing
  }
