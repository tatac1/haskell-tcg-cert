{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Util.OID
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG OID Registry for human-readable OID display.
--
-- This module provides mappings from TCG OID values to their standard names
-- as defined in the TCG Platform Certificate Profile v1.1 and related specifications.
--
-- == OID Hierarchy
--
-- The TCG OID arc is rooted at:
--
-- > tcg OBJECT IDENTIFIER ::= {
-- >     joint-iso-ccitt(2) international-organizations(23) tcg(133)
-- > }
--
-- Which corresponds to the numeric OID: 2.23.133
--
-- == References
--
-- * TCG Platform Certificate Profile v1.1
-- * TCG EK Credential Profile v2.3
-- * IETF RFC 8348 (Hardware Class Registry)
module Data.X509.TCG.Util.OID
  ( -- * OID Lookup
    lookupOIDName,
    formatOID,
    formatOIDWithName,

    -- * OID Constants
    oidTCG,
    oidTCGAttribute,
    oidTCGCommon,
    oidTCGKeyPurpose,
    oidTCGCertExtension,
    oidTCGAddress,
    oidTCGRegistry,

    -- * OID Registry
    tcgOIDRegistry,
    x509OIDRegistry,
    allOIDRegistry,

    -- * OID Classification
    isTCGOID,
    isX509OID,
    getOIDCategory,

    -- * Component Class Value
    ComponentClassValue (..),
    ComponentClassInfo (..),
    parseComponentClassValue,
    lookupComponentClassName,
    lookupComponentClassCategory,
    formatComponentClassValue,
    componentClassRegistry,
  )
where

import Data.ASN1.Types (OID)
import Data.Bits (shiftL, (.|.))
import Data.List (isPrefixOf)
import Data.Word (Word32)
import Numeric (showHex)
import qualified Data.ByteString as B

--------------------------------------------------------------------------------
-- OID Base Constants
--------------------------------------------------------------------------------

-- | TCG root OID: 2.23.133
oidTCG :: OID
oidTCG = [2, 23, 133]

-- | TCG attribute OID: 2.23.133.2
oidTCGAttribute :: OID
oidTCGAttribute = [2, 23, 133, 2]

-- | TCG platform common OID: 2.23.133.5.1
oidTCGCommon :: OID
oidTCGCommon = [2, 23, 133, 5, 1]

-- | TCG key purpose OID: 2.23.133.8
oidTCGKeyPurpose :: OID
oidTCGKeyPurpose = [2, 23, 133, 8]

-- | TCG certificate extension OID: 2.23.133.6
oidTCGCertExtension :: OID
oidTCGCertExtension = [2, 23, 133, 6]

-- | TCG address OID: 2.23.133.17
oidTCGAddress :: OID
oidTCGAddress = [2, 23, 133, 17]

-- | TCG registry OID: 2.23.133.18
oidTCGRegistry :: OID
oidTCGRegistry = [2, 23, 133, 18]

--------------------------------------------------------------------------------
-- OID Lookup Functions
--------------------------------------------------------------------------------

-- | Look up the human-readable name for an OID.
--
-- Returns 'Nothing' if the OID is not in the registry.
--
-- Example:
--
-- > lookupOIDName [2,23,133,2,17] == Just "tcg-at-tcgPlatformSpecification"
-- > lookupOIDName [1,2,3,4,5] == Nothing
lookupOIDName :: OID -> Maybe String
lookupOIDName oid = lookup oid allOIDRegistry

-- | Format an OID as a dotted decimal string.
--
-- Example:
--
-- > formatOID [2,23,133,2,17] == "2.23.133.2.17"
formatOID :: OID -> String
formatOID [] = ""
formatOID [x] = show x
formatOID (x : xs) = show x ++ "." ++ formatOID xs

-- | Format an OID with its human-readable name if available.
--
-- Example:
--
-- > formatOIDWithName [2,23,133,2,17]
-- >   == "tcg-at-tcgPlatformSpecification (2.23.133.2.17)"
-- > formatOIDWithName [1,2,3,4,5]
-- >   == "1.2.3.4.5"
formatOIDWithName :: OID -> String
formatOIDWithName oid =
  let dotted = formatOID oid
      name = lookupOIDName oid
   in case name of
        Just n -> n ++ " (" ++ dotted ++ ")"
        Nothing -> dotted

--------------------------------------------------------------------------------
-- OID Classification
--------------------------------------------------------------------------------

-- | Check if an OID is a TCG OID (under 2.23.133).
isTCGOID :: OID -> Bool
isTCGOID oid = oidTCG `isPrefixOf` oid

-- | Check if an OID is a standard X.509 OID (under 2.5).
isX509OID :: OID -> Bool
isX509OID oid = [2, 5] `isPrefixOf` oid

-- | Get the category of an OID.
getOIDCategory :: OID -> String
getOIDCategory oid
  | [2, 23, 133, 2] `isPrefixOf` oid = "TCG Attribute"
  | [2, 23, 133, 5, 1] `isPrefixOf` oid = "TCG Platform Common"
  | [2, 23, 133, 5] `isPrefixOf` oid = "TCG Platform Class"
  | [2, 23, 133, 6] `isPrefixOf` oid = "TCG Certificate Extension"
  | [2, 23, 133, 8] `isPrefixOf` oid = "TCG Key Purpose"
  | [2, 23, 133, 17] `isPrefixOf` oid = "TCG Address Type"
  | [2, 23, 133, 18, 3] `isPrefixOf` oid = "TCG Component Class Registry"
  | [2, 23, 133, 18] `isPrefixOf` oid = "TCG Registry"
  | [2, 23, 133] `isPrefixOf` oid = "TCG"
  | [2, 5, 4] `isPrefixOf` oid = "X.500 Attribute Type"
  | [2, 5, 29] `isPrefixOf` oid = "X.509 Certificate Extension"
  | [1, 3, 6, 1, 5, 5, 7, 1] `isPrefixOf` oid = "PKIX Extension"
  | [1, 3, 6, 1, 5, 5, 7, 3] `isPrefixOf` oid = "PKIX Key Purpose"
  | [1, 2, 840, 113549, 1] `isPrefixOf` oid = "PKCS"
  | otherwise = "Unknown"

--------------------------------------------------------------------------------
-- TCG OID Registry
--------------------------------------------------------------------------------

-- | TCG OID registry mapping OIDs to their standard names.
tcgOIDRegistry :: [(OID, String)]
tcgOIDRegistry =
  -- TCG Root arcs
  [ ([2, 23, 133], "tcg")
  , ([2, 23, 133, 1], "tcg-tcpaSpecVersion")
  , ([2, 23, 133, 2], "tcg-attribute")
  , ([2, 23, 133, 3], "tcg-protocol")
  , ([2, 23, 133, 4], "tcg-algorithm")
  , ([2, 23, 133, 5], "tcg-platformClass")
  , ([2, 23, 133, 6], "tcg-ce")
  , ([2, 23, 133, 8], "tcg-kp")
  , ([2, 23, 133, 17], "tcg-address")
  , ([2, 23, 133, 18], "tcg-registry")
  , -- TCG Attributes (2.23.133.2.x)
    ([2, 23, 133, 2, 1], "tcg-at-tpmManufacturer")
  , ([2, 23, 133, 2, 2], "tcg-at-tpmModel")
  , ([2, 23, 133, 2, 3], "tcg-at-tpmVersion")
  , ([2, 23, 133, 2, 10], "tcg-at-securityQualities")
  , ([2, 23, 133, 2, 11], "tcg-at-tpmProtectionProfile")
  , ([2, 23, 133, 2, 12], "tcg-at-tpmSecurityTarget")
  , ([2, 23, 133, 2, 13], "tcg-at-tbbProtectionProfile")
  , ([2, 23, 133, 2, 14], "tcg-at-tbbSecurityTarget")
  , ([2, 23, 133, 2, 15], "tcg-at-tpmIdLabel")
  , ([2, 23, 133, 2, 16], "tcg-at-tpmSpecification")
  , ([2, 23, 133, 2, 17], "tcg-at-tcgPlatformSpecification")
  , ([2, 23, 133, 2, 18], "tcg-at-tpmSecurityAssertions")
  , ([2, 23, 133, 2, 19], "tcg-at-tbbSecurityAssertions")
  , ([2, 23, 133, 2, 23], "tcg-at-tcgCredentialSpecification")
  , ([2, 23, 133, 2, 25], "tcg-at-tcgCredentialType")
  , -- TCG Platform Common (2.23.133.5.1.x)
    ([2, 23, 133, 5, 1], "tcg-common")
  , ([2, 23, 133, 5, 1, 1], "tcg-at-platformManufacturerStr")
  , ([2, 23, 133, 5, 1, 2], "tcg-at-platformManufacturerId")
  , ([2, 23, 133, 5, 1, 3], "tcg-at-platformConfigUri")
  , ([2, 23, 133, 5, 1, 4], "tcg-at-platformModel")
  , ([2, 23, 133, 5, 1, 5], "tcg-at-platformVersion")
  , ([2, 23, 133, 5, 1, 6], "tcg-at-platformSerial")
  , ([2, 23, 133, 5, 1, 7], "tcg-at-platformConfiguration")
  , ([2, 23, 133, 5, 1, 7, 1], "tcg-at-platformConfiguration-v1")
  , ([2, 23, 133, 5, 1, 7, 2], "tcg-at-platformConfiguration-v2")
  , -- TCG Key Purposes (2.23.133.8.x)
    ([2, 23, 133, 8, 1], "tcg-kp-EKCertificate")
  , ([2, 23, 133, 8, 2], "tcg-kp-PlatformAttributeCertificate")
  , ([2, 23, 133, 8, 3], "tcg-kp-AIKCertificate")
  , ([2, 23, 133, 8, 4], "tcg-kp-PlatformKeyCertificate")
  , ([2, 23, 133, 8, 5], "tcg-kp-DeltaPlatformAttributeCertificate")
  , -- TCG Certificate Extensions (2.23.133.6.x)
    ([2, 23, 133, 6, 2], "tcg-ce-relevantCredentials")
  , ([2, 23, 133, 6, 3], "tcg-ce-relevantManifests")
  , ([2, 23, 133, 6, 4], "tcg-ce-virtualPlatformAttestationService")
  , ([2, 23, 133, 6, 5], "tcg-ce-migrationControllerAttestationService")
  , ([2, 23, 133, 6, 6], "tcg-ce-migrationControllerRegistrationService")
  , ([2, 23, 133, 6, 7], "tcg-ce-virtualPlatformBackupService")
  , -- TCG Address Types (2.23.133.17.x)
    ([2, 23, 133, 17, 1], "tcg-address-ethernetmac")
  , ([2, 23, 133, 17, 2], "tcg-address-wlanmac")
  , ([2, 23, 133, 17, 3], "tcg-address-bluetoothmac")
  , -- TCG Registry (2.23.133.18.x)
    ([2, 23, 133, 18, 3], "tcg-registry-componentClass")
  , ([2, 23, 133, 18, 3, 1], "tcg-registry-componentClass-tcg")
  , ([2, 23, 133, 18, 3, 2], "tcg-registry-componentClass-ietf")
  , ([2, 23, 133, 18, 3, 3], "tcg-registry-componentClass-dmtf")
  , -- TCG Protocol (2.23.133.3.x)
    ([2, 23, 133, 3, 1], "tcg-prt-tpmIdProtocol")
  , -- TCG Algorithm (2.23.133.4.x)
    ([2, 23, 133, 4, 1], "tcg-algorithm-null")
  ]

--------------------------------------------------------------------------------
-- X.509/PKIX OID Registry
--------------------------------------------------------------------------------

-- | Standard X.509 and PKIX OID registry.
x509OIDRegistry :: [(OID, String)]
x509OIDRegistry =
  -- X.500 Attribute Types (2.5.4.x)
  [ ([2, 5, 4, 3], "id-at-commonName")
  , ([2, 5, 4, 6], "id-at-countryName")
  , ([2, 5, 4, 7], "id-at-localityName")
  , ([2, 5, 4, 8], "id-at-stateOrProvinceName")
  , ([2, 5, 4, 10], "id-at-organizationName")
  , ([2, 5, 4, 11], "id-at-organizationalUnitName")
  , ([2, 5, 4, 5], "id-at-serialNumber")
  , -- X.509 Certificate Extensions (2.5.29.x)
    ([2, 5, 29, 14], "id-ce-subjectKeyIdentifier")
  , ([2, 5, 29, 15], "id-ce-keyUsage")
  , ([2, 5, 29, 17], "id-ce-subjectAltName")
  , ([2, 5, 29, 19], "id-ce-basicConstraints")
  , ([2, 5, 29, 31], "id-ce-cRLDistributionPoints")
  , ([2, 5, 29, 32], "id-ce-certificatePolicies")
  , ([2, 5, 29, 35], "id-ce-authorityKeyIdentifier")
  , ([2, 5, 29, 37], "id-ce-extKeyUsage")
  , ([2, 5, 29, 54], "id-ce-noRevAvail")
  , ([2, 5, 29, 55], "id-ce-targetingInformation")
  , ([2, 5, 29, 56], "id-ce-deltaCRLIndicator")
  , -- PKIX Extensions (1.3.6.1.5.5.7.1.x)
    ([1, 3, 6, 1, 5, 5, 7, 1, 1], "id-pe-authorityInfoAccess")
  , ([1, 3, 6, 1, 5, 5, 7, 1, 2], "id-pe-biometricInfo")
  , ([1, 3, 6, 1, 5, 5, 7, 1, 3], "id-pe-qcStatements")
  , -- PKIX Key Purposes (1.3.6.1.5.5.7.3.x)
    ([1, 3, 6, 1, 5, 5, 7, 3, 1], "id-kp-serverAuth")
  , ([1, 3, 6, 1, 5, 5, 7, 3, 2], "id-kp-clientAuth")
  , ([1, 3, 6, 1, 5, 5, 7, 3, 3], "id-kp-codeSigning")
  , ([1, 3, 6, 1, 5, 5, 7, 3, 4], "id-kp-emailProtection")
  , ([1, 3, 6, 1, 5, 5, 7, 3, 8], "id-kp-timeStamping")
  , ([1, 3, 6, 1, 5, 5, 7, 3, 9], "id-kp-OCSPSigning")
  , -- PKIX Access Methods (1.3.6.1.5.5.7.48.x)
    ([1, 3, 6, 1, 5, 5, 7, 48, 1], "id-ad-ocsp")
  , ([1, 3, 6, 1, 5, 5, 7, 48, 2], "id-ad-caIssuers")
  , -- Signature Algorithms
    ([1, 2, 840, 113549, 1, 1, 1], "rsaEncryption")
  , ([1, 2, 840, 113549, 1, 1, 5], "sha1WithRSAEncryption")
  , ([1, 2, 840, 113549, 1, 1, 11], "sha256WithRSAEncryption")
  , ([1, 2, 840, 113549, 1, 1, 12], "sha384WithRSAEncryption")
  , ([1, 2, 840, 113549, 1, 1, 13], "sha512WithRSAEncryption")
  , ([1, 2, 840, 10045, 4, 3, 2], "ecdsa-with-SHA256")
  , ([1, 2, 840, 10045, 4, 3, 3], "ecdsa-with-SHA384")
  , ([1, 2, 840, 10045, 4, 3, 4], "ecdsa-with-SHA512")
  , -- Hash Algorithms
    ([2, 16, 840, 1, 101, 3, 4, 2, 1], "id-sha256")
  , ([2, 16, 840, 1, 101, 3, 4, 2, 2], "id-sha384")
  , ([2, 16, 840, 1, 101, 3, 4, 2, 3], "id-sha512")
  ]

-- | Combined OID registry with both TCG and X.509 OIDs.
allOIDRegistry :: [(OID, String)]
allOIDRegistry = tcgOIDRegistry ++ x509OIDRegistry

--------------------------------------------------------------------------------
-- Component Class Value Registry
--------------------------------------------------------------------------------

-- | Component class value from TCG Component Class Registry.
--
-- The value is a 4-byte OCTET STRING where:
--
-- * Bytes 0-1: Component Category (e.g., 0x0001 = Processor)
-- * Bytes 2-3: Component Subcategory (e.g., 0x0002 = CPU)
--
-- Example: 0x00010002 = Processor:CPU
data ComponentClassValue
  = ComponentClassValue
      { ccvCategory :: !Word32
      -- ^ Full 4-byte component class value
      }
  deriving (Show, Eq)

-- | Component class registry entry.
data ComponentClassInfo = ComponentClassInfo
  { cciCategory :: !String
  -- ^ Category name (e.g., "Processor", "Memory")
  , cciName :: !String
  -- ^ Component name (e.g., "CPU", "GPU")
  }
  deriving (Show, Eq)

-- | Parse component class value from 4-byte ByteString.
parseComponentClassValue :: B.ByteString -> Maybe ComponentClassValue
parseComponentClassValue bs
  | B.length bs /= 4 = Nothing
  | otherwise =
      let b0 = fromIntegral (B.index bs 0) :: Word32
          b1 = fromIntegral (B.index bs 1) :: Word32
          b2 = fromIntegral (B.index bs 2) :: Word32
          b3 = fromIntegral (B.index bs 3) :: Word32
          val = (b0 `shiftL` 24) .|. (b1 `shiftL` 16) .|. (b2 `shiftL` 8) .|. b3
       in Just (ComponentClassValue val)

-- | Look up component class name from registry.
--
-- Example:
--
-- > lookupComponentClassName 0x00010002 == Just "CPU"
lookupComponentClassName :: Word32 -> Maybe String
lookupComponentClassName val = cciName <$> lookup val componentClassRegistry

-- | Look up component class category from registry.
--
-- Example:
--
-- > lookupComponentClassCategory 0x00010002 == Just "Processor"
lookupComponentClassCategory :: Word32 -> Maybe String
lookupComponentClassCategory val = cciCategory <$> lookup val componentClassRegistry

-- | Format component class value for display.
--
-- Example:
--
-- > formatComponentClassValue 0x00010002 == "0x00010002 (CPU)"
-- > formatComponentClassValue 0x12345678 == "0x12345678"
formatComponentClassValue :: Word32 -> String
formatComponentClassValue val =
  let hexStr = "0x" ++ padHex 8 (showHex val "")
   in case lookupComponentClassName val of
        Just name -> hexStr ++ " (" ++ name ++ ")"
        Nothing -> hexStr
  where
    padHex n s = replicate (n - length s) '0' ++ s

-- | TCG Component Class Registry.
--
-- Based on TCG Component Class Registry v1.0 rev14 (May 31, 2023).
-- See Table 1: Component Class Value for the TCG Component Class Registry
--
-- Format: (4-byte value, ComponentClassInfo)
componentClassRegistry :: [(Word32, ComponentClassInfo)]
componentClassRegistry =
  -- Uncategorized Components (0x0000xxxx)
  [ (0x00000000, ComponentClassInfo "Uncategorized" "General Component")
  -- Microprocessor Components (0x0001xxxx)
  , (0x00010000, ComponentClassInfo "Microprocessor" "General Processor")
  , (0x00010002, ComponentClassInfo "Microprocessor" "CPU")
  , (0x00010004, ComponentClassInfo "Microprocessor" "DSP Processor")
  , (0x00010005, ComponentClassInfo "Microprocessor" "Video Processor")
  , (0x00010006, ComponentClassInfo "Microprocessor" "GPU")
  , (0x00010007, ComponentClassInfo "Microprocessor" "DPU")
  , (0x00010008, ComponentClassInfo "Microprocessor" "Embedded processor")
  , (0x00010009, ComponentClassInfo "Microprocessor" "SoC")
  -- Container Components (0x0002xxxx)
  , (0x00020000, ComponentClassInfo "Container" "General Container")
  , (0x00020002, ComponentClassInfo "Container" "Desktop")
  , (0x00020008, ComponentClassInfo "Container" "Laptop")
  , (0x00020009, ComponentClassInfo "Container" "Notebook")
  , (0x0002000C, ComponentClassInfo "Container" "All in One")
  , (0x00020010, ComponentClassInfo "Container" "Main Server Chassis")
  , (0x00020012, ComponentClassInfo "Container" "Sub Chassis")
  , (0x00020015, ComponentClassInfo "Container" "RAID Chassis")
  , (0x00020016, ComponentClassInfo "Container" "Rack Mount Chassis")
  , (0x00020018, ComponentClassInfo "Container" "Multi-system chassis")
  , (0x0002001B, ComponentClassInfo "Container" "Blade")
  , (0x0002001C, ComponentClassInfo "Container" "Blade Enclosure")
  , (0x0002001D, ComponentClassInfo "Container" "Tablet")
  , (0x0002001E, ComponentClassInfo "Container" "Convertible")
  , (0x00020020, ComponentClassInfo "Container" "IoT")
  , (0x00020023, ComponentClassInfo "Container" "Stick PC")
  -- IC Board Components (0x0003xxxx)
  , (0x00030000, ComponentClassInfo "IC Board" "General IC Board")
  , (0x00030002, ComponentClassInfo "IC Board" "Daughter board")
  , (0x00030003, ComponentClassInfo "IC Board" "Motherboard")
  , (0x00030004, ComponentClassInfo "IC Board" "Riser Card")
  -- Module Components (0x0004xxxx)
  , (0x00040000, ComponentClassInfo "Module" "General Module")
  , (0x00040009, ComponentClassInfo "Module" "TPM")
  -- Controller Components (0x0005xxxx)
  , (0x00050000, ComponentClassInfo "Controller" "General Controller")
  , (0x00050002, ComponentClassInfo "Controller" "Video Controller")
  , (0x00050003, ComponentClassInfo "Controller" "SCSI Controller")
  , (0x00050004, ComponentClassInfo "Controller" "Ethernet Controller")
  , (0x00050006, ComponentClassInfo "Controller" "Audio/Sound Controller")
  , (0x00050008, ComponentClassInfo "Controller" "SATA Controller")
  , (0x00050009, ComponentClassInfo "Controller" "SAS Controller")
  , (0x0005000B, ComponentClassInfo "Controller" "RAID Controller")
  , (0x0005000D, ComponentClassInfo "Controller" "USB Controller")
  , (0x0005000E, ComponentClassInfo "Controller" "Multi-function Storage Controller")
  , (0x0005000F, ComponentClassInfo "Controller" "Multi-function Network Controller")
  , (0x00050010, ComponentClassInfo "Controller" "Smart IO Controller")
  , (0x00050012, ComponentClassInfo "Controller" "BMC")
  , (0x00050013, ComponentClassInfo "Controller" "DMA Controller")
  -- Memory Components (0x0006xxxx)
  , (0x00060000, ComponentClassInfo "Memory" "General Memory")
  , (0x00060003, ComponentClassInfo "Memory" "BMC (DEPRECATED)")
  , (0x00060004, ComponentClassInfo "Memory" "DRAM Memory")
  , (0x0006000A, ComponentClassInfo "Memory" "FLASH Memory")
  , (0x00060010, ComponentClassInfo "Memory" "SDRAM Memory")
  , (0x0006001B, ComponentClassInfo "Memory" "NVRAM Memory")
  , (0x0006001C, ComponentClassInfo "Memory" "3D Xpoint Memory")
  , (0x0006001D, ComponentClassInfo "Memory" "DDR5 Memory")
  , (0x0006001E, ComponentClassInfo "Memory" "LPDDR5 Memory")
  -- Storage Components (0x0007xxxx)
  , (0x00070000, ComponentClassInfo "Storage" "General Storage Device")
  , (0x00070002, ComponentClassInfo "Storage" "Storage Drive")
  , (0x00070003, ComponentClassInfo "Storage" "SSD Drive")
  , (0x00070004, ComponentClassInfo "Storage" "M.2 Drive")
  , (0x00070005, ComponentClassInfo "Storage" "HDD Drive")
  , (0x00070006, ComponentClassInfo "Storage" "NVMe")
  -- Media Drive Components (0x0008xxxx)
  , (0x00080000, ComponentClassInfo "Media Drive" "General Media Drive")
  , (0x00080003, ComponentClassInfo "Media Drive" "Tape Drive")
  , (0x00080006, ComponentClassInfo "Media Drive" "DVD Drive")
  , (0x00080007, ComponentClassInfo "Media Drive" "BR Drive")
  -- Network Adapter Components (0x0009xxxx)
  , (0x00090000, ComponentClassInfo "Network Adapter" "General Network Adapter")
  , (0x00090002, ComponentClassInfo "Network Adapter" "Ethernet Adapter")
  , (0x00090003, ComponentClassInfo "Network Adapter" "Wi-Fi Adapter")
  , (0x00090004, ComponentClassInfo "Network Adapter" "Bluetooth Adapter")
  , (0x00090006, ComponentClassInfo "Network Adapter" "ZigBee Adapter")
  , (0x00090007, ComponentClassInfo "Network Adapter" "3G Cellular Adapter")
  , (0x00090008, ComponentClassInfo "Network Adapter" "4G Cellular Adapter")
  , (0x00090009, ComponentClassInfo "Network Adapter" "5G Cellular Adapter")
  , (0x0009000A, ComponentClassInfo "Network Adapter" "Network Switch")
  , (0x0009000B, ComponentClassInfo "Network Adapter" "Network Router")
  -- Energy Object Components (0x000Axxxx)
  , (0x000A0000, ComponentClassInfo "Energy Object" "General Energy Object")
  , (0x000A0002, ComponentClassInfo "Energy Object" "Power Supply")
  , (0x000A0003, ComponentClassInfo "Energy Object" "Battery")
  -- Cooling Components (0x000Dxxxx)
  , (0x000D0000, ComponentClassInfo "Cooling" "General Cooling Device")
  , (0x000D0004, ComponentClassInfo "Cooling" "Chassis Fan")
  , (0x000D0005, ComponentClassInfo "Cooling" "Socket Fan")
  -- Input Components (0x000Exxxx)
  , (0x000E0000, ComponentClassInfo "Input" "General Input Device")
  -- Firmware Components (0x0013xxxx)
  , (0x00130000, ComponentClassInfo "Firmware" "General Firmware")
  , (0x00130003, ComponentClassInfo "Firmware" "System firmware")
  , (0x00130004, ComponentClassInfo "Firmware" "Drive firmware")
  , (0x00130005, ComponentClassInfo "Firmware" "Bootloader")
  , (0x00130006, ComponentClassInfo "Firmware" "SMM")
  , (0x00130007, ComponentClassInfo "Firmware" "NIC firmware")
  ]
