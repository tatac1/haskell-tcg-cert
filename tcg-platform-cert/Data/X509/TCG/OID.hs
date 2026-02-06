-- |
-- Module      : Data.X509.TCG.OID
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TCG (Trusted Computing Group) Object Identifier definitions
-- as specified in the IWG Platform Certificate Profile v1.1
--
-- This module defines OIDs used in Platform Certificates and Delta Platform 
-- Certificates for component identification, platform configuration, and 
-- TPM-related attributes.
module Data.X509.TCG.OID
  ( -- * TCG OID Arc
    tcgOID,
    tcg_paa,

    -- * TCG Attribute Type OIDs (tcg-at arc: 2.23.133.2.*)
    tcg_at_platformConfiguration,
    tcg_at_platformConfiguration_v2,
    tcg_at_componentIdentifier,
    tcg_at_componentIdentifier_v2,
    tcg_at_componentClass,
    tcg_at_platformManufacturer,
    tcg_at_platformModel,
    tcg_at_platformSerial,
    tcg_at_platformVersion,
    tcg_at_componentManufacturer,
    tcg_at_componentModel,
    tcg_at_componentSerial,
    tcg_at_componentRevision,
    tcg_at_componentManufacturerSerial,
    tcg_at_componentManufacturerRevision,
    tcg_at_tpmModel,
    tcg_at_tpmVersion,
    tcg_at_tpmSpecification,
    tcg_at_tcgCredentialType,
    tcg_at_tcgCredentialSpecification,
    tcg_at_tbbSecurityAssertions,
    tcg_at_tcgPlatformSpecification,

    -- * TCG Platform Attribute Authority OIDs (tcg-paa arc: 2.23.133.5.1.*)
    tcg_paa_platformManufacturer,
    tcg_paa_platformManufacturerId,
    tcg_paa_platformConfigUri,
    tcg_paa_platformModel,
    tcg_paa_platformVersion,
    tcg_paa_platformSerial,
    tcg_paa_platformConfiguration,
    tcg_paa_platformConfiguration_v2,

    -- * TCG Address Type OIDs (2.23.133.17.*)
    tcg_address_ethernetmac,
    tcg_address_wlanmac,
    tcg_address_bluetoothmac,

    -- * TCG Component Class Registry OIDs (2.23.133.18.3.*)
    tcg_registry_componentClass_tcg,
    tcg_registry_componentClass_ietf,
    tcg_registry_componentClass_dmtf,
    tcg_registry_componentClass_pcie,
    tcg_registry_componentClass_storage,

    -- * TCG Key Purpose OIDs
    tcg_kp_EKCertificate,
    tcg_kp_PlatformAttributeCertificate,
    tcg_kp_DeltaAttributeCertificate,
    tcg_kp_ComponentIdentifierCertificate,

    -- * TCG Certificate Extension OIDs
    tcg_ce_relevantCredentials,
    tcg_ce_relevantManifests,
    tcg_ce_virtualPlatform,
    tcg_ce_multiTenant,

    -- * Extended Platform Attribute OIDs (IWG v1.1)
    tcg_at_platformConfigUri,
    tcg_at_platformClass,
    tcg_at_certificationLevel,
    tcg_at_platformQualifiers,
    tcg_at_rootOfTrust,
    tcg_at_rtmType,
    tcg_at_bootMode,
    tcg_at_firmwareVersion,
    tcg_at_policyReference,
    
    -- * Component Classes
    tcg_class_motherboard,
    tcg_class_cpu,
    tcg_class_memory,
    tcg_class_hardDrive,
    tcg_class_networkInterface,
    tcg_class_graphicsCard,
    tcg_class_soundCard,
    tcg_class_opticalDrive,
    tcg_class_keyboard,
    tcg_class_mouse,
    tcg_class_display,
    tcg_class_speaker,
    tcg_class_microphone,
    tcg_class_camera,
    tcg_class_touchscreen,
    tcg_class_fingerprint,
    tcg_class_bluetooth,
    tcg_class_wifi,
    tcg_class_ethernet,
    tcg_class_ide
  ) where

import Data.ASN1.OID

-- | TCG root OID arc: 2.23.133 (tcg)
tcgOID :: OID
tcgOID = [2, 23, 133]

-- | TCG Platform Attribute Authority arc: 2.23.133.5.1 (tcg-paa)
tcg_paa :: OID
tcg_paa = tcgOID ++ [5, 1]

-- * TCG Attribute Type OIDs (tcg-at arc: 2.23.133.2.*)

-- | Platform Configuration attribute OID (v1)
-- OID: 2.23.133.5.1.7.1 (tcg-at-platformConfiguration-v1 in spec)
-- This is defined as {tcg-at-platformConfiguration 1} where tcg-at-platformConfiguration = {tcg-common 7}
tcg_at_platformConfiguration :: OID
tcg_at_platformConfiguration = tcg_paa ++ [7, 1]

-- | Platform Configuration attribute OID (v2) - per TCG spec IWG v1.1
-- OID: 2.23.133.5.1.7.2 (tcg-at-platformConfiguration-v2 in spec)
-- This is defined as {tcg-at-platformConfiguration 2} where tcg-at-platformConfiguration = {tcg-common 7}
tcg_at_platformConfiguration_v2 :: OID
tcg_at_platformConfiguration_v2 = tcg_paa ++ [7, 2]

-- | Component Identifier attribute OID (v1)
-- OID: 2.23.133.2.2
tcg_at_componentIdentifier :: OID
tcg_at_componentIdentifier = tcgOID ++ [2, 2]

-- | Component Identifier attribute OID (v2)
-- OID: 2.23.133.2.24
tcg_at_componentIdentifier_v2 :: OID
tcg_at_componentIdentifier_v2 = tcgOID ++ [2, 24]

-- | Component Class attribute OID
-- OID: 2.23.133.2.3
tcg_at_componentClass :: OID
tcg_at_componentClass = tcgOID ++ [2, 3]

-- | Platform Manufacturer attribute OID
-- OID: 2.23.133.2.4
tcg_at_platformManufacturer :: OID
tcg_at_platformManufacturer = tcgOID ++ [2, 4]

-- | Platform Model attribute OID  
-- OID: 2.23.133.2.5
tcg_at_platformModel :: OID
tcg_at_platformModel = tcgOID ++ [2, 5]

-- | Platform Serial attribute OID
-- OID: 2.23.133.2.6  
tcg_at_platformSerial :: OID
tcg_at_platformSerial = tcgOID ++ [2, 6]

-- | Platform Version attribute OID
-- OID: 2.23.133.2.7
tcg_at_platformVersion :: OID
tcg_at_platformVersion = tcgOID ++ [2, 7]

-- | Component Manufacturer attribute OID
-- OID: 2.23.133.2.8
tcg_at_componentManufacturer :: OID
tcg_at_componentManufacturer = tcgOID ++ [2, 8]

-- | Component Model attribute OID
-- OID: 2.23.133.2.9
tcg_at_componentModel :: OID
tcg_at_componentModel = tcgOID ++ [2, 9]

-- | Component Serial attribute OID
-- OID: 2.23.133.2.10
tcg_at_componentSerial :: OID
tcg_at_componentSerial = tcgOID ++ [2, 10]

-- | Component Revision attribute OID
-- OID: 2.23.133.2.11
tcg_at_componentRevision :: OID
tcg_at_componentRevision = tcgOID ++ [2, 11]

-- | Component Manufacturer Serial attribute OID
-- OID: 2.23.133.2.12
tcg_at_componentManufacturerSerial :: OID
tcg_at_componentManufacturerSerial = tcgOID ++ [2, 12]

-- | Component Manufacturer Revision attribute OID
-- OID: 2.23.133.2.13
tcg_at_componentManufacturerRevision :: OID
tcg_at_componentManufacturerRevision = tcgOID ++ [2, 13]

-- | TPM Model attribute OID
-- OID: 2.23.133.2.16
tcg_at_tpmModel :: OID
tcg_at_tpmModel = tcgOID ++ [2, 16]

-- | TPM Version attribute OID
-- OID: 2.23.133.2.17
tcg_at_tpmVersion :: OID
tcg_at_tpmVersion = tcgOID ++ [2, 17]

-- | TPM Specification attribute OID
-- OID: 2.23.133.2.18
tcg_at_tpmSpecification :: OID
tcg_at_tpmSpecification = tcgOID ++ [2, 18]

-- * TCG Key Purpose OIDs

-- | EK Certificate key purpose OID
-- OID: 2.23.133.8.1
tcg_kp_EKCertificate :: OID
tcg_kp_EKCertificate = tcgOID ++ [8, 1]

-- | Platform Attribute Certificate key purpose OID
-- OID: 2.23.133.8.2  
tcg_kp_PlatformAttributeCertificate :: OID
tcg_kp_PlatformAttributeCertificate = tcgOID ++ [8, 2]

-- | Delta Attribute Certificate key purpose OID
-- OID: 2.23.133.8.5 (tcg-kp-DeltaPlatformAttributeCertificate per IWG v1.1 Section 3.2.2)
tcg_kp_DeltaAttributeCertificate :: OID
tcg_kp_DeltaAttributeCertificate = tcgOID ++ [8, 5]

-- | Component Identifier Certificate key purpose OID
-- OID: 2.23.133.8.4
tcg_kp_ComponentIdentifierCertificate :: OID
tcg_kp_ComponentIdentifierCertificate = tcgOID ++ [8, 4]

-- * TCG Certificate Extension OIDs

-- | Relevant Credentials extension OID
-- OID: 2.23.133.2.19
tcg_ce_relevantCredentials :: OID
tcg_ce_relevantCredentials = tcgOID ++ [2, 19]

-- | Relevant Manifests extension OID  
-- OID: 2.23.133.2.20
tcg_ce_relevantManifests :: OID
tcg_ce_relevantManifests = tcgOID ++ [2, 20]

-- | Virtual Platform extension OID
-- OID: 2.23.133.2.21
tcg_ce_virtualPlatform :: OID
tcg_ce_virtualPlatform = tcgOID ++ [2, 21]

-- | Multi-Tenant extension OID
-- OID: 2.23.133.2.22
tcg_ce_multiTenant :: OID
tcg_ce_multiTenant = tcgOID ++ [2, 22]

-- * Component Classes

-- | Motherboard component class
-- OID: 2.23.133.18.1.1
tcg_class_motherboard :: OID
tcg_class_motherboard = tcgOID ++ [18, 1, 1]

-- | CPU component class
-- OID: 2.23.133.18.1.2  
tcg_class_cpu :: OID
tcg_class_cpu = tcgOID ++ [18, 1, 2]

-- | Memory component class
-- OID: 2.23.133.18.1.3
tcg_class_memory :: OID
tcg_class_memory = tcgOID ++ [18, 1, 3]

-- | Hard Drive component class
-- OID: 2.23.133.18.1.4
tcg_class_hardDrive :: OID
tcg_class_hardDrive = tcgOID ++ [18, 1, 4]

-- | Network Interface component class
-- OID: 2.23.133.18.1.5
tcg_class_networkInterface :: OID
tcg_class_networkInterface = tcgOID ++ [18, 1, 5]

-- | Graphics Card component class
-- OID: 2.23.133.18.1.6
tcg_class_graphicsCard :: OID
tcg_class_graphicsCard = tcgOID ++ [18, 1, 6]

-- | Sound Card component class  
-- OID: 2.23.133.18.1.7
tcg_class_soundCard :: OID
tcg_class_soundCard = tcgOID ++ [18, 1, 7]

-- | Optical Drive component class
-- OID: 2.23.133.18.1.8
tcg_class_opticalDrive :: OID
tcg_class_opticalDrive = tcgOID ++ [18, 1, 8]

-- | Keyboard component class
-- OID: 2.23.133.18.1.9
tcg_class_keyboard :: OID
tcg_class_keyboard = tcgOID ++ [18, 1, 9]

-- | Mouse component class
-- OID: 2.23.133.18.1.10
tcg_class_mouse :: OID
tcg_class_mouse = tcgOID ++ [18, 1, 10]

-- | Display component class
-- OID: 2.23.133.18.1.11  
tcg_class_display :: OID
tcg_class_display = tcgOID ++ [18, 1, 11]

-- | Speaker component class
-- OID: 2.23.133.18.1.12
tcg_class_speaker :: OID
tcg_class_speaker = tcgOID ++ [18, 1, 12]

-- | Microphone component class
-- OID: 2.23.133.18.1.13
tcg_class_microphone :: OID
tcg_class_microphone = tcgOID ++ [18, 1, 13]

-- | Camera component class
-- OID: 2.23.133.18.1.14
tcg_class_camera :: OID
tcg_class_camera = tcgOID ++ [18, 1, 14]

-- | Touchscreen component class  
-- OID: 2.23.133.18.1.15
tcg_class_touchscreen :: OID
tcg_class_touchscreen = tcgOID ++ [18, 1, 15]

-- | Fingerprint component class
-- OID: 2.23.133.18.1.16
tcg_class_fingerprint :: OID
tcg_class_fingerprint = tcgOID ++ [18, 1, 16]

-- | Bluetooth component class
-- OID: 2.23.133.18.2.1
tcg_class_bluetooth :: OID
tcg_class_bluetooth = tcgOID ++ [18, 2, 1]

-- | WiFi component class
-- OID: 2.23.133.18.2.2
tcg_class_wifi :: OID
tcg_class_wifi = tcgOID ++ [18, 2, 2]

-- | Ethernet component class
-- OID: 2.23.133.18.2.3
tcg_class_ethernet :: OID
tcg_class_ethernet = tcgOID ++ [18, 2, 3]

-- | IDE component class
-- OID: 2.23.133.18.4.1 (moved from 18.3.* arc to avoid collision with registry OIDs)
tcg_class_ide :: OID
tcg_class_ide = tcgOID ++ [18, 4, 1]

-- Note: tcg_class_usb, tcg_class_firewire, tcg_class_scsi were removed
-- because they collided with tcg_registry_componentClass_* OIDs at 2.23.133.18.3.*
-- Per TCG Component Class Registry v1.0, ComponentClass uses 4-byte OCTET STRING values,
-- not OIDs. Interface-specific component classes should be represented differently.

-- * Extended Platform Attribute OID Definitions (IWG v1.1)

-- | Platform Configuration URI attribute
-- OID: 2.23.133.2.20
tcg_at_platformConfigUri :: OID
tcg_at_platformConfigUri = tcgOID ++ [2, 20]

-- | Platform Class attribute  
-- OID: 2.23.133.2.21
tcg_at_platformClass :: OID
tcg_at_platformClass = tcgOID ++ [2, 21]

-- | Certification Level attribute
-- OID: 2.23.133.2.22  
tcg_at_certificationLevel :: OID
tcg_at_certificationLevel = tcgOID ++ [2, 22]

-- | Platform Qualifiers attribute
-- OID: 2.23.133.2.23
tcg_at_platformQualifiers :: OID
tcg_at_platformQualifiers = tcgOID ++ [2, 23]

-- | Root of Trust attribute
-- OID: 2.23.133.2.24
tcg_at_rootOfTrust :: OID
tcg_at_rootOfTrust = tcgOID ++ [2, 24]

-- | RTM Type attribute
-- OID: 2.23.133.2.25
tcg_at_rtmType :: OID
tcg_at_rtmType = tcgOID ++ [2, 25]

-- | Boot Mode attribute
-- OID: 2.23.133.2.26
tcg_at_bootMode :: OID
tcg_at_bootMode = tcgOID ++ [2, 26]

-- | Firmware Version attribute
-- OID: 2.23.133.2.27
tcg_at_firmwareVersion :: OID
tcg_at_firmwareVersion = tcgOID ++ [2, 27]

-- | Policy Reference attribute
-- OID: 2.23.133.2.28
tcg_at_policyReference :: OID
tcg_at_policyReference = tcgOID ++ [2, 28]

-- | TCG Credential Type attribute
-- OID: 2.23.133.2.25 (tcg-at-tcgCredentialType per IWG v1.1 Section 3.1.2)
tcg_at_tcgCredentialType :: OID
tcg_at_tcgCredentialType = tcgOID ++ [2, 25]

-- | TBB Security Assertions attribute
-- OID: 2.23.133.2.19
tcg_at_tbbSecurityAssertions :: OID
tcg_at_tbbSecurityAssertions = tcgOID ++ [2, 19]

-- | TCG Platform Specification attribute
-- OID: 2.23.133.2.17 (tcg-at-tcgPlatformSpecification per IWG v1.1 Section 3.1.2)
tcg_at_tcgPlatformSpecification :: OID
tcg_at_tcgPlatformSpecification = tcgOID ++ [2, 17]

-- | TCG Credential Specification attribute
-- OID: 2.23.133.2.23 (tcg-at-tcgCredentialSpecification per IWG v1.1 Section 3.1.2)
tcg_at_tcgCredentialSpecification :: OID
tcg_at_tcgCredentialSpecification = tcgOID ++ [2, 23]

-- * TCG Common/Platform Attribute OIDs (tcg-paa / tcg-common arc: 2.23.133.5.1.*)
-- These OIDs identify platform identity attributes (manufacturer/model/version/serial/etc.)
-- as defined in the IWG Platform Certificate Profile v1.1.

-- | Platform Manufacturer (in subjectAltName)
-- OID: 2.23.133.5.1.1
tcg_paa_platformManufacturer :: OID
tcg_paa_platformManufacturer = tcg_paa ++ [1]

-- | Platform Manufacturer ID (in subjectAltName)
-- OID: 2.23.133.5.1.2
tcg_paa_platformManufacturerId :: OID
tcg_paa_platformManufacturerId = tcg_paa ++ [2]

-- | Platform Configuration URI (in subjectAltName)
-- OID: 2.23.133.5.1.3
tcg_paa_platformConfigUri :: OID
tcg_paa_platformConfigUri = tcg_paa ++ [3]

-- | Platform Model (in subjectAltName)
-- OID: 2.23.133.5.1.4
tcg_paa_platformModel :: OID
tcg_paa_platformModel = tcg_paa ++ [4]

-- | Platform Version (in subjectAltName)
-- OID: 2.23.133.5.1.5
tcg_paa_platformVersion :: OID
tcg_paa_platformVersion = tcg_paa ++ [5]

-- | Platform Serial (in subjectAltName)
-- OID: 2.23.133.5.1.6
tcg_paa_platformSerial :: OID
tcg_paa_platformSerial = tcg_paa ++ [6]

-- | Platform Configuration (in attribute)
-- OID: 2.23.133.5.1.7.1
tcg_paa_platformConfiguration :: OID
tcg_paa_platformConfiguration = tcg_paa ++ [7, 1]

-- | Platform Configuration v2 (in attribute) - IWG v1.1
-- OID: 2.23.133.5.1.7.2
tcg_paa_platformConfiguration_v2 :: OID
tcg_paa_platformConfiguration_v2 = tcg_paa ++ [7, 2]

-- * TCG Address Type OIDs (2.23.133.17.*)

-- | Ethernet MAC address type
-- OID: 2.23.133.17.1
tcg_address_ethernetmac :: OID
tcg_address_ethernetmac = tcgOID ++ [17, 1]

-- | WLAN MAC address type
-- OID: 2.23.133.17.2
tcg_address_wlanmac :: OID
tcg_address_wlanmac = tcgOID ++ [17, 2]

-- | Bluetooth MAC address type
-- OID: 2.23.133.17.3
tcg_address_bluetoothmac :: OID
tcg_address_bluetoothmac = tcgOID ++ [17, 3]

-- * TCG Component Class Registry OIDs (2.23.133.18.3.*)

-- | TCG Component Class Registry
-- OID: 2.23.133.18.3.1
tcg_registry_componentClass_tcg :: OID
tcg_registry_componentClass_tcg = tcgOID ++ [18, 3, 1]

-- | IETF Component Class Registry
-- OID: 2.23.133.18.3.2
tcg_registry_componentClass_ietf :: OID
tcg_registry_componentClass_ietf = tcgOID ++ [18, 3, 2]

-- | DMTF Component Class Registry
-- OID: 2.23.133.18.3.3
tcg_registry_componentClass_dmtf :: OID
tcg_registry_componentClass_dmtf = tcgOID ++ [18, 3, 3]

-- | PCIe Component Class Registry
-- OID: 2.23.133.18.3.4
tcg_registry_componentClass_pcie :: OID
tcg_registry_componentClass_pcie = tcgOID ++ [18, 3, 4]

-- | Storage Component Class Registry
-- OID: 2.23.133.18.3.5
tcg_registry_componentClass_storage :: OID
tcg_registry_componentClass_storage = tcgOID ++ [18, 3, 5]
