{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Util.Config
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Utility
-- Stability   : experimental
-- Portability : unknown
--
-- Configuration management for TCG Platform Certificate utility.
-- This module provides YAML-based configuration loading and default value management.

module Data.X509.TCG.Util.Config
  ( -- * Configuration Types
    PlatformCertConfig(..)
  , DeltaCertConfig(..)
  , ComponentConfig(..)
  , ComponentChangeConfig(..)
  , AddressConfig(..)
  , URIReferenceConfig(..)
  , SecurityAssertionsConfig(..)
  , ComponentPlatformCertConfig(..)
  , AttributeCertIdConfig(..)
  , GenericCertIdConfig(..)
  , IssuerNameConfig(..)
  , PropertyConfig(..)
  , ComponentClassConfig(..)

  -- * Configuration Loading
  , loadConfig
  , loadDeltaConfig
  , createExampleConfig

  -- * Default Values
  , createDefaultTPMInfo
  , yamlComponentToComponentIdentifier
  , configToExtendedAttrs
  , deltaConfigToExtendedAttrs
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Base64 as B64
import Data.ASN1.Types
import Data.ASN1.Types.String ()
import Data.Char (toUpper)
import Data.Maybe (fromMaybe, mapMaybe, catMaybes)
import Data.X509.TCG
import Data.Aeson (Options(..), defaultOptions, genericParseJSON, genericToJSON)
import Data.Yaml (FromJSON (..), ToJSON (..), decodeFileEither, encodeFile)
import GHC.Generics (Generic)
import Text.Read (readMaybe)

-- | Custom JSON options to strip field prefixes
-- This allows YAML files to use simpler field names like "manufacturer" instead of "pccManufacturer"
componentOptions :: Options
componentOptions = defaultOptions { fieldLabelModifier = dropPrefix "cc" }

platformOptions :: Options
platformOptions = defaultOptions { fieldLabelModifier = dropPrefix "pcc" }

securityOptions :: Options
securityOptions = defaultOptions { fieldLabelModifier = dropPrefix "sac" }

deltaOptions :: Options
deltaOptions = defaultOptions { fieldLabelModifier = dropPrefix "dcc" }

changeOptions :: Options
changeOptions = defaultOptions { fieldLabelModifier = dropPrefix "chg" }

-- | Drop a prefix from field name and lowercase the first character
dropPrefix :: String -> String -> String
dropPrefix prefix field
  | prefix `isPrefixOf` field = lowercaseFirst (drop (length prefix) field)
  | otherwise = field
  where
    isPrefixOf :: String -> String -> Bool
    isPrefixOf [] _ = True
    isPrefixOf _ [] = False
    isPrefixOf (x:xs) (y:ys) = x == y && isPrefixOf xs ys

    lowercaseFirst :: String -> String
    lowercaseFirst [] = []
    lowercaseFirst (c:cs) = toLower c : cs

    toLower :: Char -> Char
    toLower c
      | c >= 'A' && c <= 'Z' = toEnum (fromEnum c + 32)
      | otherwise = c

-- | Address configuration for component addresses
-- Supports all TCG Platform Certificate defined address types
data AddressConfig = AddressConfig
  { addrEthernetMac :: Maybe String    -- ^ IEEE 802 MAC Address (OID: 2.23.133.17.1)
  , addrWlanMac :: Maybe String        -- ^ IEEE 802.11 Wireless MAC (OID: 2.23.133.17.2)
  , addrBluetoothMac :: Maybe String   -- ^ Bluetooth Device Address (OID: 2.23.133.17.3)
  , addrPciAddress :: Maybe String     -- ^ PCI bus address (OID: 2.23.133.17.4)
  , addrUsbAddress :: Maybe String     -- ^ USB bus address (OID: 2.23.133.17.5)
  , addrSataAddress :: Maybe String    -- ^ SATA/SAS bus path (OID: 2.23.133.17.6)
  , addrWwnAddress :: Maybe String     -- ^ World Wide Name (OID: 2.23.133.17.7)
  , addrNvmeAddress :: Maybe String    -- ^ NVMe device address (OID: 2.23.133.17.8)
  , addrLogicalAddress :: Maybe String -- ^ Logical/software-defined address (OID: 2.23.133.17.9)
  } deriving (Show, Eq, Generic)

addressOptions :: Options
addressOptions = defaultOptions { fieldLabelModifier = dropPrefix "addr" }

instance FromJSON AddressConfig where
  parseJSON = genericParseJSON addressOptions
instance ToJSON AddressConfig where
  toJSON = genericToJSON addressOptions

-- | URI Reference configuration with optional hash for integrity verification
-- Per TCG Platform Certificate Profile, URIReference allows specifying
-- a hash of the referenced document to ensure integrity.
data URIReferenceConfig = URIReferenceConfig
  { uriUri :: String                     -- Uniform Resource Identifier
  , uriHashAlgorithm :: Maybe String     -- Hash algorithm: "sha256", "sha384", "sha512"
  , uriHashValue :: Maybe String         -- Base64-encoded hash value of the document
  } deriving (Show, Eq, Generic)

uriOptions :: Options
uriOptions = defaultOptions { fieldLabelModifier = dropPrefix "uri" }

instance FromJSON URIReferenceConfig where
  parseJSON = genericParseJSON uriOptions
instance ToJSON URIReferenceConfig where
  toJSON = genericToJSON uriOptions

-- | Issuer Name component (for Distinguished Name)
data IssuerNameConfig = IssuerNameConfig
  { inOid :: String    -- OID like "2.5.4.6" (Country), "2.5.4.10" (Organization)
  , inValue :: String  -- The actual value
  } deriving (Show, Eq, Generic)

issuerNameOptions :: Options
issuerNameOptions = defaultOptions { fieldLabelModifier = dropPrefix "in" }

instance FromJSON IssuerNameConfig where
  parseJSON = genericParseJSON issuerNameOptions
instance ToJSON IssuerNameConfig where
  toJSON = genericToJSON issuerNameOptions

-- | Attribute Certificate Identifier (hash-based)
data AttributeCertIdConfig = AttributeCertIdConfig
  { acidHashAlgorithm :: String     -- OID or name: "sha256", "sha384"
  , acidHashValue :: String         -- Hex-encoded hash over signature value
  } deriving (Show, Eq, Generic)

attrCertIdOptions :: Options
attrCertIdOptions = defaultOptions { fieldLabelModifier = dropPrefix "acid" }

instance FromJSON AttributeCertIdConfig where
  parseJSON = genericParseJSON attrCertIdOptions
instance ToJSON AttributeCertIdConfig where
  toJSON = genericToJSON attrCertIdOptions

-- | Generic Certificate Identifier (issuer + serial)
data GenericCertIdConfig = GenericCertIdConfig
  { gcidIssuer :: [IssuerNameConfig]  -- Distinguished name components
  , gcidSerial :: String              -- Certificate serial number
  } deriving (Show, Eq, Generic)

genericCertIdOptions :: Options
genericCertIdOptions = defaultOptions { fieldLabelModifier = dropPrefix "gcid" }

instance FromJSON GenericCertIdConfig where
  parseJSON = genericParseJSON genericCertIdOptions
instance ToJSON GenericCertIdConfig where
  toJSON = genericToJSON genericCertIdOptions

-- | Platform Certificate reference for a component
-- References another Platform Certificate that attests this component
data ComponentPlatformCertConfig = ComponentPlatformCertConfig
  { cpcAttributeCertId :: Maybe AttributeCertIdConfig   -- Hash-based identifier
  , cpcGenericCertId :: Maybe GenericCertIdConfig       -- Issuer+Serial identifier
  } deriving (Show, Eq, Generic)

platformCertRefOptions :: Options
platformCertRefOptions = defaultOptions { fieldLabelModifier = dropPrefix "cpc" }

instance FromJSON ComponentPlatformCertConfig where
  parseJSON = genericParseJSON platformCertRefOptions
instance ToJSON ComponentPlatformCertConfig where
  toJSON = genericToJSON platformCertRefOptions

-- | Component Class configuration with registry and value
-- Per TCG Platform Certificate Profile, ComponentClass contains:
-- - componentClassRegistry: OID identifying the registry (e.g., "2.23.133.18.3.1" for TCG)
-- - componentClassValue: The class value within that registry
data ComponentClassConfig = ComponentClassConfig
  { cccRegistry :: String    -- OID like "2.23.133.18.3.1" (TCG Registry)
  , cccValue :: String       -- Hex value like "00030003"
  } deriving (Show, Eq, Generic)

componentClassOptions :: Options
componentClassOptions = defaultOptions { fieldLabelModifier = dropPrefix "ccc" }

instance FromJSON ComponentClassConfig where
  parseJSON = genericParseJSON componentClassOptions
instance ToJSON ComponentClassConfig where
  toJSON = genericToJSON componentClassOptions

-- | Platform Property configuration (name-value pairs)
-- Per TCG Platform Certificate Profile v1.1, PlatformProperties contains:
-- - propertyName: Name of the property
-- - propertyValue: Value of the property
-- - propertyStatus: Optional status for Delta certificates (ADDED, MODIFIED, REMOVED)
data PropertyConfig = PropertyConfig
  { propName :: String
  , propValue :: String
  , propStatus :: Maybe String   -- "ADDED", "MODIFIED", "REMOVED" for Delta certs
  } deriving (Show, Eq, Generic)

propertyOptions :: Options
propertyOptions = defaultOptions { fieldLabelModifier = dropPrefix "prop" }

instance FromJSON PropertyConfig where
  parseJSON = genericParseJSON propertyOptions
instance ToJSON PropertyConfig where
  toJSON = genericToJSON propertyOptions

-- | YAML Configuration for Platform Certificate components
data ComponentConfig = ComponentConfig
  { ccComponentClass :: Maybe ComponentClassConfig  -- Full component class with registry
  , ccClass :: String                    -- Simple class value (for backwards compatibility)
  , ccManufacturer :: String
  , ccModel :: String
  , ccSerial :: Maybe String             -- Optional per TCG spec
  , ccRevision :: Maybe String           -- Optional per TCG spec
  , ccManufacturerId :: Maybe String     -- Manufacturer OID (Private Enterprise Number)
  , ccFieldReplaceable :: Maybe Bool     -- Field replaceable flag
  , ccAddresses :: Maybe [AddressConfig] -- Network addresses (MAC, etc.)
  , ccPlatformCert :: Maybe ComponentPlatformCertConfig  -- Reference to component's Platform Certificate
  , ccPlatformCertUri :: Maybe URIReferenceConfig        -- URI to component's Platform Certificate
  , ccStatus :: Maybe String             -- "ADDED", "MODIFIED", "REMOVED" for Delta certs
  } deriving (Show, Eq, Generic)

instance FromJSON ComponentConfig where
  parseJSON = genericParseJSON componentOptions
instance ToJSON ComponentConfig where
  toJSON = genericToJSON componentOptions

-- | YAML Configuration for Platform Certificates
data PlatformCertConfig = PlatformCertConfig
  { pccManufacturer :: String
  , pccModel :: String
  , pccVersion :: String
  , pccSerial :: String
  , pccManufacturerId :: Maybe String   -- Platform Manufacturer OID (Private Enterprise Number)
  , pccValidityDays :: Maybe Int
  , pccKeySize :: Maybe Int
  , pccComponents :: [ComponentConfig]
  , pccProperties :: Maybe [PropertyConfig]  -- Platform properties (name-value pairs)
  -- URI References
  , pccPlatformConfigUri :: Maybe URIReferenceConfig  -- Platform Config URI with optional hash
  , pccComponentsUri :: Maybe URIReferenceConfig      -- External components list URI
  , pccPropertiesUri :: Maybe URIReferenceConfig      -- External properties list URI
  -- Extended fields
  , pccPlatformClass :: Maybe String
  , pccSpecificationVersion :: Maybe String
  , pccMajorVersion :: Maybe Int
  , pccMinorVersion :: Maybe Int
  , pccPatchVersion :: Maybe Int
  , pccPlatformQualifier :: Maybe String
  -- TCG Credential fields (IWG v1.1)
  , pccCredentialSpecMajor :: Maybe Int   -- TCG Credential Specification major version
  , pccCredentialSpecMinor :: Maybe Int   -- TCG Credential Specification minor version
  , pccCredentialSpecRevision :: Maybe Int -- TCG Credential Specification revision
  -- Platform Specification fields (IWG v1.1)
  , pccPlatformSpecMajor :: Maybe Int     -- Platform specification major version
  , pccPlatformSpecMinor :: Maybe Int     -- Platform specification minor version
  , pccPlatformSpecRevision :: Maybe Int   -- Platform specification revision
  -- TBB Security Assertions (2.23.133.2.19)
  , pccSecurityAssertions :: Maybe SecurityAssertionsConfig
  } deriving (Show, Eq, Generic)

-- | Security Assertions Configuration for TBB Security Assertions attribute
data SecurityAssertionsConfig = SecurityAssertionsConfig
  { sacVersion :: Maybe Int                    -- Security assertions version (default: 0)
  -- Common Criteria fields
  , sacCCVersion :: Maybe String               -- CC Version (e.g., "3.1")
  , sacEvalAssuranceLevel :: Maybe Int         -- EAL1-7
  , sacEvalStatus :: Maybe String              -- "evaluationInProgress", "evaluationCompleted", etc.
  , sacPlus :: Maybe Bool                      -- Plus indicator
  , sacStrengthOfFunction :: Maybe String      -- "basic", "medium", "high"
  , sacProtectionProfileOID :: Maybe String    -- Protection Profile OID
  , sacProtectionProfileURI :: Maybe String    -- Protection Profile URI
  , sacSecurityTargetOID :: Maybe String       -- Security Target OID
  , sacSecurityTargetURI :: Maybe String       -- Security Target URI
  -- FIPS Level fields
  , sacFIPSVersion :: Maybe String             -- FIPS version (e.g., "140-2")
  , sacFIPSSecurityLevel :: Maybe Int          -- Security Level 1-4
  , sacFIPSPlus :: Maybe Bool                  -- FIPS Plus indicator
  -- RTM Type
  , sacRTMType :: Maybe String                 -- "static", "dynamic", "hybrid"
  -- ISO 9000
  , sacISO9000Certified :: Maybe Bool          -- ISO 9000 Certified
  , sacISO9000URI :: Maybe String              -- ISO 9000 URI
  } deriving (Show, Eq, Generic)

instance FromJSON SecurityAssertionsConfig where
  parseJSON = genericParseJSON securityOptions
instance ToJSON SecurityAssertionsConfig where
  toJSON = genericToJSON securityOptions

instance FromJSON PlatformCertConfig where
  parseJSON = genericParseJSON platformOptions
instance ToJSON PlatformCertConfig where
  toJSON = genericToJSON platformOptions

-- | YAML Configuration for Delta Platform Certificates
data DeltaCertConfig = DeltaCertConfig
  { dccManufacturer :: String
  , dccModel :: String
  , dccVersion :: String
  , dccSerial :: String
  , dccValidityDays :: Maybe Int
  , dccKeySize :: Maybe Int
  , dccComponents :: [ComponentConfig]
  -- Extended fields
  , dccPlatformConfigUri :: Maybe URIReferenceConfig  -- Platform Config URI with optional hash
  , dccPlatformClass :: Maybe String
  , dccSpecificationVersion :: Maybe String
  , dccMajorVersion :: Maybe Int
  , dccMinorVersion :: Maybe Int
  , dccPatchVersion :: Maybe Int
  , dccPlatformQualifier :: Maybe String
  -- Delta-specific fields
  , dccBaseCertificateSerial :: Maybe String
  , dccDeltaSequenceNumber :: Maybe Int
  , dccChangeDescription :: Maybe String
  } deriving (Show, Eq, Generic)

instance FromJSON DeltaCertConfig where
  parseJSON = genericParseJSON deltaOptions
instance ToJSON DeltaCertConfig where
  toJSON = genericToJSON deltaOptions

-- | Component Change Configuration for Delta certificates
data ComponentChangeConfig = ComponentChangeConfig
  { chgChangeType :: String
  , chgClass :: String
  , chgManufacturer :: String
  , chgModel :: String
  , chgSerial :: String
  , chgRevision :: String
  , chgPreviousRevision :: Maybe String
  } deriving (Show, Eq, Generic)

instance FromJSON ComponentChangeConfig where
  parseJSON = genericParseJSON changeOptions
instance ToJSON ComponentChangeConfig where
  toJSON = genericToJSON changeOptions

-- | Load YAML configuration file
loadConfig :: FilePath -> IO (Either String PlatformCertConfig)
loadConfig file = do
  result <- decodeFileEither file
  return $ case result of
    Left err -> Left (show err)
    Right config -> Right config

-- | Load Delta YAML configuration file
loadDeltaConfig :: FilePath -> IO (Either String DeltaCertConfig)
loadDeltaConfig file = do
  result <- decodeFileEither file
  return $ case result of
    Left err -> Left (show err)
    Right config -> Right config

-- | Create example YAML configuration file
createExampleConfig :: FilePath -> IO ()
createExampleConfig file = do
  let exampleConfig = PlatformCertConfig
        { pccManufacturer = "Test Corporation"
        , pccModel = "Test Platform"
        , pccVersion = "1.0"
        , pccSerial = "TEST001"
        , pccManufacturerId = Just "1.3.6.1.4.1.99999"  -- Example Private Enterprise Number
        , pccValidityDays = Just 365
        , pccKeySize = Just 2048
        -- Platform properties (name-value pairs)
        , pccProperties = Just
            [ PropertyConfig
                { propName = "firmware.version"
                , propValue = "1.2.3"
                , propStatus = Nothing
                }
            , PropertyConfig
                { propName = "bios.vendor"
                , propValue = "Test BIOS Inc."
                , propStatus = Nothing
                }
            ]
        -- Platform Config URI with optional hash for integrity verification
        -- Per TCG Platform Certificate Profile v1.1, URIReference includes hashAlgorithm and hashValue
        , pccPlatformConfigUri = Just URIReferenceConfig
            { uriUri = "https://example.com/platform-config/pcr-values"
            , uriHashAlgorithm = Just "sha256"
            -- Example: SHA-256 hash of the referenced document (base64-encoded)
            , uriHashValue = Just "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
            }
        , pccComponentsUri = Nothing    -- External components list URI
        , pccPropertiesUri = Nothing    -- External properties list URI
        , pccPlatformClass = Just "00000001"
        , pccSpecificationVersion = Just "1.1"
        , pccMajorVersion = Just 1
        , pccMinorVersion = Just 0
        , pccPatchVersion = Just 0
        , pccPlatformQualifier = Just "Enterprise"
        , pccCredentialSpecMajor = Just 1
        , pccCredentialSpecMinor = Just 1
        , pccCredentialSpecRevision = Just 13
        , pccPlatformSpecMajor = Just 2
        , pccPlatformSpecMinor = Just 0
        , pccPlatformSpecRevision = Just 164
        , pccSecurityAssertions = Just SecurityAssertionsConfig
            { sacVersion = Just 0
            , sacCCVersion = Just "3.1"
            , sacEvalAssuranceLevel = Just 4
            , sacEvalStatus = Just "evaluationCompleted"
            , sacPlus = Just False
            , sacStrengthOfFunction = Just "medium"
            , sacProtectionProfileOID = Nothing
            , sacProtectionProfileURI = Nothing
            , sacSecurityTargetOID = Nothing
            , sacSecurityTargetURI = Nothing
            , sacFIPSVersion = Just "140-2"
            , sacFIPSSecurityLevel = Just 2
            , sacFIPSPlus = Just False
            , sacRTMType = Just "hybrid"
            , sacISO9000Certified = Just False
            , sacISO9000URI = Nothing
            }
        , pccComponents =
            [ ComponentConfig
                { ccComponentClass = Just ComponentClassConfig
                    { cccRegistry = "2.23.133.18.3.1"  -- TCG Component Class Registry
                    , cccValue = "00030003"            -- Motherboard
                    }
                , ccClass = "00030003"  -- TCG Registry: Motherboard (backwards compatibility)
                , ccManufacturer = "Test Corporation"
                , ccModel = "Test Platform Motherboard"
                , ccSerial = Just "MB-TEST001"
                , ccRevision = Just "1.0"
                , ccManufacturerId = Just "1.3.6.1.4.1.99999"
                , ccFieldReplaceable = Just True
                , ccAddresses = Nothing
                , ccPlatformCert = Nothing
                , ccPlatformCertUri = Nothing
                , ccStatus = Nothing
                }
            , ComponentConfig
                { ccComponentClass = Just ComponentClassConfig
                    { cccRegistry = "2.23.133.18.3.1"
                    , cccValue = "00010002"            -- CPU
                    }
                , ccClass = "00010002"  -- TCG Registry: CPU
                , ccManufacturer = "Intel Corporation"
                , ccModel = "Xeon E5-2680"
                , ccSerial = Just "CPU-TEST001"
                , ccRevision = Just "Rev C0"
                , ccManufacturerId = Just "1.3.6.1.4.1.343"  -- Intel's Private Enterprise Number
                , ccFieldReplaceable = Just False
                , ccAddresses = Nothing
                , ccPlatformCert = Nothing
                , ccPlatformCertUri = Nothing
                , ccStatus = Nothing
                }
            , ComponentConfig
                { ccComponentClass = Just ComponentClassConfig
                    { cccRegistry = "2.23.133.18.3.1"
                    , cccValue = "00060004"            -- DRAM Memory
                    }
                , ccClass = "00060004"  -- TCG Registry: DRAM Memory
                , ccManufacturer = "Samsung"
                , ccModel = "DDR4-3200"
                , ccSerial = Just "MEM-TEST001"
                , ccRevision = Just "1.35V"
                , ccManufacturerId = Just "1.3.6.1.4.1.236"  -- Samsung's Private Enterprise Number
                , ccFieldReplaceable = Just True
                , ccAddresses = Nothing
                , ccPlatformCert = Nothing
                , ccPlatformCertUri = Nothing
                , ccStatus = Nothing
                }
            ]
        }
  encodeFile file exampleConfig
  putStrLn $ "Example configuration created: " ++ file

-- | Create default TPM 2.0 information based on standard specification
createDefaultTPMInfo :: TPMInfo
createDefaultTPMInfo = TPMInfo
  { tpmModel = BC.pack "TPM 2.0"
  , tpmVersion = TPMVersion
      { tpmVersionMajor = 2
      , tpmVersionMinor = 0
      , tpmVersionRevMajor = 1
      , tpmVersionRevMinor = 59  -- Current TPM 2.0 revision as of 2023
      }
  , tpmSpecification = TPMSpecification
      { tpmSpecFamily = BC.pack "2.0"
      , tpmSpecLevel = 0
      , tpmSpecRevision = 164  -- TPM 2.0 Library Specification revision 164
      }
  }

-- | Convert YAML ComponentConfig to TCG ComponentIdentifier
yamlComponentToComponentIdentifier :: ComponentConfig -> ComponentIdentifier
yamlComponentToComponentIdentifier config =
  ComponentIdentifier
    { ciManufacturer = BC.pack (ccManufacturer config)
    , ciModel = BC.pack (ccModel config)
    , ciSerial = fmap BC.pack (ccSerial config)
    , ciRevision = fmap BC.pack (ccRevision config)
    , ciManufacturerSerial = Nothing
    , ciManufacturerRevision = Nothing
    }

-- | Convert PlatformCertConfig to ExtendedTCGAttributes
configToExtendedAttrs :: PlatformCertConfig -> ExtendedTCGAttributes
configToExtendedAttrs config =
  ExtendedTCGAttributes
    { etaPlatformConfigUri = fmap convertUriConfig (pccPlatformConfigUri config)
    , etaPlatformClass = fmap parseHexClass (pccPlatformClass config)
    , etaCredentialSpecVersion = buildVersion (pccCredentialSpecMajor config)
                                              (pccCredentialSpecMinor config)
                                              (pccCredentialSpecRevision config)
    , etaPlatformSpecVersion = buildVersion (pccPlatformSpecMajor config)
                                            (pccPlatformSpecMinor config)
                                            (pccPlatformSpecRevision config)
    , etaSecurityAssertions = fmap convertSecurityAssertions (pccSecurityAssertions config)
    , etaComponentsV2 = case pccComponents config of
        [] -> Nothing
        comps -> Just (map convertComponentToV2 comps)
    , etaCredentialTypeOid = Nothing
    , etaHolderBaseCertificateID = Nothing
    , etaExtensions = Nothing
    , etaIssuerDN = Nothing
    , etaSerialNumber = Nothing
    , etaNotBefore = Nothing
    , etaNotAfter = Nothing
    }
  where
    -- Convert URIReferenceConfig to PlatformConfigUri
    -- Per TCG Platform Certificate Profile v1.1, URIReference includes optional hash fields
    convertUriConfig :: URIReferenceConfig -> PlatformConfigUri
    convertUriConfig uriCfg = PlatformConfigUri
      { pcUri = BC.pack (uriUri uriCfg)
      , pcHashAlgorithm = fmap BC.pack (uriHashAlgorithm uriCfg)
      , pcHashValue = case uriHashValue uriCfg of
          Just b64Str -> case B64.decode (BC.pack b64Str) of
            Right decoded -> Just decoded
            Left _ -> Nothing  -- Invalid base64, ignore
          Nothing -> Nothing
      }

    -- Convert ComponentConfig to ComponentConfigV2 for platformConfiguration-v2 encoding
    convertComponentToV2 :: ComponentConfig -> ComponentConfigV2
    convertComponentToV2 comp = ComponentConfigV2
      { ccv2Class = parseHexClass (ccClass comp)
      , ccv2Manufacturer = BC.pack (ccManufacturer comp)
      , ccv2Model = BC.pack (ccModel comp)
      , ccv2Serial = fmap BC.pack (ccSerial comp)
      , ccv2Revision = fmap BC.pack (ccRevision comp)
      , ccv2ManufacturerId = fmap parseOidString (ccManufacturerId comp)
      , ccv2FieldReplaceable = ccFieldReplaceable comp
      , ccv2Addresses = case ccAddresses comp of
          Just addrs -> let pairs = concatMap addressConfigToPairs addrs
                        in if null pairs then Nothing else Just pairs
          Nothing -> Nothing
      , ccv2PlatformCert = fmap encodeComponentPlatformCert (ccPlatformCert comp)
      , ccv2PlatformCertUri = fmap encodeComponentCertUri (ccPlatformCertUri comp)
      , ccv2Status = Nothing
      }

    -- Parse hex class string to ByteString (e.g., "00000001" -> "\x00\x00\x00\x01")
    parseHexClass :: String -> BC.ByteString
    parseHexClass hexStr =
      let -- Remove any spaces and group by 2 characters
          hexBytes = groupsOf 2 hexStr
          -- Convert each pair of hex digits to a Word8
          bytes = map (read . ("0x" ++)) hexBytes :: [Int]
      in BC.pack $ map (toEnum :: Int -> Char) bytes

    -- Convert SecurityAssertionsConfig to TBBSecurityAssertions
    convertSecurityAssertions :: SecurityAssertionsConfig -> TBBSecurityAssertions
    convertSecurityAssertions sac = TBBSecurityAssertions
      { tbbVersion = fromMaybe 0 (sacVersion sac)
      , tbbCCVersion = fmap BC.pack (sacCCVersion sac)
      , tbbEvalAssuranceLevel = sacEvalAssuranceLevel sac
      , tbbEvalStatus = fmap parseEvalStatus (sacEvalStatus sac)
      , tbbPlus = sacPlus sac
      , tbbStrengthOfFunction = fmap parseStrengthOfFunction (sacStrengthOfFunction sac)
      , tbbProtectionProfileOID = fmap (oidToContentBytes . parseOidString) (sacProtectionProfileOID sac)
      , tbbProtectionProfileURI = fmap BC.pack (sacProtectionProfileURI sac)
      , tbbSecurityTargetOID = fmap (oidToContentBytes . parseOidString) (sacSecurityTargetOID sac)
      , tbbSecurityTargetURI = fmap BC.pack (sacSecurityTargetURI sac)
      , tbbFIPSVersion = fmap BC.pack (sacFIPSVersion sac)
      , tbbFIPSSecurityLevel = sacFIPSSecurityLevel sac
      , tbbFIPSPlus = sacFIPSPlus sac
      , tbbRTMType = fmap parseRTMType (sacRTMType sac)
      , tbbISO9000Certified = sacISO9000Certified sac
      , tbbISO9000URI = fmap BC.pack (sacISO9000URI sac)
      }

    -- Parse evaluation status string to integer per ASN.1:
    -- designedToMeet(0), evaluationInProgress(1), evaluationCompleted(2)
    parseEvalStatus :: String -> Int
    parseEvalStatus "designedToMeet" = 0
    parseEvalStatus "evaluationInProgress" = 1
    parseEvalStatus "evaluationCompleted" = 2
    parseEvalStatus "evaluationWithdrawn" = 3
    parseEvalStatus _ = 2 -- default to completed

    -- Parse strength of function string to integer
    parseStrengthOfFunction :: String -> Int
    parseStrengthOfFunction "basic" = 0
    parseStrengthOfFunction "medium" = 1
    parseStrengthOfFunction "high" = 2
    parseStrengthOfFunction _ = 1 -- default to medium

    -- Parse RTM type string to integer
    parseRTMType :: String -> Int
    parseRTMType "static" = 0
    parseRTMType "dynamic" = 1
    parseRTMType "nonHosted" = 2
    parseRTMType "hybrid" = 3
    parseRTMType "physical" = 4
    parseRTMType "virtual" = 5
    parseRTMType _ = 0 -- default to static

    groupsOf :: Int -> [a] -> [[a]]
    groupsOf _ [] = []
    groupsOf n xs = take n xs : groupsOf n (drop n xs)

    buildVersion :: Maybe Int -> Maybe Int -> Maybe Int -> Maybe (Int, Int, Int)
    buildVersion (Just maj) (Just minor) (Just rev) = Just (maj, minor, rev)
    buildVersion _ _ _ = Nothing

    -- Parse dotted OID string "1.2.3.4" to OID [Integer]
    parseOidString :: String -> OID
    parseOidString s = mapMaybe readMaybe (splitOn '.' s)

    splitOn :: Char -> String -> [String]
    splitOn _ [] = []
    splitOn c s = let (w, rest) = break (== c) s
                  in w : case rest of
                           [] -> []
                           (_:xs) -> splitOn c xs

    -- Convert AddressConfig fields to (OID, ByteString) pairs
    -- addressValue is UTF8String per ASN.1 spec, so keep hex string as-is
    addressConfigToPairs :: AddressConfig -> [(OID, B.ByteString)]
    addressConfigToPairs addr = catMaybes
      [ fmap (\m -> ([2,23,133,17,1], BC.pack m)) (addrEthernetMac addr)
      , fmap (\m -> ([2,23,133,17,2], BC.pack m)) (addrWlanMac addr)
      , fmap (\m -> ([2,23,133,17,3], BC.pack m)) (addrBluetoothMac addr)
      , fmap (\m -> ([2,23,133,17,4], BC.pack m)) (addrPciAddress addr)
      , fmap (\m -> ([2,23,133,17,5], BC.pack m)) (addrUsbAddress addr)
      , fmap (\m -> ([2,23,133,17,6], BC.pack m)) (addrSataAddress addr)
      , fmap (\m -> ([2,23,133,17,7], BC.pack m)) (addrWwnAddress addr)
      , fmap (\m -> ([2,23,133,17,8], BC.pack m)) (addrNvmeAddress addr)
      , fmap (\m -> ([2,23,133,17,9], BC.pack m)) (addrLogicalAddress addr)
      ]

    -- Encode ComponentPlatformCertConfig to ASN1 list for [5] CertificateIdentifier
    encodeComponentPlatformCert :: ComponentPlatformCertConfig -> [ASN1]
    encodeComponentPlatformCert cpc =
      let attrCertId = case cpcAttributeCertId cpc of
            Just acid ->
              let hashAlgOid = parseOidString (acidHashAlgorithm acid)
                  hashBytes = case B64.decode (BC.pack (acidHashValue acid)) of
                    Right decoded -> decoded
                    Left _ -> BC.pack (acidHashValue acid) -- fallback to raw
              in [ Start (Container Context 0)    -- [0] AttributeCertIdentifier
                 , Start Sequence, OID hashAlgOid, End Sequence  -- AlgorithmIdentifier
                 , OctetString hashBytes           -- hashOverSignatureValue
                 , End (Container Context 0)
                 ]
            Nothing -> []
          genericCertId = case cpcGenericCertId cpc of
            Just gcid ->
              let -- Build DN from IssuerNameConfig list: each has oid + value
                  dnRdns = concatMap issuerNameToRdn (gcidIssuer gcid)
                  serialNum = case readMaybe (gcidSerial gcid) :: Maybe Integer of
                    Just n -> n
                    Nothing -> 0
              in [ Start (Container Context 1)    -- [1] IssuerSerial
                 , Start Sequence                 -- GeneralNames
                 , Start (Container Context 4)    -- directoryName [4]
                 , Start Sequence                 -- RDNSequence
                 ] ++ dnRdns ++
                 [ End Sequence                   -- end RDNSequence
                 , End (Container Context 4)
                 , End Sequence                   -- end GeneralNames
                 , IntVal serialNum               -- CertificateSerialNumber
                 , End (Container Context 1)
                 ]
            Nothing -> []
      in attrCertId ++ genericCertId

    -- Convert IssuerNameConfig to ASN1 RDN (SET { SEQUENCE { OID, value } })
    -- RFC 5280: countryName (2.5.4.6) MUST use PrintableString
    issuerNameToRdn :: IssuerNameConfig -> [ASN1]
    issuerNameToRdn inc =
      let oid = parseOidString (inOid inc)
          strType = if oid == [2,5,4,6] then Printable else UTF8
      in [ Start Set
         , Start Sequence
         , OID oid
         , ASN1String (ASN1CharacterString strType (BC.pack (inValue inc)))
         , End Sequence
         , End Set
         ]

    -- Encode URIReferenceConfig to ASN1 list for [6] URIReference
    encodeComponentCertUri :: URIReferenceConfig -> [ASN1]
    encodeComponentCertUri cfg =
      [ASN1String (ASN1CharacterString IA5 (BC.pack (uriUri cfg)))]

-- | Convert DeltaCertConfig to ExtendedTCGAttributes.
-- Delta generation requires component status and Delta credential type.
deltaConfigToExtendedAttrs :: DeltaCertConfig -> Either String ExtendedTCGAttributes
deltaConfigToExtendedAttrs config = do
  comps <- mapM convertDeltaComponentToV2 (dccComponents config)
  return ExtendedTCGAttributes
    { etaPlatformConfigUri = fmap convertUriConfig (dccPlatformConfigUri config)
    , etaPlatformClass = fmap parseHexClass (dccPlatformClass config)
    , etaCredentialSpecVersion = Nothing
    , etaPlatformSpecVersion = Nothing
    , etaSecurityAssertions = Nothing
    , etaComponentsV2 = Just comps
    , etaCredentialTypeOid = Just tcg_kp_DeltaAttributeCertificate
    , etaHolderBaseCertificateID = Nothing
    , etaExtensions = Nothing
    , etaIssuerDN = Nothing
    , etaSerialNumber = Nothing
    , etaNotBefore = Nothing
    , etaNotAfter = Nothing
    }
  where
    convertUriConfig :: URIReferenceConfig -> PlatformConfigUri
    convertUriConfig uriCfg = PlatformConfigUri
      { pcUri = BC.pack (uriUri uriCfg)
      , pcHashAlgorithm = fmap BC.pack (uriHashAlgorithm uriCfg)
      , pcHashValue = case uriHashValue uriCfg of
          Just b64Str -> case B64.decode (BC.pack b64Str) of
            Right decoded -> Just decoded
            Left _ -> Nothing
          Nothing -> Nothing
      }

    convertDeltaComponentToV2 :: ComponentConfig -> Either String ComponentConfigV2
    convertDeltaComponentToV2 comp = do
      status <- parseComponentStatus (ccStatus comp) (ccManufacturer comp) (ccModel comp)
      return ComponentConfigV2
        { ccv2Class = parseHexClass (ccClass comp)
        , ccv2Manufacturer = BC.pack (ccManufacturer comp)
        , ccv2Model = BC.pack (ccModel comp)
        , ccv2Serial = fmap BC.pack (ccSerial comp)
        , ccv2Revision = fmap BC.pack (ccRevision comp)
        , ccv2ManufacturerId = fmap parseOidString' (ccManufacturerId comp)
        , ccv2FieldReplaceable = ccFieldReplaceable comp
        , ccv2Addresses = case ccAddresses comp of
            Just addrs -> let pairs = concatMap addressConfigToPairs' addrs
                          in if null pairs then Nothing else Just pairs
            Nothing -> Nothing
        , ccv2PlatformCert = Nothing  -- Delta certs typically don't have platformCert refs
        , ccv2PlatformCertUri = Nothing
        , ccv2Status = Just status
        }

    parseComponentStatus :: Maybe String -> String -> String -> Either String ComponentStatus
    parseComponentStatus Nothing mfg mdl =
      Left $ "Delta component status is required for " ++ mfg ++ " / " ++ mdl
    parseComponentStatus (Just rawStatus) _ _ =
      case map toUpper rawStatus of
        "ADDED" -> Right ComponentAdded
        "MODIFIED" -> Right ComponentModified
        "REMOVED" -> Right ComponentRemoved
        other -> Left $ "Unsupported delta component status: " ++ other ++ " (expected ADDED|MODIFIED|REMOVED)"

    parseHexClass :: String -> BC.ByteString
    parseHexClass hexStr =
      let hexBytes = groupsOf 2 hexStr
          bytes = map (read . ("0x" ++)) hexBytes :: [Int]
      in BC.pack $ map (toEnum :: Int -> Char) bytes

    groupsOf :: Int -> [a] -> [[a]]
    groupsOf _ [] = []
    groupsOf n xs = take n xs : groupsOf n (drop n xs)

    parseOidString' :: String -> OID
    parseOidString' s = mapMaybe readMaybe (splitOn' '.' s)

    splitOn' :: Char -> String -> [String]
    splitOn' _ [] = []
    splitOn' c s = let (w, rest) = break (== c) s
                   in w : case rest of
                            [] -> []
                            (_:xs) -> splitOn' c xs

    addressConfigToPairs' :: AddressConfig -> [(OID, B.ByteString)]
    addressConfigToPairs' addr = catMaybes
      [ fmap (\m -> ([2,23,133,17,1], BC.pack m)) (addrEthernetMac addr)
      , fmap (\m -> ([2,23,133,17,2], BC.pack m)) (addrWlanMac addr)
      , fmap (\m -> ([2,23,133,17,3], BC.pack m)) (addrBluetoothMac addr)
      , fmap (\m -> ([2,23,133,17,4], BC.pack m)) (addrPciAddress addr)
      , fmap (\m -> ([2,23,133,17,5], BC.pack m)) (addrUsbAddress addr)
      , fmap (\m -> ([2,23,133,17,6], BC.pack m)) (addrSataAddress addr)
      , fmap (\m -> ([2,23,133,17,7], BC.pack m)) (addrWwnAddress addr)
      , fmap (\m -> ([2,23,133,17,8], BC.pack m)) (addrNvmeAddress addr)
      , fmap (\m -> ([2,23,133,17,9], BC.pack m)) (addrLogicalAddress addr)
      ]
