{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Data.X509.TCG.Util.Paccor
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Utility
-- Stability   : experimental
-- Portability : unknown
--
-- Support for NSA Cybersecurity paccor JSON format.
-- This module provides data types and functions to parse paccor JSON files
-- and convert them to the tcg-platform-cert-util YAML format.
--
-- paccor (Platform Attribute Certificate Creator) is a tool developed by
-- NSA Cybersecurity for creating TCG Platform Certificates.
-- See: https://github.com/nsacyber/paccor

module Data.X509.TCG.Util.Paccor
  ( -- * Paccor Data Types
    PaccorConfig(..)
  , PaccorPlatform(..)
  , PaccorComponent(..)
  , PaccorComponentClass(..)
  , PaccorProperty(..)
  , PaccorUri(..)
  , PaccorAddress(..)
    -- ** Platform Certificate Reference Types
  , PaccorPlatformCert(..)
  , PaccorAttributeCertId(..)
  , PaccorGenericCertId(..)
  , PaccorGeneralName(..)

    -- * PolicyReference Types
  , PaccorPolicyReference(..)
  , PaccorPlatformSpec(..)
  , PaccorSpecVersion(..)
  , PaccorTBBSecurityAssertions(..)
  , PaccorCCInfo(..)
  , PaccorFipsLevel(..)

    -- * Extensions Types
  , PaccorExtensions(..)
  , PaccorCertPolicy(..)
  , PaccorPolicyQualifier(..)
  , PaccorAIAEntry(..)
  , PaccorCRLDistPoint(..)
  , PaccorDistName(..)

    -- * Conversion Functions
  , paccorToYamlConfig
  , loadPaccorConfig
  , savePaccorAsYaml
  , loadPaccorPolicyReference
  , mergePolicyReference
  , loadPaccorExtensions
  , paccorExtensionsToX509
  , buildSanExtension
  , buildAkiExtension

    -- * Format Detection
  , InputFormat(..)
  , detectInputFormat
  , loadAnyConfig
  ) where

import Control.Applicative ((<|>))
import Data.Aeson hiding (encodeFile)
import Data.Aeson.Types (Parser)
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.Types
import Data.Word (Word8)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as BL
import Data.Maybe (catMaybes, isJust, mapMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Bits (shiftR, (.&.))
import Data.X509 (Extensions(..), ExtensionRaw(..), Certificate(..), ExtSubjectKeyId(..), extensionGet, certIssuerDN, certSerial, DistinguishedName(..))
import qualified Data.Yaml as Yaml
import GHC.Generics (Generic)
import Text.Read (readMaybe)

-- Local imports
import Data.X509.TCG.Util.Config

-- | Paccor JSON configuration structure
data PaccorConfig = PaccorConfig
  { paccorPlatform :: PaccorPlatform
  , paccorComponents :: Maybe [PaccorComponent]
  , paccorComponentsUri :: Maybe PaccorUri
  , paccorProperties :: Maybe [PaccorProperty]
  , paccorPropertiesUri :: Maybe PaccorUri
  } deriving (Show, Eq, Generic)

-- | Platform information from paccor JSON
data PaccorPlatform = PaccorPlatform
  { platformManufacturerStr :: Text
  , platformModel :: Text
  , platformVersion :: Maybe Text
  , platformSerial :: Maybe Text
  , platformManufacturerId :: Maybe Text  -- OID like "1.3.6.1.4.1.674"
  } deriving (Show, Eq, Generic)

-- | Private Enterprise Number structure (for array format)
data PaccorPEN = PaccorPEN
  { penValue :: Text
  } deriving (Show, Eq, Generic)

instance FromJSON PaccorPEN where
  parseJSON = withObject "PaccorPEN" $ \v ->
    PaccorPEN <$> v .: "PRIVATEENTERPRISENUMBER"

-- | Component class with registry and value
data PaccorComponentClass = PaccorComponentClass
  { componentClassRegistry :: Text    -- OID like "2.23.133.18.3.1"
  , componentClassValue :: Text       -- Hex value like "00000001"
  } deriving (Show, Eq, Generic)

-- | Component address
-- Supports MAC addresses (ETHERNETMAC, WLANMAC, BLUETOOTHMAC),
-- bus addresses (PCI, USB, SATA), and storage identifiers (WWN, NVMe).
-- Also supports OID-based format (ADDRESSTYPE, ADDRESSVALUE)
data PaccorAddress = PaccorAddress
  { paccorEthernetMac :: Maybe Text
  , paccorWlanMac :: Maybe Text
  , paccorBluetoothMac :: Maybe Text
  , paccorPciAddress :: Maybe Text      -- ^ PCI address (e.g., "0000:00:1f.6")
  , paccorUsbAddress :: Maybe Text      -- ^ USB address
  , paccorSataAddress :: Maybe Text     -- ^ SATA/SAS bus path
  , paccorWwnAddress :: Maybe Text      -- ^ World Wide Name
  , paccorNvmeAddress :: Maybe Text     -- ^ NVMe device address
  , paccorLogicalAddress :: Maybe Text  -- ^ Logical/software-defined address
  } deriving (Show, Eq, Generic)

-- | OID-based address format used in extended paccor JSON
data PaccorOIDAddress = PaccorOIDAddress
  { addressType :: Text   -- OID like "2.23.133.17.1" (Ethernet) or "2.23.133.17.2" (WLAN)
  , addressValue :: Text  -- MAC address value
  } deriving (Show, Eq, Generic)

instance FromJSON PaccorOIDAddress where
  parseJSON = withObject "PaccorOIDAddress" $ \v -> PaccorOIDAddress
    <$> v .: "ADDRESSTYPE"
    <*> v .: "ADDRESSVALUE"

-- | Convert OID-based address to simple format
oidAddressToSimple :: PaccorOIDAddress -> PaccorAddress
oidAddressToSimple addr = case T.unpack (addressType addr) of
  -- TCG defined OIDs for ComponentAddress types
  "2.23.133.17.1" -> emptyPaccorAddress { paccorEthernetMac = Just (addressValue addr) }  -- Ethernet
  "2.23.133.17.2" -> emptyPaccorAddress { paccorWlanMac = Just (addressValue addr) }      -- WLAN
  "2.23.133.17.3" -> emptyPaccorAddress { paccorBluetoothMac = Just (addressValue addr) } -- Bluetooth
  "2.23.133.17.4" -> emptyPaccorAddress { paccorPciAddress = Just (addressValue addr) }   -- PCI
  "2.23.133.17.5" -> emptyPaccorAddress { paccorUsbAddress = Just (addressValue addr) }   -- USB
  "2.23.133.17.6" -> emptyPaccorAddress { paccorSataAddress = Just (addressValue addr) }  -- SATA
  "2.23.133.17.7" -> emptyPaccorAddress { paccorWwnAddress = Just (addressValue addr) }   -- WWN
  "2.23.133.17.8" -> emptyPaccorAddress { paccorNvmeAddress = Just (addressValue addr) }  -- NVMe
  "2.23.133.17.9" -> emptyPaccorAddress { paccorLogicalAddress = Just (addressValue addr) } -- Logical
  _               -> emptyPaccorAddress { paccorEthernetMac = Just (addressValue addr) }  -- Default to Ethernet

-- | Empty PaccorAddress with all fields set to Nothing
emptyPaccorAddress :: PaccorAddress
emptyPaccorAddress = PaccorAddress Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing

-- | Component information from paccor JSON
data PaccorComponent = PaccorComponent
  { componentClass :: PaccorComponentClass
  , componentManufacturer :: Maybe Text
  , componentModel :: Maybe Text
  , componentSerial :: Maybe Text
  , componentRevision :: Maybe Text
  , componentManufacturerId :: Maybe Text  -- OID
  , componentFieldReplaceable :: Maybe Text -- "true" or "false"
  , componentAddresses :: Maybe [PaccorAddress]
  , componentStatus :: Maybe Text  -- "ADDED", "MODIFIED", "REMOVED"
  , componentPlatformCert :: Maybe PaccorPlatformCert     -- Component's Platform Certificate reference
  , componentPlatformCertUri :: Maybe PaccorUri           -- URI to component's Platform Certificate
  } deriving (Show, Eq, Generic)

-- | Property information from paccor JSON
data PaccorProperty = PaccorProperty
  { propertyName :: Text
  , propertyValue :: Text
  , propertyStatus :: Maybe Text  -- "ADDED", "MODIFIED", "REMOVED"
  } deriving (Show, Eq, Generic)

-- | URI reference with optional hash
data PaccorUri = PaccorUri
  { paccorUriValue :: Text
  , paccorUriHashAlgorithm :: Maybe Text  -- OID like "2.16.840.1.101.3.4.2.1"
  , paccorUriHashValue :: Maybe Text      -- Base64 encoded hash
  } deriving (Show, Eq, Generic)

-- | Attribute Certificate Identifier (hash-based)
data PaccorAttributeCertId = PaccorAttributeCertId
  { attrCertHashAlgorithm :: Text        -- OID like "1.3.6.1.4.1.22554.1.2.1"
  , attrCertHashOverSignature :: Text    -- Hex-encoded hash over signature value
  } deriving (Show, Eq, Generic)

instance FromJSON PaccorAttributeCertId where
  parseJSON = withObject "PaccorAttributeCertId" $ \v -> do
    alg <- v .: "HASHALGORITHM"
    mHashOverSig <- v .:? "HASHOVERSIGNATUREVALUE"
    hashValue <- case mHashOverSig of
      Just hv -> return hv
      Nothing -> v .: "HASH"
    return (PaccorAttributeCertId alg hashValue)

-- | General Name entry in issuer
data PaccorGeneralName = PaccorGeneralName
  { gnName :: Text   -- OID like "2.5.4.6" (Country), "2.5.4.10" (Organization)
  , gnValue :: Text  -- The actual value
  } deriving (Show, Eq, Generic)

instance FromJSON PaccorGeneralName where
  parseJSON = withObject "PaccorGeneralName" $ \v -> PaccorGeneralName
    <$> v .: "GENERALNAME"
    <*> v .: "GENERALVALUE"

-- | Generic Certificate Identifier (issuer + serial based)
data PaccorGenericCertId = PaccorGenericCertId
  { genCertIssuer :: [PaccorGeneralName]  -- Distinguished name components
  , genCertSerial :: Text                  -- Certificate serial number
  } deriving (Show, Eq, Generic)

instance FromJSON PaccorGenericCertId where
  parseJSON = withObject "PaccorGenericCertId" $ \v -> do
    issuerValue <- v .: "ISSUER"
    issuer <- case issuerValue of
      String dn -> return (parseIssuerDnString dn)
      _ -> parseJSON issuerValue
    serial <- v .: "SERIAL"
    return (PaccorGenericCertId issuer serial)

-- | Platform Certificate reference for component
-- References another Platform Certificate that attests this component
data PaccorPlatformCert = PaccorPlatformCert
  { pcAttributeCertId :: Maybe PaccorAttributeCertId   -- Hash-based identifier
  , pcGenericCertId :: Maybe PaccorGenericCertId       -- Issuer+Serial identifier
  } deriving (Show, Eq, Generic)

instance FromJSON PaccorPlatformCert where
  parseJSON = withObject "PaccorPlatformCert" $ \v -> PaccorPlatformCert
    <$> v .:? "ATTRIBUTECERTIDENTIFIER"
    <*> v .:? "GENERICCERTIDENTIFIER"

-- JSON parsing instances

instance FromJSON PaccorConfig where
  parseJSON = withObject "PaccorConfig" $ \v -> PaccorConfig
    <$> v .: "PLATFORM"
    <*> v .:? "COMPONENTS"
    <*> v .:? "COMPONENTSURI"
    <*> v .:? "PROPERTIES"
    <*> v .:? "PROPERTIESURI"

instance FromJSON PaccorPlatform where
  parseJSON = withObject "PaccorPlatform" $ \v -> PaccorPlatform
    <$> v .: "PLATFORMMANUFACTURERSTR"
    <*> v .: "PLATFORMMODEL"
    <*> v .:? "PLATFORMVERSION"
    <*> v .:? "PLATFORMSERIAL"
    <*> parseManufacturerId v
    where
      -- Handle both string format and array format for PLATFORMMANUFACTURERID
      parseManufacturerId obj = do
        mValue <- obj .:? "PLATFORMMANUFACTURERID"
        case mValue of
          Nothing -> return Nothing
          Just val -> case val of
            String s -> return (Just s)
            Array arr -> case toList arr of
              [] -> return Nothing
              (x:_) -> case fromJSON x of
                Success (pen :: PaccorPEN) -> return (Just (penValue pen))
                Error _ -> return Nothing
            _ -> return Nothing
      toList = foldr (:) []

instance FromJSON PaccorComponentClass where
  parseJSON = withObject "PaccorComponentClass" $ \v -> PaccorComponentClass
    <$> v .: "COMPONENTCLASSREGISTRY"
    <*> v .: "COMPONENTCLASSVALUE"

instance FromJSON PaccorAddress where
  parseJSON = withObject "PaccorAddress" $ \v -> do
    -- Check for OID-based format first
    mAddrType <- v .:? "ADDRESSTYPE"
    mAddrValue <- v .:? "ADDRESSVALUE"
    case (mAddrType, mAddrValue) of
      (Just addrType, Just addrValue) ->
        -- OID-based format
        return $ oidAddressToSimple (PaccorOIDAddress addrType addrValue)
      _ -> do
        -- Simple/direct format - parse all address types
        mEthernet <- v .:? "ETHERNETMAC"
        mWlan <- v .:? "WLANMAC"
        mBluetooth <- v .:? "BLUETOOTHMAC"
        mPci <- v .:? "PCIADDRESS"
        mUsb <- v .:? "USBADDRESS"
        mSata <- v .:? "SATAADDRESS"
        mWwn <- v .:? "WWNADDRESS"
        mNvme <- v .:? "NVMEADDRESS"
        mLogical <- v .:? "LOGICALADDRESS"
        return $ PaccorAddress mEthernet mWlan mBluetooth mPci mUsb mSata mWwn mNvme mLogical

instance FromJSON PaccorComponent where
  parseJSON = withObject "PaccorComponent" $ \v -> PaccorComponent
    <$> v .: "COMPONENTCLASS"
    <*> v .:? "MANUFACTURER"
    <*> v .:? "MODEL"
    <*> v .:? "SERIAL"
    <*> v .:? "REVISION"
    <*> v .:? "MANUFACTURERID"
    <*> v .:? "FIELDREPLACEABLE"
    <*> v .:? "ADDRESSES"
    <*> v .:? "STATUS"
    <*> v .:? "PLATFORMCERT"
    <*> v .:? "PLATFORMCERTURI"

instance FromJSON PaccorProperty where
  parseJSON = withObject "PaccorProperty" $ \v -> PaccorProperty
    <$> (v .: "PROPERTYNAME" <|> v .: "NAME")
    <*> (v .: "PROPERTYVALUE" <|> v .: "VALUE")
    <*> v .:? "PROPERTYSTATUS"

instance FromJSON PaccorUri where
  parseJSON = withObject "PaccorUri" $ \v -> PaccorUri
    <$> v .: "UNIFORMRESOURCEIDENTIFIER"
    <*> v .:? "HASHALGORITHM"
    <*> v .:? "HASHVALUE"

-- | Parse DN string form used by paccor example JSON
-- Example: "C=US, ST=CA, L=Sample City, O=Sample Corp, OU=CA, CN=www.example.com"
parseIssuerDnString :: Text -> [PaccorGeneralName]
parseIssuerDnString dn =
  mapMaybe toGeneralName (splitDn dn)
  where
    splitDn :: Text -> [Text]
    splitDn = map T.strip . T.splitOn ","

    toGeneralName :: Text -> Maybe PaccorGeneralName
    toGeneralName part =
      case T.breakOn "=" part of
        (k, vWithEq)
          | T.null vWithEq -> Nothing
          | otherwise ->
              let v = T.drop 1 vWithEq
              in fmap (\oid -> PaccorGeneralName oid (T.strip v)) (keyToOid (T.toUpper (T.strip k)))

    keyToOid :: Text -> Maybe Text
    keyToOid "C"  = Just "2.5.4.6"
    keyToOid "ST" = Just "2.5.4.8"
    keyToOid "L"  = Just "2.5.4.7"
    keyToOid "O"  = Just "2.5.4.10"
    keyToOid "OU" = Just "2.5.4.11"
    keyToOid "CN" = Just "2.5.4.3"
    keyToOid _    = Nothing

-- | Input format detection
data InputFormat = FormatYAML | FormatJSON
  deriving (Show, Eq)

-- | Detect input format based on file extension and content
detectInputFormat :: FilePath -> B.ByteString -> InputFormat
detectInputFormat path content
  | ".json" `isSuffixOf` path = FormatJSON
  | ".yaml" `isSuffixOf` path = FormatYAML
  | ".yml" `isSuffixOf` path = FormatYAML
  | startsWithBrace content = FormatJSON
  | otherwise = FormatYAML
  where
    isSuffixOf suffix str = suffix == drop (length str - length suffix) str
    startsWithBrace bs =
      case B.uncons (B.dropWhile isSpace bs) of
        Just (c, _) -> c == 0x7B  -- '{'
        Nothing -> False
    isSpace c = c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D

-- | Load paccor JSON configuration file
loadPaccorConfig :: FilePath -> IO (Either String PaccorConfig)
loadPaccorConfig file = do
  content <- BL.readFile file
  return $ eitherDecode content

-- | Convert paccor configuration to YAML configuration
paccorToYamlConfig :: PaccorConfig -> PlatformCertConfig
paccorToYamlConfig paccor = PlatformCertConfig
  { pccManufacturer = T.unpack (platformManufacturerStr platform)
  , pccModel = T.unpack (platformModel platform)
  , pccVersion = maybe "1.0" T.unpack (platformVersion platform)
  , pccSerial = maybe "0001" T.unpack (platformSerial platform)
  , pccManufacturerId = fmap T.unpack (platformManufacturerId platform)  -- Platform Manufacturer OID
  , pccValidityDays = Nothing  -- Not present in paccor format
  , pccKeySize = Nothing       -- Not present in paccor format
  , pccComponents = maybe [] (map convertComponent) (paccorComponents paccor)
  , pccProperties = convertProperties (paccorProperties paccor)  -- Platform properties
  -- URI References
  , pccPlatformConfigUri = Nothing  -- Separate from ComponentsUri
  , pccComponentsUri = convertPaccorUriToConfig (paccorComponentsUri paccor)  -- External components list
  , pccPropertiesUri = convertPaccorUriToConfig (paccorPropertiesUri paccor)  -- External properties list
  -- Extended fields - set defaults
  , pccPlatformClass = Nothing
  , pccSpecificationVersion = Just "1.1"
  , pccMajorVersion = Nothing
  , pccMinorVersion = Nothing
  , pccPatchVersion = Nothing
  , pccPlatformQualifier = Nothing
  -- TCG Credential fields
  , pccCredentialSpecMajor = Nothing
  , pccCredentialSpecMinor = Nothing
  , pccCredentialSpecRevision = Nothing
  -- Platform Specification fields
  , pccPlatformSpecMajor = Nothing
  , pccPlatformSpecMinor = Nothing
  , pccPlatformSpecRevision = Nothing
  -- Security Assertions
  , pccSecurityAssertions = Nothing
  }
  where
    platform = paccorPlatform paccor

    convertComponent :: PaccorComponent -> ComponentConfig
    convertComponent comp = ComponentConfig
      { ccComponentClass = Just ComponentClassConfig
          { cccRegistry = T.unpack (componentClassRegistry (componentClass comp))
          , cccValue = T.unpack (componentClassValue (componentClass comp))
          }
      , ccClass = T.unpack (componentClassValue (componentClass comp))  -- Backwards compatibility
      , ccManufacturer = maybe "Unknown" T.unpack (componentManufacturer comp)
      , ccModel = maybe "Unknown" T.unpack (componentModel comp)
      , ccSerial = fmap T.unpack (componentSerial comp)
      , ccRevision = fmap T.unpack (componentRevision comp)
      , ccManufacturerId = fmap T.unpack (componentManufacturerId comp)  -- Component Manufacturer OID
      , ccFieldReplaceable = convertFieldReplaceable (componentFieldReplaceable comp)
      , ccAddresses = convertAddresses (componentAddresses comp)
      , ccPlatformCert = convertPlatformCert (componentPlatformCert comp)
      , ccPlatformCertUri = convertPaccorUriToConfig (componentPlatformCertUri comp)
      , ccStatus = fmap T.unpack (componentStatus comp)  -- Delta status
      }

    convertFieldReplaceable :: Maybe Text -> Maybe Bool
    convertFieldReplaceable Nothing = Nothing
    convertFieldReplaceable (Just txt) = case T.toLower txt of
      "true" -> Just True
      "false" -> Just False
      "1" -> Just True
      "0" -> Just False
      _ -> Nothing

    convertProperties :: Maybe [PaccorProperty] -> Maybe [PropertyConfig]
    convertProperties Nothing = Nothing
    convertProperties (Just []) = Nothing
    convertProperties (Just props) = Just (map convertProperty props)

    convertProperty :: PaccorProperty -> PropertyConfig
    convertProperty prop = PropertyConfig
      { propName = T.unpack (propertyName prop)
      , propValue = T.unpack (propertyValue prop)
      , propStatus = fmap T.unpack (propertyStatus prop)
      }

    convertPlatformCert :: Maybe PaccorPlatformCert -> Maybe ComponentPlatformCertConfig
    convertPlatformCert Nothing = Nothing
    convertPlatformCert (Just pc) = Just ComponentPlatformCertConfig
      { cpcAttributeCertId = convertAttrCertId (pcAttributeCertId pc)
      , cpcGenericCertId = convertGenericCertId (pcGenericCertId pc)
      }

    convertAttrCertId :: Maybe PaccorAttributeCertId -> Maybe AttributeCertIdConfig
    convertAttrCertId Nothing = Nothing
    convertAttrCertId (Just acid) = Just AttributeCertIdConfig
      { acidHashAlgorithm = T.unpack (attrCertHashAlgorithm acid)
      , acidHashValue = T.unpack (attrCertHashOverSignature acid)
      }

    convertGenericCertId :: Maybe PaccorGenericCertId -> Maybe GenericCertIdConfig
    convertGenericCertId Nothing = Nothing
    convertGenericCertId (Just gcid) = Just GenericCertIdConfig
      { gcidIssuer = map convertIssuerName (genCertIssuer gcid)
      , gcidSerial = T.unpack (genCertSerial gcid)
      }

    convertIssuerName :: PaccorGeneralName -> IssuerNameConfig
    convertIssuerName gn = IssuerNameConfig
      { inOid = T.unpack (gnName gn)
      , inValue = T.unpack (gnValue gn)
      }

    convertAddresses :: Maybe [PaccorAddress] -> Maybe [AddressConfig]
    convertAddresses Nothing = Nothing
    convertAddresses (Just []) = Nothing
    convertAddresses (Just addrs) =
      let converted = map convertAddress addrs
      in if null (catMaybes $ map hasAnyAddress converted)
         then Nothing
         else Just converted

    convertAddress :: PaccorAddress -> AddressConfig
    convertAddress addr = AddressConfig
      { addrEthernetMac = fmap T.unpack (paccorEthernetMac addr)
      , addrWlanMac = fmap T.unpack (paccorWlanMac addr)
      , addrBluetoothMac = fmap T.unpack (paccorBluetoothMac addr)
      , addrPciAddress = fmap T.unpack (paccorPciAddress addr)
      , addrUsbAddress = fmap T.unpack (paccorUsbAddress addr)
      , addrSataAddress = fmap T.unpack (paccorSataAddress addr)
      , addrWwnAddress = fmap T.unpack (paccorWwnAddress addr)
      , addrNvmeAddress = fmap T.unpack (paccorNvmeAddress addr)
      , addrLogicalAddress = fmap T.unpack (paccorLogicalAddress addr)
      }

    hasAnyAddress :: AddressConfig -> Maybe ()
    hasAnyAddress addr
      | isJust (addrEthernetMac addr) = Just ()
      | isJust (addrWlanMac addr) = Just ()
      | isJust (addrBluetoothMac addr) = Just ()
      | isJust (addrPciAddress addr) = Just ()
      | isJust (addrUsbAddress addr) = Just ()
      | isJust (addrSataAddress addr) = Just ()
      | isJust (addrWwnAddress addr) = Just ()
      | isJust (addrNvmeAddress addr) = Just ()
      | isJust (addrLogicalAddress addr) = Just ()
      | otherwise = Nothing

-- | Save paccor config as YAML file
savePaccorAsYaml :: PaccorConfig -> FilePath -> IO ()
savePaccorAsYaml paccor outputFile = do
  let yamlConfig = paccorToYamlConfig paccor
  Yaml.encodeFile outputFile yamlConfig
  putStrLn $ "YAML configuration written to: " ++ outputFile

-- | Load configuration from either YAML or paccor JSON format
loadAnyConfig :: FilePath -> IO (Either String PlatformCertConfig)
loadAnyConfig file = do
  content <- B.readFile file
  let format = detectInputFormat file content
  case format of
    FormatYAML -> loadConfig file
    FormatJSON -> do
      result <- loadPaccorConfig file
      return $ case result of
        Left err -> Left $ "Failed to parse paccor JSON: " ++ err
        Right paccor -> Right (paccorToYamlConfig paccor)

-- ============================================================================
-- PolicyReference.json support
-- ============================================================================

-- | Paccor PolicyReference.json top-level structure
data PaccorPolicyReference = PaccorPolicyReference
  { pprPlatformSpec       :: Maybe PaccorPlatformSpec
  , pprCredentialSpec     :: Maybe PaccorSpecVersion
  , pprSecurityAssertions :: Maybe PaccorTBBSecurityAssertions
  , pprPlatformConfigUri  :: Maybe PaccorUri
  } deriving (Show, Eq, Generic)

-- | TCG Platform Specification (version + platform class)
data PaccorPlatformSpec = PaccorPlatformSpec
  { ppsVersion       :: PaccorSpecVersion
  , ppsPlatformClass :: Text  -- Base64 encoded
  } deriving (Show, Eq, Generic)

-- | Spec version with major.minor.revision
data PaccorSpecVersion = PaccorSpecVersion
  { psvMajor    :: Int
  , psvMinor    :: Int
  , psvRevision :: Int
  } deriving (Show, Eq, Generic)

-- | TBB Security Assertions
data PaccorTBBSecurityAssertions = PaccorTBBSecurityAssertions
  { ptbbVersion          :: Maybe Int
  , ptbbCCInfo           :: Maybe PaccorCCInfo
  , ptbbFipsLevel        :: Maybe PaccorFipsLevel
  , ptbbRtmType          :: Maybe Text
  , ptbbIso9000Certified :: Maybe Bool
  , ptbbIso9000Uri       :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | Common Criteria measures
data PaccorCCInfo = PaccorCCInfo
  { pccInfoVersion            :: Text        -- "3.1"
  , pccInfoAssuranceLevel     :: Text        -- "level7"
  , pccInfoEvalStatus         :: Text        -- "evaluationCompleted"
  , pccInfoPlus               :: Maybe Bool
  , pccInfoStrengthOfFunction :: Maybe Text
  , pccInfoProfileOid         :: Maybe Text
  , pccInfoProfileUri         :: Maybe PaccorUri
  , pccInfoTargetOid          :: Maybe Text
  , pccInfoTargetUri          :: Maybe PaccorUri
  } deriving (Show, Eq, Generic)

-- | FIPS Level
data PaccorFipsLevel = PaccorFipsLevel
  { pflVersion :: Text    -- "140-2"
  , pflLevel   :: Text    -- "level4"
  , pflPlus    :: Maybe Bool
  } deriving (Show, Eq, Generic)

-- JSON parsing helpers

-- | Parse a value that may be a JSON string containing a number or a JSON number
parseIntOrString :: Value -> Parser Int
parseIntOrString (Number n) = return (round n)
parseIntOrString (String s) = case readMaybe (T.unpack s) of
  Just i  -> return i
  Nothing -> fail $ "Cannot parse as Int: " ++ T.unpack s
parseIntOrString v = fail $ "Expected Int or String, got: " ++ show v

-- | Parse a value that may be a JSON bool, string bool, or 0/1
parseBoolFlexible :: Value -> Parser Bool
parseBoolFlexible (Bool b) = return b
parseBoolFlexible (Number n) = return (n /= 0)
parseBoolFlexible (String s) = case T.toLower s of
  "true"  -> return True
  "false" -> return False
  "1"     -> return True
  "0"     -> return False
  _       -> fail $ "Cannot parse as Bool: " ++ T.unpack s
parseBoolFlexible v = fail $ "Expected Bool or String, got: " ++ show v

-- FromJSON instances for PolicyReference types

instance FromJSON PaccorPolicyReference where
  parseJSON = withObject "PaccorPolicyReference" $ \v -> PaccorPolicyReference
    <$> v .:? "TCGPLATFORMSPECIFICATION"
    <*> v .:? "TCGCREDENTIALSPECIFICATION"
    <*> v .:? "TBBSECURITYASSERTIONS"
    <*> v .:? "PLATFORMCONFIGURI"

instance FromJSON PaccorPlatformSpec where
  parseJSON = withObject "PaccorPlatformSpec" $ \v -> PaccorPlatformSpec
    <$> v .: "VERSION"
    <*> v .: "PLATFORMCLASS"

instance FromJSON PaccorSpecVersion where
  parseJSON = withObject "PaccorSpecVersion" $ \v -> PaccorSpecVersion
    <$> (v .: "MAJORVERSION" >>= parseIntOrString)
    <*> (v .: "MINORVERSION" >>= parseIntOrString)
    <*> (v .: "REVISION" >>= parseIntOrString)

instance FromJSON PaccorTBBSecurityAssertions where
  parseJSON = withObject "PaccorTBBSecurityAssertions" $ \v -> PaccorTBBSecurityAssertions
    <$> (do mv <- v .:? "VERSION"
            case mv of
              Nothing  -> return Nothing
              Just val -> Just <$> parseIntOrString val)
    <*> v .:? "CCINFO"
    <*> v .:? "FIPSLEVEL"
    <*> v .:? "RTMTYPE"
    <*> (do mv <- v .:? "ISO9000CERTIFIED"
            case mv of
              Nothing  -> return Nothing
              Just val -> Just <$> parseBoolFlexible val)
    <*> v .:? "ISO9000URI"

instance FromJSON PaccorCCInfo where
  parseJSON = withObject "PaccorCCInfo" $ \v -> PaccorCCInfo
    <$> v .: "VERSION"
    <*> v .: "ASSURANCELEVEL"
    <*> v .: "EVALUATIONSTATUS"
    <*> (do mv <- v .:? "PLUS"
            case mv of
              Nothing  -> return Nothing
              Just val -> Just <$> parseBoolFlexible val)
    <*> v .:? "STRENGTHOFFUNCTION"
    <*> v .:? "PROFILEOID"
    <*> v .:? "PROFILEURI"
    <*> v .:? "TARGETOID"
    <*> v .:? "TARGETURI"

instance FromJSON PaccorFipsLevel where
  parseJSON = withObject "PaccorFipsLevel" $ \v -> PaccorFipsLevel
    <$> v .: "VERSION"
    <*> v .: "LEVEL"
    <*> (do mv <- v .:? "PLUS"
            case mv of
              Nothing  -> return Nothing
              Just val -> Just <$> parseBoolFlexible val)

-- | Load paccor PolicyReference.json file
loadPaccorPolicyReference :: FilePath -> IO (Either String PaccorPolicyReference)
loadPaccorPolicyReference file = do
  content <- BL.readFile file
  return $ eitherDecode content

-- | Merge PolicyReference data into an existing PlatformCertConfig
mergePolicyReference :: PaccorPolicyReference -> PlatformCertConfig -> PlatformCertConfig
mergePolicyReference pr config = config
  { pccPlatformSpecMajor    = fmap (psvMajor . ppsVersion) (pprPlatformSpec pr)    <|> pccPlatformSpecMajor config
  , pccPlatformSpecMinor    = fmap (psvMinor . ppsVersion) (pprPlatformSpec pr)    <|> pccPlatformSpecMinor config
  , pccPlatformSpecRevision = fmap (psvRevision . ppsVersion) (pprPlatformSpec pr) <|> pccPlatformSpecRevision config
  , pccPlatformClass        = fmap (base64ToHex . ppsPlatformClass) (pprPlatformSpec pr) <|> pccPlatformClass config
  , pccCredentialSpecMajor    = fmap psvMajor (pprCredentialSpec pr)    <|> pccCredentialSpecMajor config
  , pccCredentialSpecMinor    = fmap psvMinor (pprCredentialSpec pr)    <|> pccCredentialSpecMinor config
  , pccCredentialSpecRevision = fmap psvRevision (pprCredentialSpec pr) <|> pccCredentialSpecRevision config
  , pccSecurityAssertions = fmap convertTBBToSecurityAssertions (pprSecurityAssertions pr) <|> pccSecurityAssertions config
  , pccPlatformConfigUri  = convertPaccorUriToConfig (pprPlatformConfigUri pr) <|> pccPlatformConfigUri config
  }

-- | Decode Base64 text to hex string
base64ToHex :: Text -> String
base64ToHex b64 =
  case B64.decode (encodeUtf8 b64) of
    Left _err -> T.unpack b64  -- fallback: return as-is
    Right bs  -> concatMap toHexPair (B.unpack bs)
  where
    toHexPair w =
      let (hi, lo) = w `divMod` 16
      in [hexChar hi, hexChar lo]
    hexChar n
      | n < 10    = toEnum (fromEnum '0' + fromIntegral n)
      | otherwise = toEnum (fromEnum 'a' + fromIntegral n - 10)

-- | Convert PaccorTBBSecurityAssertions to SecurityAssertionsConfig
convertTBBToSecurityAssertions :: PaccorTBBSecurityAssertions -> SecurityAssertionsConfig
convertTBBToSecurityAssertions tbb = SecurityAssertionsConfig
  { sacVersion             = ptbbVersion tbb
  , sacCCVersion           = fmap (T.unpack . pccInfoVersion) (ptbbCCInfo tbb)
  , sacEvalAssuranceLevel  = ptbbCCInfo tbb >>= parseLevelInt . pccInfoAssuranceLevel
  , sacEvalStatus          = fmap (T.unpack . pccInfoEvalStatus) (ptbbCCInfo tbb)
  , sacPlus                = ptbbCCInfo tbb >>= pccInfoPlus
  , sacStrengthOfFunction  = ptbbCCInfo tbb >>= pccInfoStrengthOfFunction >>= Just . T.unpack
  , sacProtectionProfileOID = ptbbCCInfo tbb >>= fmap T.unpack . pccInfoProfileOid
  , sacProtectionProfileURI = ptbbCCInfo tbb >>= pccInfoProfileUri >>= \u -> Just (T.unpack (paccorUriValue u))
  , sacSecurityTargetOID    = ptbbCCInfo tbb >>= fmap T.unpack . pccInfoTargetOid
  , sacSecurityTargetURI    = ptbbCCInfo tbb >>= pccInfoTargetUri >>= \u -> Just (T.unpack (paccorUriValue u))
  , sacFIPSVersion         = fmap (T.unpack . pflVersion) (ptbbFipsLevel tbb)
  , sacFIPSSecurityLevel   = ptbbFipsLevel tbb >>= parseLevelInt . pflLevel
  , sacFIPSPlus            = ptbbFipsLevel tbb >>= pflPlus
  , sacRTMType             = fmap (T.unpack . T.toLower) (ptbbRtmType tbb)
  , sacISO9000Certified    = ptbbIso9000Certified tbb
  , sacISO9000URI          = fmap T.unpack (ptbbIso9000Uri tbb)
  }

-- | Parse "level7" -> Just 7, "level4" -> Just 4, etc.
parseLevelInt :: Text -> Maybe Int
parseLevelInt t = readMaybe (T.unpack (T.dropWhile (not . isDigitChar) t))
  where
    isDigitChar c = c >= '0' && c <= '9'

-- | Convert Maybe PaccorUri to Maybe URIReferenceConfig (module-level reusable)
convertPaccorUriToConfig :: Maybe PaccorUri -> Maybe URIReferenceConfig
convertPaccorUriToConfig Nothing = Nothing
convertPaccorUriToConfig (Just uri) = Just URIReferenceConfig
  { uriUri = T.unpack (paccorUriValue uri)
  , uriHashAlgorithm = fmap (oidToHashNameTop . T.unpack) (paccorUriHashAlgorithm uri)
  , uriHashValue = fmap T.unpack (paccorUriHashValue uri)
  }

-- | Convert OID to hash algorithm name (module-level)
oidToHashNameTop :: String -> String
oidToHashNameTop "2.16.840.1.101.3.4.2.1" = "sha256"
oidToHashNameTop "2.16.840.1.101.3.4.2.2" = "sha384"
oidToHashNameTop "2.16.840.1.101.3.4.2.3" = "sha512"
oidToHashNameTop oid = oid

-- ============================================================================
-- Extensions.json support
-- ============================================================================

-- | Paccor Extensions.json top-level structure
data PaccorExtensions = PaccorExtensions
  { pextCertPolicies       :: Maybe [PaccorCertPolicy]
  , pextAuthorityInfoAccess :: Maybe [PaccorAIAEntry]
  , pextCrlDistribution    :: Maybe PaccorCRLDistPoint
  } deriving (Show, Eq, Generic)

-- | Certificate Policy entry
data PaccorCertPolicy = PaccorCertPolicy
  { pcpOid        :: Text
  , pcpQualifiers :: [PaccorPolicyQualifier]
  } deriving (Show, Eq, Generic)

-- | Policy Qualifier (CPS or USERNOTICE)
data PaccorPolicyQualifier = PaccorPolicyQualifier
  { ppqId    :: Text    -- "CPS" or "USERNOTICE"
  , ppqValue :: Text
  } deriving (Show, Eq, Generic)

-- | Authority Info Access entry
data PaccorAIAEntry = PaccorAIAEntry
  { paiaMethod   :: Text     -- "OCSP" or "CAISSUERS"
  , paiaLocation :: Text
  } deriving (Show, Eq, Generic)

-- | CRL Distribution Point
data PaccorCRLDistPoint = PaccorCRLDistPoint
  { pcrlDistName :: Maybe PaccorDistName
  , pcrlReason   :: Maybe Int
  , pcrlIssuer   :: Maybe Text
  } deriving (Show, Eq, Generic)

-- | Distribution Point Name
data PaccorDistName = PaccorDistName
  { pdnType :: Int
  , pdnName :: Text
  } deriving (Show, Eq, Generic)

-- FromJSON instances for Extensions types

instance FromJSON PaccorExtensions where
  parseJSON = withObject "PaccorExtensions" $ \v -> PaccorExtensions
    <$> v .:? "CERTIFICATEPOLICIES"
    <*> v .:? "AUTHORITYINFOACCESS"
    <*> v .:? "CRLDISTRIBUTION"

instance FromJSON PaccorCertPolicy where
  parseJSON = withObject "PaccorCertPolicy" $ \v -> PaccorCertPolicy
    <$> v .: "POLICYIDENTIFIER"
    <*> (v .:? "POLICYQUALIFIERS" >>= maybe (return []) return)

instance FromJSON PaccorPolicyQualifier where
  parseJSON = withObject "PaccorPolicyQualifier" $ \v -> PaccorPolicyQualifier
    <$> v .: "POLICYQUALIFIERID"
    <*> v .: "QUALIFIER"

instance FromJSON PaccorAIAEntry where
  parseJSON = withObject "PaccorAIAEntry" $ \v -> PaccorAIAEntry
    <$> v .: "ACCESSMETHOD"
    <*> v .: "ACCESSLOCATION"

instance FromJSON PaccorCRLDistPoint where
  parseJSON = withObject "PaccorCRLDistPoint" $ \v -> PaccorCRLDistPoint
    <$> v .:? "DISTRIBUTIONNAME"
    <*> (do mv <- v .:? "REASON"
            case mv of
              Nothing  -> return Nothing
              Just val -> Just <$> parseIntOrString val)
    <*> v .:? "ISSUER"

instance FromJSON PaccorDistName where
  parseJSON = withObject "PaccorDistName" $ \v -> PaccorDistName
    <$> (v .: "TYPE" >>= parseIntOrString)
    <*> v .: "NAME"

-- | Load paccor Extensions.json file
loadPaccorExtensions :: FilePath -> IO (Either String PaccorExtensions)
loadPaccorExtensions file = do
  content <- BL.readFile file
  return $ eitherDecode content

-- | Convert PaccorExtensions to X.509 Extensions for certificate generation.
-- Encodes CertificatePolicies, AuthorityInfoAccess, and CRLDistributionPoints
-- as DER-encoded ExtensionRaw values per RFC 5280.
paccorExtensionsToX509 :: PaccorExtensions -> Extensions
paccorExtensionsToX509 pext =
  let exts = catMaybes
        [ encodeCertPolicies <$> pextCertPolicies pext
        , encodeAIA <$> pextAuthorityInfoAccess pext
        , encodeCRLDistPoints <$> pextCrlDistribution pext
        ]
  in if null exts
     then Extensions Nothing
     else Extensions (Just exts)

-- | Encode CertificatePolicies extension (OID 2.5.29.32, non-critical)
-- ASN.1: SEQUENCE OF PolicyInformation
--   PolicyInformation ::= SEQUENCE { policyIdentifier OID, policyQualifiers SEQUENCE OF PolicyQualifierInfo OPTIONAL }
--   PolicyQualifierInfo ::= SEQUENCE { policyQualifierId OID, qualifier ANY }
encodeCertPolicies :: [PaccorCertPolicy] -> ExtensionRaw
encodeCertPolicies policies =
  let asn1 = [Start Sequence] ++ concatMap encodePolicyInfo policies ++ [End Sequence]
      raw = encodeASN1' DER asn1
  in ExtensionRaw [2, 5, 29, 32] False raw

encodePolicyInfo :: PaccorCertPolicy -> [ASN1]
encodePolicyInfo policy =
  let oid = parseOidText (pcpOid policy)
      qualifiers = pcpQualifiers policy
  in [Start Sequence, OID oid]
     ++ (if null qualifiers then []
         else [Start Sequence] ++ concatMap encodePolicyQualifier qualifiers ++ [End Sequence])
     ++ [End Sequence]

encodePolicyQualifier :: PaccorPolicyQualifier -> [ASN1]
encodePolicyQualifier pq =
  let qualOid = case T.toUpper (ppqId pq) of
        "CPS"        -> [1, 3, 6, 1, 5, 5, 7, 2, 1]  -- id-qt-cps
        "USERNOTICE" -> [1, 3, 6, 1, 5, 5, 7, 2, 2]  -- id-qt-unotice
        _            -> [1, 3, 6, 1, 5, 5, 7, 2, 1]  -- default to CPS
      qualValue = case T.toUpper (ppqId pq) of
        "CPS" -> [ASN1String (asn1CharacterString IA5 (T.unpack (ppqValue pq)))]
        "USERNOTICE" ->
          -- UserNotice ::= SEQUENCE { explicitText DisplayText OPTIONAL }
          -- DisplayText ::= CHOICE { utf8String UTF8String }
          [ Start Sequence
          , ASN1String (asn1CharacterString UTF8 (T.unpack (ppqValue pq)))
          , End Sequence
          ]
        _ -> [ASN1String (asn1CharacterString IA5 (T.unpack (ppqValue pq)))]
  in [Start Sequence, OID qualOid] ++ qualValue ++ [End Sequence]

-- | Encode AuthorityInfoAccess extension (OID 1.3.6.1.5.5.7.1.1, non-critical)
-- ASN.1: SEQUENCE OF AccessDescription
--   AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
--   GeneralName uniformResourceIdentifier [6] IA5String
encodeAIA :: [PaccorAIAEntry] -> ExtensionRaw
encodeAIA entries =
  let asn1 = [Start Sequence] ++ concatMap encodeAIAEntry entries ++ [End Sequence]
      raw = encodeASN1' DER asn1
  in ExtensionRaw [1, 3, 6, 1, 5, 5, 7, 1, 1] False raw

encodeAIAEntry :: PaccorAIAEntry -> [ASN1]
encodeAIAEntry entry =
  let methodOid = case T.toUpper (paiaMethod entry) of
        "OCSP"      -> [1, 3, 6, 1, 5, 5, 7, 48, 1]  -- id-ad-ocsp
        "CAISSUERS" -> [1, 3, 6, 1, 5, 5, 7, 48, 2]  -- id-ad-caIssuers
        _           -> [1, 3, 6, 1, 5, 5, 7, 48, 1]  -- default to OCSP
      -- GeneralName uniformResourceIdentifier is context tag [6] implicit
      uriBytes = encodeUtf8 (paiaLocation entry)
  in [ Start Sequence
     , OID methodOid
     , Other Context 6 uriBytes  -- uniformResourceIdentifier [6]
     , End Sequence
     ]

-- | Encode CRLDistributionPoints extension (OID 2.5.29.31, non-critical)
-- ASN.1: SEQUENCE OF DistributionPoint
--   DistributionPoint ::= SEQUENCE {
--     distributionPoint [0] DistributionPointName OPTIONAL,
--     reasons           [1] ReasonFlags OPTIONAL,
--     cRLIssuer         [2] GeneralNames OPTIONAL }
--   DistributionPointName ::= CHOICE {
--     fullName [0] GeneralNames }
--   ReasonFlags ::= BIT STRING
encodeCRLDistPoints :: PaccorCRLDistPoint -> ExtensionRaw
encodeCRLDistPoints dp =
  let dpContent = catMaybes
        [ encodeDistPointName <$> pcrlDistName dp
        , encodeReasonFlags <$> pcrlReason dp
        , encodeIssuerName <$> pcrlIssuer dp
        ]
      asn1 = [Start Sequence, Start Sequence]
             ++ concat dpContent
             ++ [End Sequence, End Sequence]
      raw = encodeASN1' DER asn1
  in ExtensionRaw [2, 5, 29, 31] False raw

-- | Encode DistributionPointName as [0] EXPLICIT { fullName [0] IMPLICIT GeneralNames }
-- Per RFC 5280: distributionPoint [0] is EXPLICIT (wrapping CHOICE),
-- fullName [0] is IMPLICIT (replacing SEQUENCE OF GeneralName)
encodeDistPointName :: PaccorDistName -> [ASN1]
encodeDistPointName dn =
  let uriBytes = encodeUtf8 (pdnName dn)
  in case pdnType dn of
       0 -> -- fullName: distributionPoint [0] { fullName [0] { GeneralName } }
         [ Start (Container Context 0)    -- distributionPoint [0] EXPLICIT
         , Start (Container Context 0)    -- fullName [0] IMPLICIT SEQUENCE OF GeneralName
         , Other Context 6 uriBytes       -- uniformResourceIdentifier [6]
         , End (Container Context 0)      -- end fullName
         , End (Container Context 0)      -- end distributionPoint
         ]
       _ -> -- relativeName or unknown: encode as fullName
         [ Start (Container Context 0)
         , Start (Container Context 0)
         , Other Context 6 uriBytes
         , End (Container Context 0)
         , End (Container Context 0)
         ]

-- | Encode ReasonFlags as BIT STRING wrapped in [1] context tag.
-- DER requires minimal encoding: strip trailing zero bytes and compute unused bits.
encodeReasonFlags :: Int -> [ASN1]
encodeReasonFlags reason =
  let reasonByte = fromIntegral reason :: Word8
      -- Count trailing zero bits for minimal DER BIT STRING
      unusedBits = if reasonByte == 0 then 8 else trailingZeroBits reasonByte 0
  in [Other Context 1 (B.pack [fromIntegral unusedBits, reasonByte])]
  where
    trailingZeroBits :: Word8 -> Int -> Int
    trailingZeroBits b n
      | b .&. 1 == 0 = trailingZeroBits (b `shiftR` 1) (n + 1)
      | otherwise     = n

-- | Encode CRL issuer as GeneralNames wrapped in [2] context tag.
-- Per IWG convention, crlIssuer uses directoryName (not URI).
-- Input: DN string like "C=US, ST=TX, L=City, O=Org, CN=www.example.com"
encodeIssuerName :: Text -> [ASN1]
encodeIssuerName issuer =
  let dnRdns = textToDnRdns issuer
  in [ Start (Container Context 2)    -- cRLIssuer [2] GeneralNames
     , Start (Container Context 4)    -- directoryName [4]
     , Start Sequence                 -- Name = SEQUENCE OF RDN
     ] ++ dnRdns ++
     [ End Sequence
     , End (Container Context 4)
     , End (Container Context 2)
     ]

-- | Parse a DN string like "C=US, ST=TX, L=City, O=Org, CN=www.example.com"
-- into ASN1 RDN encoding (SET { SEQUENCE { OID, value } } for each component)
textToDnRdns :: Text -> [ASN1]
textToDnRdns t =
  let parts = map T.strip (T.splitOn "," t)
  in concatMap parseDnComponent parts
  where
    parseDnComponent :: Text -> [ASN1]
    parseDnComponent comp =
      case T.breakOn "=" comp of
        (key, rest) | not (T.null rest) ->
          let val = T.drop 1 rest  -- drop the '='
              strippedKey = T.strip key
              mOid = dnAttrOid strippedKey
              -- RFC 5280: countryName MUST use PrintableString
              strType = if strippedKey == "C" then Printable else UTF8
          in case mOid of
               Just oid ->
                 [ Start Set, Start Sequence
                 , OID oid
                 , ASN1String (ASN1CharacterString strType (encodeUtf8 val))
                 , End Sequence, End Set
                 ]
               Nothing -> []  -- skip unknown attributes
        _ -> []  -- skip malformed components

    dnAttrOid :: Text -> Maybe OID
    dnAttrOid "CN"  = Just [2,5,4,3]
    dnAttrOid "C"   = Just [2,5,4,6]
    dnAttrOid "L"   = Just [2,5,4,7]
    dnAttrOid "ST"  = Just [2,5,4,8]
    dnAttrOid "O"   = Just [2,5,4,10]
    dnAttrOid "OU"  = Just [2,5,4,11]
    dnAttrOid "SN"  = Just [2,5,4,4]
    dnAttrOid "GN"  = Just [2,5,4,42]
    dnAttrOid _     = Nothing

-- | Parse a dotted OID string like "1.2.840.113741.1.5.2.4" into OID
parseOidText :: Text -> OID
parseOidText t =
  let parts = T.splitOn "." t
  in mapMaybe (readMaybe . T.unpack) parts

-- ============================================================================
-- Subject Alternative Names (SAN) extension generation
-- ============================================================================

-- | Build SubjectAltName extension from PlatformCertConfig.
-- Per IWG Profile §3.2.8, SAN MUST contain a directoryName with
-- platformManufacturerStr, platformModel, and platformVersion attributes.
-- OID 2.5.29.17, non-critical.
buildSanExtension :: PlatformCertConfig -> ExtensionRaw
buildSanExtension config =
  let -- Required attributes
      mfgAttr  = mkRdn [2, 23, 133, 5, 1, 1] (BC.pack $ pccManufacturer config)  -- tcg-paa-platformManufacturerStr
      modelAttr = mkRdn [2, 23, 133, 5, 1, 4] (BC.pack $ pccModel config)         -- tcg-paa-platformModel
      verAttr  = mkRdn [2, 23, 133, 5, 1, 5] (BC.pack $ pccVersion config)        -- tcg-paa-platformVersion
      -- Optional attributes
      serialAttr = mkRdn [2, 23, 133, 5, 1, 6] (BC.pack $ pccSerial config)       -- tcg-paa-platformSerial
      -- ManufacturerId ::= SEQUENCE { manufacturerIdentifier PrivateEnterpriseNumber }
      -- PrivateEnterpriseNumber ::= OBJECT IDENTIFIER  (Errata 9)
      mfgIdAttr = case pccManufacturerId config of
        Just mid -> mkRdnManufacturerId [2, 23, 133, 5, 1, 2] (parseOidText (T.pack mid))
        Nothing  -> []
      -- DirectoryName encoding
      dn = [Start Sequence] ++ mfgAttr ++ modelAttr ++ verAttr ++ serialAttr ++ mfgIdAttr ++ [End Sequence]
      generalNames =
        [ Start Sequence
        , Start (Container Context 4)  -- directoryName [4]
        ] ++ dn ++
        [ End (Container Context 4)
        , End Sequence
        ]
      raw = encodeASN1' DER generalNames
  in ExtensionRaw [2, 5, 29, 17] False raw

-- | Create an RDN SET { SEQUENCE { OID, UTF8String } } for SAN directoryName
mkRdn :: OID -> B.ByteString -> [ASN1]
mkRdn oid val =
  [ Start Set
  , Start Sequence
  , OID oid
  , ASN1String (ASN1CharacterString UTF8 val)
  , End Sequence
  , End Set
  ]

-- | Create an RDN for ManufacturerId per IWG §3.1.6 + Errata 9:
-- SET { SEQUENCE { OID(2.23.133.5.1.2), SEQUENCE { OID(pen) } } }
-- ManufacturerId ::= SEQUENCE { manufacturerIdentifier PrivateEnterpriseNumber }
-- PrivateEnterpriseNumber ::= OBJECT IDENTIFIER
mkRdnManufacturerId :: OID -> OID -> [ASN1]
mkRdnManufacturerId attrOid penOid =
  [ Start Set
  , Start Sequence
  , OID attrOid
  , Start Sequence
  , OID penOid
  , End Sequence
  , End Sequence
  , End Set
  ]

-- | Build Authority Key Identifier extension from CA certificate per CHN-001.
-- Includes keyIdentifier [0], authorityCertIssuer [1], and authorityCertSerialNumber [2].
-- Returns Nothing if the CA cert has no SKI extension.
buildAkiExtension :: Certificate -> Maybe ExtensionRaw
buildAkiExtension cert =
  let mSki = extensionGet (certExtensions cert) :: Maybe ExtSubjectKeyId
      issuerDN = certIssuerDN cert
      serialNum = certSerial cert
  in case mSki of
       Just (ExtSubjectKeyId ski) ->
         let dnAsn1 = toASN1 issuerDN []
             asn1 = [ Start Sequence
                    , Other Context 0 ski                     -- keyIdentifier [0]
                    , Start (Container Context 1)             -- authorityCertIssuer [1] GeneralNames
                    , Start (Container Context 4)             -- directoryName [4]
                    ] ++ dnAsn1 ++
                    [ End (Container Context 4)
                    , End (Container Context 1)
                    , Other Context 2 (integerToBytes serialNum)  -- authorityCertSerialNumber [2]
                    , End Sequence
                    ]
             raw = encodeASN1' DER asn1
         in Just $ ExtensionRaw [2, 5, 29, 35] False raw
       Nothing -> Nothing

-- | Encode an Integer as DER INTEGER content bytes (big-endian two's complement)
integerToBytes :: Integer -> B.ByteString
integerToBytes 0 = B.singleton 0
integerToBytes n
  | n > 0     = let bs = unrollPositive n
                in if B.head bs >= 128 then B.cons 0 bs else bs
  | otherwise = B.singleton 0  -- negative serials shouldn't occur
  where
    unrollPositive :: Integer -> B.ByteString
    unrollPositive i = B.pack (go i [])
      where
        go 0 acc = acc
        go x acc = go (x `shiftR` 8) (fromIntegral (x .&. 0xff) : acc)
