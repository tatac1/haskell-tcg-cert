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

    -- * Conversion Functions
  , paccorToYamlConfig
  , loadPaccorConfig
  , savePaccorAsYaml

    -- * Format Detection
  , InputFormat(..)
  , detectInputFormat
  , loadAnyConfig
  ) where

import Control.Applicative ((<|>))
import Data.Aeson hiding (encodeFile)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Maybe (catMaybes)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Yaml as Yaml
import GHC.Generics (Generic)

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

-- | Component address (MAC addresses)
-- Supports both simple format (ETHERNETMAC, WLANMAC, BLUETOOTHMAC)
-- and OID-based format (ADDRESSTYPE, ADDRESSVALUE)
data PaccorAddress = PaccorAddress
  { paccorEthernetMac :: Maybe Text
  , paccorWlanMac :: Maybe Text
  , paccorBluetoothMac :: Maybe Text
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
  "2.23.133.17.1" -> PaccorAddress (Just (addressValue addr)) Nothing Nothing  -- Ethernet
  "2.23.133.17.2" -> PaccorAddress Nothing (Just (addressValue addr)) Nothing  -- WLAN
  "2.23.133.17.3" -> PaccorAddress Nothing Nothing (Just (addressValue addr))  -- Bluetooth
  _               -> PaccorAddress (Just (addressValue addr)) Nothing Nothing  -- Default to Ethernet

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
  parseJSON = withObject "PaccorAttributeCertId" $ \v -> PaccorAttributeCertId
    <$> v .: "HASHALGORITHM"
    <*> v .: "HASHOVERSIGNATUREVALUE"

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
  parseJSON = withObject "PaccorGenericCertId" $ \v -> PaccorGenericCertId
    <$> v .: "ISSUER"
    <*> v .: "SERIAL"

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
    -- Try simple format first
    mEthernet <- v .:? "ETHERNETMAC"
    mWlan <- v .:? "WLANMAC"
    mBluetooth <- v .:? "BLUETOOTHMAC"
    -- Check for OID-based format
    mAddrType <- v .:? "ADDRESSTYPE"
    mAddrValue <- v .:? "ADDRESSVALUE"
    case (mAddrType, mAddrValue) of
      (Just addrType, Just addrValue) ->
        -- OID-based format
        return $ oidAddressToSimple (PaccorOIDAddress addrType addrValue)
      _ ->
        -- Simple format
        return $ PaccorAddress mEthernet mWlan mBluetooth

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
  , pccComponentsUri = convertPaccorUri (paccorComponentsUri paccor)  -- External components list
  , pccPropertiesUri = convertPaccorUri (paccorPropertiesUri paccor)  -- External properties list
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
      , ccPlatformCertUri = convertPlatformCertUri (componentPlatformCertUri comp)
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

    convertPaccorUri :: Maybe PaccorUri -> Maybe URIReferenceConfig
    convertPaccorUri Nothing = Nothing
    convertPaccorUri (Just uri) = Just URIReferenceConfig
      { uriUri = T.unpack (paccorUriValue uri)
      , uriHashAlgorithm = fmap (oidToHashName . T.unpack) (paccorUriHashAlgorithm uri)
      , uriHashValue = fmap T.unpack (paccorUriHashValue uri)
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

    convertPlatformCertUri :: Maybe PaccorUri -> Maybe URIReferenceConfig
    convertPlatformCertUri Nothing = Nothing
    convertPlatformCertUri (Just uri) = Just URIReferenceConfig
      { uriUri = T.unpack (paccorUriValue uri)
      , uriHashAlgorithm = fmap (oidToHashName . T.unpack) (paccorUriHashAlgorithm uri)
      , uriHashValue = fmap T.unpack (paccorUriHashValue uri)
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
      }

    hasAnyAddress :: AddressConfig -> Maybe ()
    hasAnyAddress addr
      | addrEthernetMac addr /= Nothing = Just ()
      | addrWlanMac addr /= Nothing = Just ()
      | addrBluetoothMac addr /= Nothing = Just ()
      | otherwise = Nothing

    -- Convert OID to hash algorithm name
    oidToHashName :: String -> String
    oidToHashName "2.16.840.1.101.3.4.2.1" = "sha256"
    oidToHashName "2.16.840.1.101.3.4.2.2" = "sha384"
    oidToHashName "2.16.840.1.101.3.4.2.3" = "sha512"
    oidToHashName oid = oid  -- Return as-is if unknown

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
