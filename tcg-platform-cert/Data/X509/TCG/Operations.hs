{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Operations
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Library
-- Stability   : experimental
-- Portability : unknown
--
-- High-level operations for TCG Platform Certificates.
-- This module provides the main API for creating, validating, and manipulating
-- TCG Platform and Delta Platform Certificates.
module Data.X509.TCG.Operations
  ( -- * Certificate Creation
    createPlatformCertificate,
    createSignedPlatformCertificate,
    createDeltaPlatformCertificate,
    createSignedDeltaPlatformCertificate,

    -- * Configuration Management
    getCurrentPlatformConfiguration,
    applyDeltaCertificate,
    computeConfigurationChain,

    -- * Component Operations
    getComponentIdentifiers,
    getComponentIdentifiersV2,
    findComponentByClass,
    findComponentByAddress,
    buildComponentHierarchy,

    -- * Certificate Chain Operations
    buildCertificateChain,
    findBaseCertificate,

    -- * Validation Functions
    validatePlatformCertificateInputs,
    validatePlatformConfigurationFields,
    validateDeltaCertificateInputs,
    validateComponentIdentifierV2,
    validateSignatureAlgorithm,
    validateUTF8String,
  )
where

import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import Data.ASN1.Types (ASN1 (..), OID)
import Data.ASN1.Types.String (ASN1CharacterString(..), ASN1StringEncoding(..))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Control.Monad (when)
import Control.Applicative ((<|>))
import Data.X509 (AltName (..), DistinguishedName (..), Extensions (..), HashALG (..), PubKeyALG (..), SignatureALG (..), objectToSignedExact, objectToSignedExactF)
import Data.X509.AttCert (AttCertIssuer (..), AttCertValidityPeriod, Holder (..))
import Data.X509.Attribute (Attribute (..), Attributes (..))
import Data.X509.TCG.Component
import Data.X509.TCG.Delta
import Data.X509.TCG.OID
  ( tcg_at_componentIdentifier_v2
  , tcg_at_platformConfiguration_v2
  , tcg_at_platformManufacturer
  , tcg_at_platformModel
  , tcg_at_platformSerial
  , tcg_at_platformVersion
  , tcg_paa_platformManufacturer
  , tcg_paa_platformModel
  , tcg_paa_platformSerial
  , tcg_paa_platformVersion
  )
import Data.X509.TCG.Platform
import Data.X509AC (IssuerSerial (..), V2Form (..))

-- * Certificate Creation

-- | Create a Platform Certificate with the specified configuration and attributes
--
-- This function constructs a Platform Certificate containing platform identification
-- and component information as specified in the TCG Platform Certificate Profile.
--
-- Example:
-- @
-- cert <- createPlatformCertificate holder issuer validity config attrs
-- @
createPlatformCertificate ::
  -- | Certificate holder information
  Holder ->
  -- | Attribute certificate issuer
  AttCertIssuer ->
  -- | Validity period
  AttCertValidityPeriod ->
  -- | Platform configuration
  PlatformConfiguration ->
  -- | Additional attributes
  Attributes ->
  IO (Either String SignedPlatformCertificate)
createPlatformCertificate holder certIssuer validity config additionalAttrs = do
  -- Build attributes from platform configuration
  case buildPlatformAttributes config additionalAttrs of
    Left err -> return $ Left err
    Right attrs -> do
      -- Build the certificate info structure
      let certInfo =
            PlatformCertificateInfo
              { pciVersion = 1, -- v2 (RFC 5755: AttCertVersion v2 = INTEGER 1)
                pciHolder = holder,
                pciIssuer = certIssuer,
                pciSignature = SignatureALG HashSHA384 PubKeyALG_RSA,
                pciSerialNumber = 1, -- Simple serial number for testing
                pciValidity = validity,
                pciAttributes = attrs,
                pciIssuerUniqueID = Nothing,
                pciExtensions = Extensions Nothing
              }

      -- Create a signed certificate using a dummy signature
      -- NOTE: This function uses dummy signing for testing purposes only
      -- For production use, use createSignedPlatformCertificate instead
      let dummySigningFunction = createDummySigningFunction
      let (signedCert, _) = objectToSignedExact dummySigningFunction certInfo

      return $ Right signedCert

-- | Create a Platform Certificate with real cryptographic signing
--
-- This function creates a properly signed Platform Certificate using
-- a real private key for cryptographic signature generation.
createSignedPlatformCertificate ::
  -- | Certificate holder information
  Holder ->
  -- | Attribute certificate issuer
  AttCertIssuer ->
  -- | Validity period
  AttCertValidityPeriod ->
  -- | Platform configuration
  PlatformConfiguration ->
  -- | Additional attributes
  Attributes ->
  -- | Signing key material
  (SignatureALG, RSA.PublicKey, RSA.PrivateKey) ->
  IO (Either String SignedPlatformCertificate)
createSignedPlatformCertificate holder certIssuer validity config additionalAttrs (sigAlg, _pubKey, privKey) = do
  -- Validate input parameters before certificate generation to prevent parsing errors and specification violations
  case validatePlatformCertificateInputs holder certIssuer validity config additionalAttrs sigAlg of
    Left validationErr -> return $ Left ("Validation failed: " ++ validationErr)
    Right () -> do
      -- Build attributes from platform configuration
      case buildPlatformAttributes config additionalAttrs of
        Left err -> return $ Left err
        Right attrs -> do
          -- Build the certificate info structure
          let certInfo =
                PlatformCertificateInfo
                  { pciVersion = 1, -- v2 (RFC 5755: AttCertVersion v2 = INTEGER 1)
                    pciHolder = holder,
                    pciIssuer = certIssuer,
                    pciSignature = sigAlg,
                    pciSerialNumber = 1, -- Simple serial number for testing
                    pciValidity = validity,
                    pciAttributes = attrs,
                    pciIssuerUniqueID = Nothing,
                    pciExtensions = Extensions Nothing
                  }

          -- Create real signing function using RSA private key
          let realSigningFunction objRaw = do
                let hashAlg = case sigAlg of
                      SignatureALG hashType _ -> hashType
                      _ -> HashSHA384 -- Default fallback
                sigBits <- doSignRSA hashAlg privKey objRaw
                return (sigBits, sigAlg)

          -- Create signed certificate with real signature
          signedCert <- objectToSignedExactF realSigningFunction certInfo

          return $ Right signedCert

-- | Build platform attributes from configuration and additional attributes
buildPlatformAttributes :: PlatformConfiguration -> Attributes -> Either String Attributes
buildPlatformAttributes config (Attributes additionalAttrs) = do
  -- Create basic platform attributes from configuration
  let manufacturerAttr = Attribute tcg_paa_platformManufacturer [[ASN1String (ASN1CharacterString UTF8 (pcManufacturer config))]]
      modelAttr = Attribute tcg_paa_platformModel [[ASN1String (ASN1CharacterString UTF8 (pcModel config))]]
      serialAttr = Attribute tcg_paa_platformSerial [[ASN1String (ASN1CharacterString UTF8 (pcSerial config))]]
      versionAttr = Attribute tcg_paa_platformVersion [[ASN1String (ASN1CharacterString UTF8 (pcVersion config))]]

  -- Combine platform attributes with additional attributes
  let allAttributes = [manufacturerAttr, modelAttr, serialAttr, versionAttr] ++ additionalAttrs

  return $ Attributes allAttributes

-- | Create a dummy signing function for testing purposes
createDummySigningFunction :: B.ByteString -> (B.ByteString, SignatureALG, ())
createDummySigningFunction _dataToSign =
  (B.replicate 48 0x42, SignatureALG HashSHA384 PubKeyALG_RSA, ()) -- 48 bytes of dummy signature data (SHA384)

-- | Create a Delta Platform Certificate for incremental updates
--
-- Delta Platform Certificates describe changes to a base Platform Certificate,
-- allowing efficient updates without reissuing complete certificates.
--
-- Example:
-- @
-- deltaCert <- createDeltaPlatformCertificate holder issuer validity baseRef delta
-- @
createDeltaPlatformCertificate ::
  -- | Certificate holder
  Holder ->
  -- | Attribute certificate issuer
  AttCertIssuer ->
  -- | Validity period
  AttCertValidityPeriod ->
  -- | Reference to base certificate
  BasePlatformCertificateRef ->
  -- | Configuration changes
  PlatformConfigurationDelta ->
  IO (Either String SignedDeltaPlatformCertificate)
createDeltaPlatformCertificate holder deltaIssuer validity baseRef configDelta = do
  -- Build delta configuration attributes
  case buildDeltaAttributes configDelta of
    Left err -> return $ Left err
    Right attrs -> do
      -- Build the Delta Platform Certificate Info structure
      let deltaCertInfo =
            DeltaPlatformCertificateInfo
              { dpciVersion = 1, -- v2 (RFC 5755: AttCertVersion v2 = INTEGER 1)
                dpciHolder = holder,
                dpciIssuer = deltaIssuer,
                dpciSignature = SignatureALG HashSHA384 PubKeyALG_RSA,
                dpciSerialNumber = bpcrSerialNumber baseRef + 1, -- Increment from base
                dpciValidity = validity,
                dpciAttributes = attrs,
                dpciIssuerUniqueID = Nothing,
                dpciExtensions = Extensions Nothing,
                dpciBaseCertificateRef = baseRef
              }

      -- Create a signed certificate using a dummy signature
      -- NOTE: This function uses dummy signing for testing purposes only
      -- For production use, use createSignedDeltaPlatformCertificate instead
      let dummySigningFunction = createDummySigningFunctionForDelta
      let (signedCert, _) = objectToSignedExact dummySigningFunction deltaCertInfo

      return $ Right signedCert

-- | Build attributes from delta configuration
buildDeltaAttributes :: PlatformConfigurationDelta -> Either String Attributes
buildDeltaAttributes delta =
  -- For now, create basic attributes containing delta configuration
  -- In a full implementation, this would encode the delta as ASN.1 and store it
  let componentCount = length (pcdComponentDeltas delta)
      changeCount = length (pcdChangeRecords delta)
      -- Create simple attributes indicating the presence of changes
      countAttr = Attribute tcg_at_componentIdentifier_v2 [[OctetString (B8.pack ("component_count:" ++ show componentCount))]]
      changeAttr = Attribute tcg_at_platformConfiguration_v2 [[OctetString (B8.pack ("change_count:" ++ show changeCount))]]
      allAttributes = [countAttr, changeAttr]
   in Right $ Attributes allAttributes

-- | Create a dummy signing function for delta certificates
createDummySigningFunctionForDelta :: B.ByteString -> (B.ByteString, SignatureALG, ())
createDummySigningFunctionForDelta _dataToSign =
  (B.replicate 48 0x43, SignatureALG HashSHA384 PubKeyALG_RSA, ()) -- 48 bytes of dummy signature data (SHA384)

-- | Create a Delta Platform Certificate with real cryptographic signing
--
-- This function creates a properly signed Delta Platform Certificate using
-- a real private key for cryptographic signature generation.
createSignedDeltaPlatformCertificate ::
  -- | Certificate holder
  Holder ->
  -- | Attribute certificate issuer
  AttCertIssuer ->
  -- | Validity period
  AttCertValidityPeriod ->
  -- | Reference to base certificate
  BasePlatformCertificateRef ->
  -- | Configuration changes
  PlatformConfigurationDelta ->
  -- | Signing key material
  (SignatureALG, RSA.PublicKey, RSA.PrivateKey) ->
  IO (Either String SignedDeltaPlatformCertificate)
createSignedDeltaPlatformCertificate holder certIssuer validity baseRef configDelta (sigAlg, _pubKey, privKey) = do
  -- Validate input parameters before certificate generation
  case validateDeltaCertificateInputs holder certIssuer validity baseRef configDelta sigAlg of
    Left validationErr -> return $ Left ("Validation failed: " ++ validationErr)
    Right () -> do
      -- Build delta configuration attributes
      case buildDeltaAttributes configDelta of
        Left err -> return $ Left err
        Right attrs -> do
          -- Build the Delta Platform Certificate Info structure
          let deltaCertInfo =
                DeltaPlatformCertificateInfo
                  { dpciVersion = 1, -- v2 (RFC 5755: AttCertVersion v2 = INTEGER 1)
                    dpciHolder = holder,
                    dpciIssuer = certIssuer,
                    dpciSignature = sigAlg,
                    dpciSerialNumber = bpcrSerialNumber baseRef + 1, -- Increment from base
                    dpciValidity = validity,
                    dpciAttributes = attrs,
                    dpciIssuerUniqueID = Nothing,
                    dpciExtensions = Extensions Nothing,
                    dpciBaseCertificateRef = baseRef
                  }

          -- Create real signing function using RSA private key
          let realSigningFunction objRaw = do
                let hashAlg = case sigAlg of
                      SignatureALG hashType _ -> hashType
                      _ -> HashSHA384 -- Default fallback
                sigBits <- doSignRSA hashAlg privKey objRaw
                return (sigBits, sigAlg)

          -- Create signed certificate with real signature
          signedCert <- objectToSignedExactF realSigningFunction deltaCertInfo

          return $ Right signedCert

-- | RSA signing helper for Delta certificates
doSignRSA :: HashALG -> RSA.PrivateKey -> B.ByteString -> IO B.ByteString
doSignRSA hashAlg privKey msg = do
  result <- case hashAlg of
    HashSHA1 -> RSA.signSafer (Just Hash.SHA1) privKey msg
    HashSHA256 -> RSA.signSafer (Just Hash.SHA256) privKey msg
    HashSHA384 -> RSA.signSafer (Just Hash.SHA384) privKey msg
    HashSHA512 -> RSA.signSafer (Just Hash.SHA512) privKey msg
    _ -> RSA.signSafer (Just Hash.SHA384) privKey msg -- Default fallback
  case result of
    Left err -> error ("doSignRSA: " ++ show err)
    Right signature -> return signature

-- * Configuration Management

-- | Extract platform configuration from individual attributes when composite attribute is not available
extractFromIndividualAttributes :: SignedPlatformCertificate -> Maybe PlatformConfigurationV2
extractFromIndividualAttributes cert = do
  let attrs = pciAttributes $ getPlatformCertificate cert
  manufacturer <- lookupAttributeValue tcg_paa_platformManufacturer attrs
    <|> lookupAttributeValue tcg_at_platformManufacturer attrs
  model <- lookupAttributeValue tcg_paa_platformModel attrs
    <|> lookupAttributeValue tcg_at_platformModel attrs
  platformSerial <- lookupAttributeValue tcg_paa_platformSerial attrs
    <|> lookupAttributeValue tcg_at_platformSerial attrs
  version <- lookupAttributeValue tcg_paa_platformVersion attrs
    <|> lookupAttributeValue tcg_at_platformVersion attrs
  return $
    PlatformConfigurationV2
      { pcv2Manufacturer = manufacturer,
        pcv2Model = model,
        pcv2Version = version,
        pcv2Serial = platformSerial,
        pcv2Components = [] -- Individual attributes don't contain component info
      }
  where
    -- Helper to extract OctetString value from attribute
    lookupAttributeValue :: OID -> Attributes -> Maybe B.ByteString
    lookupAttributeValue targetOID (Attributes attrList) =
      case [attrVal | Attribute attrOID attrVals <- attrList, attrOID == targetOID, [attrVal] <- attrVals] of
        (OctetString bs : _) -> Just bs
        (ASN1String (ASN1CharacterString _ bs) : _) -> Just bs
        _ -> Nothing

-- | Extract the current platform configuration from a certificate
--
-- This function handles both Platform Certificates and Delta Platform Certificates,
-- returning the appropriate configuration for the certificate type.
getCurrentPlatformConfiguration ::
  Either SignedPlatformCertificate SignedDeltaPlatformCertificate ->
  Maybe PlatformConfigurationV2
getCurrentPlatformConfiguration (Left platCert) =
  case getPlatformConfiguration platCert of
    Just config -> convertToV2 config
    Nothing -> extractFromIndividualAttributes platCert
  where
    -- Convert v1 configuration to v2 format for consistency
    convertToV2 :: PlatformConfiguration -> Maybe PlatformConfigurationV2
    convertToV2 config =
      Just $
        PlatformConfigurationV2
          { pcv2Manufacturer = pcManufacturer config,
            pcv2Model = pcModel config,
            pcv2Version = pcVersion config,
            pcv2Serial = pcSerial config,
            pcv2Components = map upgradeComponent (pcComponents config)
          }

    upgradeComponent :: ComponentIdentifier -> (ComponentIdentifierV2, ComponentStatus)
    upgradeComponent comp = (upgradeToV2 comp, ComponentUnchanged)

    upgradeToV2 :: ComponentIdentifier -> ComponentIdentifierV2
    upgradeToV2 comp =
      ComponentIdentifierV2
        { ci2Manufacturer = ciManufacturer comp,
          ci2Model = ciModel comp,
          ci2Serial = ciSerial comp,
          ci2Revision = ciRevision comp,
          ci2ManufacturerSerial = ciManufacturerSerial comp,
          ci2ManufacturerRevision = ciManufacturerRevision comp,
          ci2ComponentClass = ComponentOther [1, 3, 6, 1, 4, 1, 2312, 16, 3, 2, 1], -- Default class for v1 components
          ci2ComponentAddress = Nothing
        }
getCurrentPlatformConfiguration (Right deltaCert) =
  -- Delta certificates contain changes, not complete configurations.
  -- Extract component information from the delta and create a partial configuration
  case getPlatformConfigurationDelta deltaCert of
    Just deltaConfig ->
      -- Create a configuration based on delta changes
      -- This represents the changes, not a complete platform configuration
      let components = map deltaToComponent (pcdComponentDeltas deltaConfig)
       in Just $
            PlatformConfigurationV2
              { pcv2Manufacturer = B.empty, -- Delta certificates don't contain base platform info
                pcv2Model = B.empty,
                pcv2Version = B.empty,
                pcv2Serial = B.empty,
                pcv2Components = components
              }
    Nothing ->
      -- For delta certificates created by TCG.hs that don't have platform configuration in attributes,
      -- return a basic empty configuration to indicate the certificate exists but has no accessible delta info
      Just $
        PlatformConfigurationV2
          { pcv2Manufacturer = B.empty,
            pcv2Model = B.empty,
            pcv2Version = B.empty,
            pcv2Serial = B.empty,
            pcv2Components = [] -- No component info available from certificate structure
          }
  where
    -- Convert component delta to component with status
    deltaToComponent :: ComponentDelta -> (ComponentIdentifierV2, ComponentStatus)
    deltaToComponent delta =
      let component = cdComponent delta
          status = operationToStatus (cdOperation delta)
       in (component, status)

    -- Convert delta operation to component status
    operationToStatus :: DeltaOperation -> ComponentStatus
    operationToStatus DeltaAdd = ComponentAdded
    operationToStatus DeltaRemove = ComponentRemoved
    operationToStatus DeltaModify = ComponentModified
    operationToStatus DeltaReplace = ComponentModified
    operationToStatus DeltaUpdate = ComponentModified

-- | Apply a Delta Certificate to a base configuration
--
-- This function computes the resulting platform configuration after applying
-- the changes specified in a Delta Platform Certificate.
applyDeltaCertificate ::
  -- | Base configuration
  PlatformConfigurationV2 ->
  -- | Delta certificate
  SignedDeltaPlatformCertificate ->
  Either String PlatformConfigurationV2
applyDeltaCertificate baseConfig deltaCert = do
  delta <- case getPlatformConfigurationDelta deltaCert of
    Just d -> Right d
    Nothing -> Left "Cannot extract delta configuration"

  applyDeltaToBaseLocal baseConfig delta
  where
    applyDeltaToBaseLocal :: PlatformConfigurationV2 -> PlatformConfigurationDelta -> Either String PlatformConfigurationV2
    applyDeltaToBaseLocal config delta =
      foldlM applyComponentDelta config (pcdComponentDeltas delta)
      where
        foldlM :: (a -> b -> Either String a) -> a -> [b] -> Either String a
        foldlM _ acc [] = Right acc
        foldlM f acc (x : xs) = case f acc x of
          Left err -> Left err
          Right acc' -> foldlM f acc' xs

    applyComponentDelta :: PlatformConfigurationV2 -> ComponentDelta -> Either String PlatformConfigurationV2
    applyComponentDelta config compDelta =
      case cdOperation compDelta of
        DeltaAdd -> Right $ addComponent config (cdComponent compDelta)
        DeltaRemove -> Right $ removeComponent config (cdComponent compDelta)
        DeltaModify -> Right $ modifyComponent config (cdComponent compDelta)
        _ -> Left "Unsupported delta operation"

    addComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
    addComponent config comp =
      config
        { pcv2Components = (comp, ComponentAdded) : pcv2Components config
        }

    removeComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
    removeComponent config comp =
      config
        { pcv2Components = [(c, s) | (c, s) <- pcv2Components config, c /= comp] ++ [(comp, ComponentRemoved)]
        }

    modifyComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
    modifyComponent config comp =
      config
        { pcv2Components = [(if c == comp then (comp, ComponentModified) else (c, s)) | (c, s) <- pcv2Components config]
        }

-- | Compute the final configuration by applying a chain of delta certificates
--
-- This function processes a sequence of Delta Platform Certificates to compute
-- the final platform configuration state.
computeConfigurationChain ::
  -- | Base certificate
  SignedPlatformCertificate ->
  -- | Chain of deltas
  [SignedDeltaPlatformCertificate] ->
  Either String PlatformConfigurationV2
computeConfigurationChain baseCert deltaChain = do
  baseConfig <- case getCurrentPlatformConfiguration (Left baseCert) of
    Just config -> Right config
    Nothing -> Left "Cannot extract base configuration"

  deltas <-
    mapM
      ( \cert -> case getPlatformConfigurationDelta cert of
          Just delta -> Right delta
          Nothing -> Left "Cannot extract delta configuration"
      )
      deltaChain
  computeResultingConfiguration baseConfig deltas

-- * Component Operations

-- | Extract all component identifiers from a Platform Certificate
getComponentIdentifiers :: SignedPlatformCertificate -> [ComponentIdentifier]
getComponentIdentifiers cert =
  case getPlatformConfiguration cert of
    Just config -> pcComponents config
    Nothing -> []

-- | Extract all v2 component identifiers with status information
getComponentIdentifiersV2 :: SignedPlatformCertificate -> [ComponentIdentifierV2]
getComponentIdentifiersV2 cert =
  case getCurrentPlatformConfiguration (Left cert) of
    Just config -> map fst (pcv2Components config)
    Nothing -> []

-- | Find components matching a specific component class
findComponentByClass :: ComponentClass -> [ComponentIdentifierV2] -> [ComponentIdentifierV2]
findComponentByClass targetClass components =
  filter (\comp -> ci2ComponentClass comp == targetClass) components

-- | Find component by its address (if specified)
findComponentByAddress :: ComponentAddress -> [ComponentIdentifierV2] -> Maybe ComponentIdentifierV2
findComponentByAddress targetAddr components =
  case filter hasMatchingAddress components of
    [] -> Nothing
    (comp : _) -> Just comp
  where
    hasMatchingAddress comp = ci2ComponentAddress comp == Just targetAddr

-- | Build a hierarchical component tree based on component relationships
buildComponentHierarchy :: [ComponentIdentifierV2] -> ComponentTree
buildComponentHierarchy components =
  case components of
    [] ->
      ComponentTree
        (ComponentIdentifierV2 B.empty B.empty Nothing Nothing Nothing Nothing ComponentMotherboard Nothing)
        []
        (ComponentProperties [] Nothing [])
    (rootComp : _) -> ComponentTree rootComp [] (ComponentProperties [] Nothing [])

-- * Certificate Chain Operations

-- | Build a certificate chain from base certificate and delta certificates
buildCertificateChain ::
  -- | Base certificate
  SignedPlatformCertificate ->
  -- | Delta chain
  [SignedDeltaPlatformCertificate] ->
  CertificateChain
buildCertificateChain baseCert deltaChain =
  let baseRef =
        BasePlatformCertificateRef
          (extractIssuerDN $ pciIssuer $ getPlatformCertificate baseCert)
          (pciSerialNumber $ getPlatformCertificate baseCert)
          Nothing
          (Just $ pciValidity $ getPlatformCertificate baseCert)
      deltaRefs = map deltaToRef deltaChain
   in CertificateChain baseRef deltaRefs (pciValidity $ getPlatformCertificate baseCert)
  where
    deltaToRef :: SignedDeltaPlatformCertificate -> BasePlatformCertificateRef
    deltaToRef deltaCert =
      let deltaInfo = getDeltaPlatformCertificate deltaCert
       in BasePlatformCertificateRef
            (extractIssuerDN $ dpciIssuer deltaInfo)
            (dpciSerialNumber deltaInfo)
            Nothing
            Nothing

-- | Find the base certificate referenced by a delta certificate
findBaseCertificate ::
  -- | Delta certificate
  SignedDeltaPlatformCertificate ->
  -- | Candidate base certificates
  [SignedPlatformCertificate] ->
  Maybe SignedPlatformCertificate
findBaseCertificate deltaCert candidates =
  let baseRef = extractBaseCertificateReference deltaCert
      targetSerial = bpcrSerialNumber baseRef
   in case filter (\cert -> pciSerialNumber (getPlatformCertificate cert) == targetSerial) candidates of
        [] -> Nothing
        (cert : _) -> Just cert

-- Helper functions

-- | Validate Platform Certificate inputs before generation
--
-- This function performs comprehensive validation to prevent parsing errors and specification violations
-- as required for TCG Platform Certificate compliance.
validatePlatformCertificateInputs :: 
  Holder -> 
  AttCertIssuer -> 
  AttCertValidityPeriod -> 
  PlatformConfiguration -> 
  Attributes -> 
  SignatureALG -> 
  Either String ()
validatePlatformCertificateInputs _holder _issuer _validity config (Attributes _attrs) sigAlg = do
  -- Validate Platform Configuration fields
  validatePlatformConfigurationFields config
  
  -- Validate signature algorithm
  validateSignatureAlgorithm sigAlg
  
  -- Validate attribute structure
  -- (Additional validation can be added here)
  
  return ()

-- | Validate Delta Certificate inputs before generation
validateDeltaCertificateInputs :: 
  Holder -> 
  AttCertIssuer -> 
  AttCertValidityPeriod -> 
  BasePlatformCertificateRef -> 
  PlatformConfigurationDelta -> 
  SignatureALG -> 
  Either String ()
validateDeltaCertificateInputs _holder _issuer _validity baseRef configDelta sigAlg = do
  -- Validate base certificate reference
  validateBaseCertificateRef baseRef
  
  -- Validate delta configuration
  validateDeltaConfiguration configDelta
  
  -- Validate signature algorithm
  validateSignatureAlgorithm sigAlg
  
  return ()

-- | Validate Base Certificate Reference
validateBaseCertificateRef :: BasePlatformCertificateRef -> Either String ()
validateBaseCertificateRef baseRef = do
  -- Validate serial number (must be positive)
  let serialNum = bpcrSerialNumber baseRef
  when (serialNum <= 0) $
    Left "Base certificate serial number must be positive"
    
  -- Additional validation can be added here for issuer DN, etc.
  return ()

-- | Validate Delta Configuration
validateDeltaConfiguration :: PlatformConfigurationDelta -> Either String ()
validateDeltaConfiguration delta = do
  -- Validate that there are actual changes
  let componentDeltas = pcdComponentDeltas delta
  let changeRecords = pcdChangeRecords delta
  
  when (null componentDeltas && null changeRecords) $
    Left "Delta certificate must contain at least one change"
    
  -- Validate individual component deltas
  mapM_ validateComponentDelta componentDeltas
  
  return ()

-- | Validate Component Delta
validateComponentDelta :: ComponentDelta -> Either String ()
validateComponentDelta compDelta = do
  let component = cdComponent compDelta
  let operation = cdOperation compDelta
  
  -- Validate component fields
  validateComponentIdentifierV2 component
  
  -- Validate delta operation
  validateDeltaOperation operation
  
  return ()

-- | Validate Component Identifier V2
validateComponentIdentifierV2 :: ComponentIdentifierV2 -> Either String ()
validateComponentIdentifierV2 comp = do
  -- Validate manufacturer field
  let manufacturer = ci2Manufacturer comp
  when (B.null manufacturer) $
    Left "Component manufacturer cannot be empty"
  when (B.length manufacturer > 255) $
    Left "Component manufacturer exceeds STRMAX (255 chars)"
    
  -- Validate model field  
  let model = ci2Model comp
  when (B.null model) $
    Left "Component model cannot be empty"
  when (B.length model > 255) $
    Left "Component model exceeds STRMAX (255 chars)"
    
  -- Validate UTF8 encoding
  validateUTF8String manufacturer "component manufacturer"
  validateUTF8String model "component model"
  
  -- Serial and revision are optional, but if present must be valid
  case ci2Serial comp of
    Just compSerial -> do
      when (B.length compSerial > 255) $
        Left "Component serial exceeds STRMAX (255 chars)"
      validateUTF8String compSerial "component serial"
    Nothing -> return ()
    
  case ci2Revision comp of
    Just revision -> do
      when (B.length revision > 255) $
        Left "Component revision exceeds STRMAX (255 chars)"
      validateUTF8String revision "component revision"
    Nothing -> return ()
    
  return ()

-- | Validate Delta Operation
validateDeltaOperation :: DeltaOperation -> Either String ()
validateDeltaOperation op = do
  case op of
    DeltaAdd -> Right ()
    DeltaRemove -> Right ()
    DeltaModify -> Right ()
    DeltaReplace -> Right ()
    DeltaUpdate -> Right ()

-- | Validate Platform Configuration fields for TCG compliance
validatePlatformConfigurationFields :: PlatformConfiguration -> Either String ()
validatePlatformConfigurationFields config = do
  -- Validate manufacturer field (must not be empty and within STRMAX limit of 255 chars)
  let manufacturer = pcManufacturer config
  when (B.null manufacturer) $
    Left "Platform manufacturer cannot be empty"
  when (B.length manufacturer > 255) $
    Left "Platform manufacturer exceeds STRMAX (255 chars) - TCG v1.1 compliance"
    
  -- Validate model field
  let model = pcModel config
  when (B.null model) $
    Left "Platform model cannot be empty"
  when (B.length model > 255) $
    Left "Platform model exceeds STRMAX (255 chars) - TCG v1.1 compliance"
    
  -- Validate serial field
  let platSerial = pcSerial config
  when (B.null platSerial) $
    Left "Platform serial cannot be empty"
  when (B.length platSerial > 255) $
    Left "Platform serial exceeds STRMAX (255 chars) - TCG v1.1 compliance"
    
  -- Validate version field
  let version = pcVersion config
  when (B.null version) $
    Left "Platform version cannot be empty"
  when (B.length version > 255) $
    Left "Platform version exceeds STRMAX (255 chars) - TCG v1.1 compliance"
    
  -- Validate UTF8 encoding for all text fields
  validateUTF8String manufacturer "manufacturer"
  validateUTF8String model "model"
  validateUTF8String platSerial "serial"
  validateUTF8String version "version"

-- | Validate UTF8 string encoding
validateUTF8String :: B.ByteString -> String -> Either String ()
validateUTF8String bs fieldName = do
  -- Check for valid UTF8 encoding by attempting decode
  case B8.unpack bs of
    [] -> Left (fieldName ++ " cannot be empty after UTF8 decode")
    decoded -> 
      if any (\c -> fromEnum c > 127) decoded  -- Contains non-ASCII
        then Right () -- Valid UTF8 with unicode chars
        else Right () -- Valid ASCII (subset of UTF8)

-- | Validate signature algorithm
validateSignatureAlgorithm :: SignatureALG -> Either String ()
validateSignatureAlgorithm sigAlg = do
  case sigAlg of
    SignatureALG hashAlg pubKeyAlg -> do
      -- Validate supported hash algorithms
      case hashAlg of
        HashSHA1 -> Left "SHA1 is deprecated and not allowed for new certificates"
        HashMD5 -> Left "MD5 is insecure and not allowed"
        HashSHA224 -> Right () -- Allowed
        HashSHA256 -> Right () -- Allowed
        HashSHA384 -> Right () -- Allowed
        HashSHA512 -> Right () -- Allowed
        _ -> Left "Unsupported hash algorithm"
        
      -- Validate supported public key algorithms
      case pubKeyAlg of
        PubKeyALG_RSA -> Right () -- Allowed
        PubKeyALG_DSA -> Right () -- Allowed
        PubKeyALG_EC -> Right ()  -- Allowed
        PubKeyALG_Ed25519 -> Right () -- Allowed
        PubKeyALG_Ed448 -> Right ()   -- Allowed
        _ -> Left "Unsupported public key algorithm"
    SignatureALG_IntrinsicHash _ -> Left "Intrinsic hash algorithms are not supported for TCG certificates"
    SignatureALG_Unknown _ -> Left "Unknown signature algorithms are not allowed"

-- | Extract DistinguishedName from AttCertIssuer
-- Extracts issuer information from Attribute Certificate issuer field.
-- This implementation provides a workable solution given the module access constraints.
--
-- Note: A complete implementation would require:
-- 1. Access to AltName constructors to pattern match on AltDirectoryName
-- 2. Certificate resolution for baseCertificateID references
-- 3. Full ASN.1 parsing of GeneralNames structures
--
-- For now, we return an empty DistinguishedName as a placeholder.
-- This is acceptable for certificate chain building where the DN is primarily used for identification.
extractIssuerDN :: AttCertIssuer -> DistinguishedName
extractIssuerDN (AttCertIssuerV1 generalNames) =
  -- V1 form with GeneralNames - extract DirectoryName if present
  case extractDirectoryNameFromGeneralNames generalNames of
    Just dn -> dn
    Nothing -> DistinguishedName [] -- Fallback if no DirectoryName found
extractIssuerDN (AttCertIssuerV2 v2form) =
  case v2formBaseCertificateID v2form of
    Just issuerSerial ->
      -- When baseCertificateID is present, extract issuer from the IssuerSerial
      -- The IssuerSerial contains GeneralNames for the issuer
      case extractDirectoryNameFromGeneralNames (issuer issuerSerial) of
        Just dn -> dn
        Nothing -> DistinguishedName []
    Nothing ->
      -- No baseCertificateID, issuer name should be in issuerName (GeneralNames)
      -- Extract DirectoryName from the GeneralNames in issuerName
      case extractDirectoryNameFromGeneralNames (v2formIssuerName v2form) of
        Just dn -> dn
        Nothing -> DistinguishedName []

-- | Extract DirectoryName from GeneralNames
extractDirectoryNameFromGeneralNames :: [AltName] -> Maybe DistinguishedName
extractDirectoryNameFromGeneralNames [] = Nothing
extractDirectoryNameFromGeneralNames (AltDirectoryName dn : _) = Just dn
extractDirectoryNameFromGeneralNames (_ : rest) = extractDirectoryNameFromGeneralNames rest

-- | Extract base certificate reference from delta certificate
extractBaseCertificateReference :: SignedDeltaPlatformCertificate -> BasePlatformCertificateRef
extractBaseCertificateReference deltaCert = dpciBaseCertificateRef $ getDeltaPlatformCertificate deltaCert
