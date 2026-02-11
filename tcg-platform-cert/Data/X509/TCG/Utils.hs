{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Utils
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Library
-- Stability   : experimental
-- Portability : unknown
--
-- Utility functions for TCG Platform Certificate operations.
-- This module provides common helper functions, type utilities,
-- and conversion functions used throughout the TCG library.

module Data.X509.TCG.Utils
  ( -- * Certificate Type Utilities
    isPlatformCertificate,
    isDeltaCertificate,
    
    -- * Configuration Utilities
    applyDeltaToBase,
    
    -- * Component Utilities
    ComponentTreeUtils(..),
    
    -- * Attribute Utilities
    lookupAttributeByOID,
    extractTCGAttributes,
    
    -- * Conversion Utilities
    upgradeComponentToV2,
    downgradeComponentFromV2,
    
    -- * Error Utilities
    TCGError(..),
    formatError,
  ) where

import Data.Maybe (mapMaybe, fromMaybe)
import Data.List (foldl')
import Data.X509.Attribute (Attributes(..), Attribute(..), AttributeValue)
import Data.X509.TCG.Platform
import Data.X509.TCG.Delta hiding (applyDeltaToBase)
import Data.X509.TCG.Component
import Data.X509.TCG.Attributes (TCGAttribute, parseTCGAttribute)
import Data.X509.TCG.OID
import Data.ASN1.Types (OID)

-- * Certificate Type Utilities

-- | Check if a certificate is a Platform Certificate
--
-- This function examines certificate attributes to determine if it
-- represents a standard Platform Certificate (as opposed to a Delta).
--
-- Example:
-- @
-- if isPlatformCertificate cert
--   then processPlatformCert cert
--   else handleOtherCertType cert
-- @
isPlatformCertificate :: SignedPlatformCertificate -> Bool
isPlatformCertificate cert = 
  let attrs = pciAttributes $ getPlatformCertificate cert
  in hasAttribute tcg_at_platformConfiguration attrs ||
     hasAttribute tcg_at_platformConfiguration_v2 attrs
  where
    hasAttribute :: OID -> Attributes -> Bool
    hasAttribute targetOID (Attributes attrList) = 
      any (\attr -> attrType attr == targetOID) attrList

-- | Check if a certificate is a Delta Platform Certificate
--
-- Delta certificates are identified by the presence of delta-specific
-- attributes and base certificate references.
isDeltaCertificate :: SignedDeltaPlatformCertificate -> Bool
isDeltaCertificate deltaCert =
  let deltaInfo = getDeltaPlatformCertificate deltaCert
      attrs = dpciAttributes deltaInfo
  in hasAttribute tcg_at_platformConfiguration_v2 attrs
  where
    hasAttribute :: OID -> Attributes -> Bool
    hasAttribute targetOID (Attributes attrList) = 
      any (\attr -> attrType attr == targetOID) attrList

-- * Configuration Utilities


-- | Apply a single configuration delta to a base configuration
--
-- This function takes a base configuration and applies the changes
-- specified in a platform configuration delta.
applyDeltaToBase :: PlatformConfigurationV2 
                 -> PlatformConfigurationDelta 
                 -> Either TCGError PlatformConfigurationV2
applyDeltaToBase config delta = do
  -- Apply component deltas
  configWithComponents <- foldl' applyComponentDelta (Right config) (pcdComponentDeltas delta)
  
  -- Apply platform info changes if present
  case pcdPlatformInfoChanges delta of
    Nothing -> Right configWithComponents
    Just infoChanges -> applyPlatformInfoChanges (Right configWithComponents) infoChanges
  where
    applyComponentDelta :: Either TCGError PlatformConfigurationV2 
                        -> ComponentDelta 
                        -> Either TCGError PlatformConfigurationV2
    applyComponentDelta (Left err) _ = Left err
    applyComponentDelta (Right cfg) compDelta = 
      case cdOperation compDelta of
        DeltaAdd -> Right $ addComponent cfg (cdComponent compDelta)
        DeltaRemove -> Right $ removeComponent cfg (cdComponent compDelta)
        DeltaModify -> Right $ modifyComponent cfg (cdComponent compDelta)
        DeltaReplace -> case cdPreviousComponent compDelta of
          Just prevComp -> Right $ replaceComponent cfg (Just prevComp) (cdComponent compDelta)
          Nothing -> Right $ replaceComponent cfg Nothing (cdComponent compDelta)
        DeltaUpdate -> Right $ updateComponent cfg (cdComponent compDelta)

-- | Apply platform information changes to configuration
applyPlatformInfoChanges :: Either TCGError PlatformConfigurationV2 
                        -> PlatformInfoDelta 
                        -> Either TCGError PlatformConfigurationV2
applyPlatformInfoChanges (Left err) _ = Left err
applyPlatformInfoChanges (Right config) infoChanges = Right $ config
  { pcv2Manufacturer = fromMaybe (pcv2Manufacturer config) (pidManufacturerChange infoChanges)
  , pcv2Model = fromMaybe (pcv2Model config) (pidModelChange infoChanges)
  , pcv2Serial = fromMaybe (pcv2Serial config) (pidSerialChange infoChanges)
  , pcv2Version = fromMaybe (pcv2Version config) (pidVersionChange infoChanges)
  }

-- * Component Utilities

-- | Component hierarchy tree structure
--
-- This data type represents the hierarchical relationship between
-- components in a platform certificate.
data ComponentTreeUtils = ComponentTreeUtils
  { ctComponents :: [ComponentIdentifierV2]
    -- ^ All components in the tree
  , ctHierarchy :: [(ComponentIdentifierV2, [ComponentIdentifierV2])]
    -- ^ Parent-child relationships
  } deriving (Show, Eq)


-- * Attribute Utilities

-- | Lookup an attribute value by OID
--
-- This function searches through attributes to find one matching
-- the specified OID and returns its value.
--
-- Example:
-- @
-- case lookupAttributeByOID tcg_at_platformManufacturer attrs of
--   Just value -> processManufacturer value
--   Nothing -> handleMissingAttribute
-- @
lookupAttributeByOID :: OID -> Attributes -> Maybe [AttributeValue]
lookupAttributeByOID targetOID (Attributes attrList) = 
  case filter (\attr -> attrType attr == targetOID) attrList of
    [] -> Nothing
    (attr:_) -> Just $ concat $ attrValues attr

-- | Extract and parse all TCG-specific attributes from a generic attribute list
--
-- This function processes a list of attributes and extracts only those
-- that are recognized TCG attributes, parsing them into the appropriate types.
extractTCGAttributes :: Attributes -> [TCGAttribute]
extractTCGAttributes (Attributes attrList) = 
  mapMaybe parseAttribute attrList
  where
    parseAttribute :: Attribute -> Maybe TCGAttribute
    parseAttribute attr = case parseTCGAttribute attr of
      Right tcgAttr -> Just tcgAttr
      Left _ -> Nothing

-- * Conversion Utilities

-- | Upgrade a v1 ComponentIdentifier to v2 format
--
-- This function converts legacy component identifiers to the enhanced
-- v2 format with additional fields for better component tracking.
upgradeComponentToV2 :: ComponentIdentifier -> ComponentIdentifierV2
upgradeComponentToV2 comp = ComponentIdentifierV2
  { ci2Manufacturer = ciManufacturer comp
  , ci2Model = ciModel comp
  , ci2Serial = ciSerial comp
  , ci2Revision = ciRevision comp
  , ci2ManufacturerSerial = ciManufacturerSerial comp
  , ci2ManufacturerRevision = ciManufacturerRevision comp
  , ci2ComponentClass = ComponentOther []  -- Default class for upgraded components
  , ci2ComponentAddress = Nothing       -- No address information in v1
  }

-- | Downgrade a v2 ComponentIdentifier to v1 format
--
-- This function converts v2 component identifiers back to the legacy
-- v1 format, losing v2-specific information in the process.
downgradeComponentFromV2 :: ComponentIdentifierV2 -> ComponentIdentifier
downgradeComponentFromV2 comp = ComponentIdentifier
  { ciManufacturer = ci2Manufacturer comp
  , ciModel = ci2Model comp
  , ciSerial = ci2Serial comp
  , ciRevision = ci2Revision comp
  , ciManufacturerSerial = ci2ManufacturerSerial comp
  , ciManufacturerRevision = ci2ManufacturerRevision comp
  }

-- * Error Utilities

-- | Comprehensive error type for TCG operations
data TCGError
  = ParseError String                    -- ^ ASN.1 parsing failed
  | ValidationError String              -- ^ Certificate validation failed
  | ConfigurationError String           -- ^ Configuration operation failed
  | ComponentError String               -- ^ Component operation failed
  | NotImplemented String               -- ^ Feature not yet implemented
  | InternalError String                -- ^ Internal library error
  deriving (Show, Eq)

-- | Format error messages for user-friendly display
--
-- This function takes a TCGError and formats it into a readable
-- error message suitable for logging or user display.
--
-- Example:
-- @
-- case operation of
--   Left err -> putStrLn $ formatError err
--   Right result -> processResult result
-- @
formatError :: TCGError -> String
formatError err = case err of
  ParseError msg -> "Parse error: " ++ msg
  ValidationError msg -> "Validation error: " ++ msg
  ConfigurationError msg -> "Configuration error: " ++ msg
  ComponentError msg -> "Component error: " ++ msg
  NotImplemented feature -> "Not implemented: " ++ feature
  InternalError msg -> "Internal error: " ++ msg

-- * Helper Functions (Internal)

-- Component manipulation helper functions moved from other modules

-- | Add a component to platform configuration
addComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
addComponent config component = 
  config { pcv2Components = pcv2Components config ++ [(component, ComponentAdded)] }

-- | Remove a component from platform configuration
removeComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2  
removeComponent config component = 
  config { pcv2Components = filter ((/= component) . fst) (pcv2Components config) }

-- | Modify a component in platform configuration
modifyComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
modifyComponent config component = 
  config { pcv2Components = map updateStatus (pcv2Components config) }
  where
    updateStatus (comp, status) 
      | comp == component = (comp, ComponentModified)
      | otherwise = (comp, status)

-- | Replace a component in platform configuration
replaceComponent :: PlatformConfigurationV2 -> Maybe ComponentIdentifierV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
replaceComponent config Nothing newComp = addComponent config newComp
replaceComponent config (Just oldComp) newComp = 
  addComponent (removeComponent config oldComp) newComp

-- | Update a component in platform configuration
updateComponent :: PlatformConfigurationV2 -> ComponentIdentifierV2 -> PlatformConfigurationV2
updateComponent config component = 
  config { pcv2Components = map updateStatus (pcv2Components config) }
  where
    updateStatus (comp, status)
      | comp == component = (comp, ComponentModified)
      | otherwise = (comp, status)