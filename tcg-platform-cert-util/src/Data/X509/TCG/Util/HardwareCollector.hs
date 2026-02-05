{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Data.X509.TCG.Util.HardwareCollector
-- Description : Integration between platform-hardware-info and TCG Platform Certificate
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to collect hardware information and convert
-- it to TCG Platform Certificate structures (PACCOR format).

module Data.X509.TCG.Util.HardwareCollector
  ( -- * Hardware collection
    collectHardware
  , collectHardwareComponents
    -- * Conversion to PACCOR format
  , hardwareToPaccorConfig
  , componentToPaccorComponent
    -- * Re-exports from platform-hardware-info
  , HardwareInfo(..)
  , PlatformInfo(..)
  , HW.Component(..)
  , ComponentClass(..)
  , ComponentAddress(..)
  , HardwareError(..)
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word32)
import Text.Printf (printf)

import Data.HardwareInfo
  ( HardwareInfo(..)
  , PlatformInfo(..)
  , ComponentClass(..)
  , ComponentAddress(..)
  , HardwareError(..)
  , getHardwareInfo
  , componentClassToTcgValue
  , tcgComponentClassRegistry
  )
import qualified Data.HardwareInfo as HW

import qualified Data.X509.TCG.Util.Paccor as P

-- | Collect hardware information from the current system
collectHardware :: IO (Either HardwareError HardwareInfo)
collectHardware = getHardwareInfo

-- | Collect hardware components directly
collectHardwareComponents :: IO (Either HardwareError [HW.Component])
collectHardwareComponents = do
  result <- getHardwareInfo
  return $ fmap hwComponents result

-- | Convert HardwareInfo to PACCOR Config format
hardwareToPaccorConfig :: HardwareInfo -> P.PaccorConfig
hardwareToPaccorConfig hw = P.PaccorConfig
  { P.paccorPlatform = platformToPaccor (hwPlatform hw)
  , P.paccorComponents = Just $ map componentToPaccorComponent (hwComponents hw)
  , P.paccorComponentsUri = Nothing
  , P.paccorProperties = Nothing
  , P.paccorPropertiesUri = Nothing
  }

-- | Convert PlatformInfo to PACCOR Platform format
platformToPaccor :: PlatformInfo -> P.PaccorPlatform
platformToPaccor p = P.PaccorPlatform
  { P.platformManufacturerStr = HW.platformManufacturer p
  , P.platformModel = HW.platformModel p
  , P.platformVersion = Just $ HW.platformVersion p
  , P.platformSerial = HW.platformSerial p
  , P.platformManufacturerId = Nothing
  }

-- | Convert Component to PACCOR Component format
componentToPaccorComponent :: HW.Component -> P.PaccorComponent
componentToPaccorComponent c = P.PaccorComponent
  { P.componentClass = componentClassToPaccor (HW.componentClass c)
  , P.componentManufacturer = Just $ HW.componentManufacturer c
  , P.componentModel = Just $ HW.componentModel c
  , P.componentSerial = HW.componentSerial c
  , P.componentRevision = HW.componentRevision c
  , P.componentManufacturerId = Nothing
  , P.componentFieldReplaceable = fmap boolToText (HW.componentFieldReplaceable c)
  , P.componentAddresses = case HW.componentAddresses c of
      [] -> Nothing
      addrs -> Just $ map addressToPaccor addrs
  , P.componentStatus = Nothing
  , P.componentPlatformCert = Nothing
  , P.componentPlatformCertUri = Nothing
  }

-- | Convert ComponentClass to PACCOR ComponentClass format
componentClassToPaccor :: ComponentClass -> P.PaccorComponentClass
componentClassToPaccor cls = P.PaccorComponentClass
  { P.componentClassRegistry = tcgComponentClassRegistry
  , P.componentClassValue = formatClassValue $ componentClassToTcgValue cls
  }
  where
    formatClassValue :: Word32 -> Text
    formatClassValue v = T.pack $ printf "%08X" v

-- | Convert ComponentAddress to PACCOR Address format
addressToPaccor :: ComponentAddress -> P.PaccorAddress
addressToPaccor addr = case addr of
  EthernetMAC mac -> emptyAddress { P.paccorEthernetMac = Just mac }
  WirelessMAC mac -> emptyAddress { P.paccorWlanMac = Just mac }
  BluetoothMAC mac -> emptyAddress { P.paccorBluetoothMac = Just mac }
  PCIAddress pci -> emptyAddress { P.paccorPciAddress = Just pci }
  USBAddress usb -> emptyAddress { P.paccorUsbAddress = Just usb }
  SATAAddress sata -> emptyAddress { P.paccorSataAddress = Just sata }
  WWNAddress wwn -> emptyAddress { P.paccorWwnAddress = Just wwn }
  NVMeAddress nvme -> emptyAddress { P.paccorNvmeAddress = Just nvme }
  LogicalAddress logical -> emptyAddress { P.paccorLogicalAddress = Just logical }
  where
    emptyAddress = P.PaccorAddress Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing

-- | Convert Bool to Text
boolToText :: Bool -> Text
boolToText True = "true"
boolToText False = "false"
