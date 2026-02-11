{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Main
-- Description : Tests for platform-hardware-info
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3

module Main where

import Test.Tasty
import Test.Tasty.HUnit

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Data.HardwareInfo.Types
import Data.HardwareInfo.Smbios.Types
import Data.HardwareInfo.Smbios.Parser

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "platform-hardware-info"
  [ testGroup "Types" typesTests
  , testGroup "SMBIOS Parser" smbiosParserTests
  ]

-- | Tests for Types module
typesTests :: [TestTree]
typesTests =
  [ testCase "componentClassToTcgValue - CPU" $
      componentClassToTcgValue ClassCPU @?= 0x00010002

  , testCase "componentClassToTcgValue - RAM (legacy alias)" $
      componentClassToTcgValue ClassRAM @?= 0x00060000  -- General Memory

  , testCase "componentClassToTcgValue - NIC (legacy alias)" $
      componentClassToTcgValue ClassNIC @?= 0x00090002  -- Ethernet Adapter

  , testCase "componentClassToTcgValue - Baseboard" $
      componentClassToTcgValue ClassBaseboard @?= 0x00030003  -- Motherboard

  , testCase "componentClassToTcgValue - BIOS (legacy alias)" $
      componentClassToTcgValue ClassBIOS @?= 0x00130003  -- System Firmware

  , testCase "componentClassToTcgValue - TPM" $
      componentClassToTcgValue ClassTPM @?= 0x00040009  -- TPM per TCG spec

  , testCase "componentClassToTcgValue - GPU" $
      componentClassToTcgValue ClassGPU @?= 0x00010006

  , testCase "componentClassToTcgValue - NVMe" $
      componentClassToTcgValue ClassNVMe @?= 0x00070006

  , testCase "componentClassToTcgValue - PowerSupply" $
      componentClassToTcgValue ClassPowerSupply @?= 0x000A0002

  , testCase "componentClassToTcgValue - Battery" $
      componentClassToTcgValue ClassBattery @?= 0x000A0003

  , testCase "componentClassToTcgValue - BMC" $
      componentClassToTcgValue ClassBMC @?= 0x00050012

  , testCase "tcgComponentClassRegistry" $
      tcgComponentClassRegistry @?= "2.23.133.18.3.1"

  , testCase "emptyHardwareInfo" $
      hwComponents emptyHardwareInfo @?= []

  , testCase "emptyPlatformInfo" $
      platformManufacturer emptyPlatformInfo @?= ""
  ]

-- | Tests for SMBIOS Parser module
smbiosParserTests :: [TestTree]
smbiosParserTests =
  [ testCase "parseHeader - valid header" $ do
      let headerBytes = BS.pack [0x01, 0x1B, 0x00, 0x01]  -- Type 1, Length 27, Handle 256
          header = parseTestHeader headerBytes
      headerType header @?= 1
      headerLength header @?= 27
      headerHandle header @?= 256

  , testCase "parseSmbiosStructures - empty data" $ do
      let result = parseSmbiosStructures BS.empty
      case result of
        Right [] -> return ()
        Right _ -> assertFailure "Expected empty list"
        Left _ -> assertFailure "Expected success with empty list"

  , testCase "parseSmbiosStructures - end of table marker" $ do
      -- Type 127 (end of table), Length 4, Handle 0, followed by double null
      let endMarker = BS.pack [127, 4, 0, 0, 0, 0]
          result = parseSmbiosStructures endMarker
      case result of
        Right [s] -> headerType (structHeader s) @?= 127
        Right _ -> assertFailure "Expected single end-of-table structure"
        Left err -> assertFailure $ "Parse error: " ++ err

  , testCase "getStructureString - valid index" $ do
      let struct = SmbiosStructure
            { structHeader = SmbiosHeader 1 27 0
            , structFormatted = BS.pack [1, 2, 3]  -- String indices
            , structStrings = ["Test Manufacturer", "Test Model"]
            }
      getStructureString struct 1 @?= Just "Test Manufacturer"
      getStructureString struct 2 @?= Just "Test Model"

  , testCase "getStructureString - index 0 returns Nothing" $ do
      let struct = SmbiosStructure
            { structHeader = SmbiosHeader 1 27 0
            , structFormatted = BS.empty
            , structStrings = ["Test"]
            }
      getStructureString struct 0 @?= Nothing

  , testCase "getStructureString - out of bounds" $ do
      let struct = SmbiosStructure
            { structHeader = SmbiosHeader 1 27 0
            , structFormatted = BS.empty
            , structStrings = ["Test"]
            }
      getStructureString struct 5 @?= Nothing

  , testCase "findStructuresByType - filters correctly" $ do
      let struct1 = SmbiosStructure (SmbiosHeader 1 27 0) BS.empty []
          struct2 = SmbiosStructure (SmbiosHeader 2 15 1) BS.empty []
          struct3 = SmbiosStructure (SmbiosHeader 1 27 2) BS.empty []
          ep = SmbiosEntryPoint 3 0 0 100 0 False
          table = SmbiosTable ep [struct1, struct2, struct3]
          type1Structs = findStructuresByType 1 table
      length type1Structs @?= 2

  , testCase "SmbiosType values" $ do
      smbiosTypeValue TypeBiosInfo @?= 0
      smbiosTypeValue TypeSystemInfo @?= 1
      smbiosTypeValue TypeBaseboard @?= 2
      smbiosTypeValue TypeChassis @?= 3
      smbiosTypeValue TypeProcessor @?= 4
      smbiosTypeValue TypeMemoryDevice @?= 17
      smbiosTypeValue TypeTpm @?= 43
      smbiosTypeValue TypeEndOfTable @?= 127
  ]

-- | Helper to parse header for testing
parseTestHeader :: ByteString -> SmbiosHeader
parseTestHeader bs = SmbiosHeader
  { headerType = BS.index bs 0
  , headerLength = BS.index bs 1
  , headerHandle = fromIntegral (BS.index bs 2)
                   + fromIntegral (BS.index bs 3) * 256
  }
