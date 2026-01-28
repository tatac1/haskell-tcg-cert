{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Data.HardwareInfo.Smbios.Parser
-- Description : SMBIOS binary data parser
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to parse raw SMBIOS binary data
-- into structured Haskell types.

module Data.HardwareInfo.Smbios.Parser
  ( -- * Parsing
    parseSmbiosTable
  , parseSmbiosStructures
  , parseEntryPoint32
  , parseEntryPoint64
    -- * Structure access
  , findStructuresByType
  , getStructureString
  , getStructureByte
  , getStructureWord
  , getStructureDWord
  , getStructureQWord
    -- * High-level extraction
  , extractSystemInfo
  , extractBaseboardInfo
  , extractBiosInfo
  , extractProcessorInfo
  , extractMemoryDevices
  , extractChassisInfo
  , extractTpmInfo
  , extractPowerSupplyInfo
  , extractBatteryInfo
  , extractCoolingDevices
  , extractBmcInfo
    -- * Re-exports
  , SmbiosTable(..)
  , SmbiosStructure(..)
  , SmbiosHeader(..)
  , SmbiosType(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8, Word16, Word32, Word64)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Bits (shiftL, shiftR, (.|.), (.&.))
import Data.Maybe (mapMaybe)

import Data.HardwareInfo.Types
import Data.HardwareInfo.Smbios.Types

-- | Parse complete SMBIOS table from raw binary data
parseSmbiosTable :: SmbiosEntryPoint -> ByteString -> Either String SmbiosTable
parseSmbiosTable ep rawData = do
  structures <- parseSmbiosStructures rawData
  return SmbiosTable
    { tableEntryPoint = ep
    , tableStructures = structures
    }

-- | Parse SMBIOS structures from raw binary data
-- The data should start at the first structure (after entry point)
parseSmbiosStructures :: ByteString -> Either String [SmbiosStructure]
parseSmbiosStructures = go []
  where
    go acc bs
      | BS.null bs = Right (reverse acc)
      | BS.length bs < 4 = Right (reverse acc)  -- Not enough for header
      | otherwise = do
          (struct, rest) <- parseOneStructure bs
          -- Check for end-of-table marker (type 127)
          if headerType (structHeader struct) == 127
            then Right (reverse (struct : acc))
            else go (struct : acc) rest

-- | Parse a single SMBIOS structure
parseOneStructure :: ByteString -> Either String (SmbiosStructure, ByteString)
parseOneStructure bs
  | BS.length bs < 4 = Left "Not enough data for SMBIOS header"
  | otherwise = do
      let header = parseHeader bs
          len = fromIntegral (headerLength header)
      if BS.length bs < len
        then Left "Structure length exceeds available data"
        else do
          let formatted = BS.drop 4 $ BS.take len bs  -- Skip header, take formatted
              afterFormatted = BS.drop len bs
              (strings, rest) = parseStrings afterFormatted
          Right (SmbiosStructure header formatted strings, rest)

-- | Parse 4-byte SMBIOS header
parseHeader :: ByteString -> SmbiosHeader
parseHeader bs = SmbiosHeader
  { headerType   = BS.index bs 0
  , headerLength = BS.index bs 1
  , headerHandle = getWord16LE bs 2
  }

-- | Parse null-terminated string table
-- Strings are separated by single null bytes, table ends with double null
parseStrings :: ByteString -> ([ByteString], ByteString)
parseStrings = go []
  where
    go acc bs
      | BS.null bs = (reverse acc, bs)
      | BS.head bs == 0 = (reverse acc, BS.drop 1 bs)  -- End of strings
      | otherwise =
          let (str, rest) = BS.break (== 0) bs
          in if BS.null rest
               then (reverse (str : acc), BS.empty)
               else go (str : acc) (BS.drop 1 rest)  -- Skip null terminator

-- | Parse 32-bit SMBIOS entry point (_SM_)
parseEntryPoint32 :: ByteString -> Either String SmbiosEntryPoint
parseEntryPoint32 bs
  | BS.length bs < 31 = Left "Entry point too short for 32-bit format"
  | BS.take 4 bs /= "_SM_" = Left "Invalid 32-bit entry point signature"
  | otherwise = Right SmbiosEntryPoint
      { epMajorVersion = BS.index bs 6
      , epMinorVersion = BS.index bs 7
      , epRevision     = 0
      , epTableLength  = fromIntegral $ getWord16LE bs 22
      , epTableAddress = getWord32LE bs 24
      , epIs64Bit      = False
      }

-- | Parse 64-bit SMBIOS entry point (_SM3_)
parseEntryPoint64 :: ByteString -> Either String SmbiosEntryPoint
parseEntryPoint64 bs
  | BS.length bs < 24 = Left "Entry point too short for 64-bit format"
  | BS.take 5 bs /= "_SM3_" = Left "Invalid 64-bit entry point signature"
  | otherwise = Right SmbiosEntryPoint
      { epMajorVersion = BS.index bs 7
      , epMinorVersion = BS.index bs 8
      , epRevision     = BS.index bs 9
      , epTableLength  = getWord32LE bs 12
      , epTableAddress = fromIntegral $ getWord32LE bs 16  -- Truncate 64-bit address
      , epIs64Bit      = True
      }

-- | Find all structures of a given type
findStructuresByType :: Word8 -> SmbiosTable -> [SmbiosStructure]
findStructuresByType t table =
  filter (\s -> headerType (structHeader s) == t) (tableStructures table)

-- | Get a string from structure's string table (1-indexed as per SMBIOS spec)
getStructureString :: SmbiosStructure -> Int -> Maybe Text
getStructureString struct idx
  | idx <= 0 = Nothing  -- 0 means no string
  | idx > length (structStrings struct) = Nothing
  | otherwise =
      let bs = structStrings struct !! (idx - 1)
      in Just $ sanitizeString $ decodeText bs

-- | Get byte at offset in formatted section (offset from start of structure, not header)
-- Note: SMBIOS spec offsets include header, so subtract 4
getStructureByte :: SmbiosStructure -> Int -> Maybe Word8
getStructureByte struct offset
  | adjustedOffset < 0 = Nothing
  | adjustedOffset >= BS.length (structFormatted struct) = Nothing
  | otherwise = Just $ BS.index (structFormatted struct) adjustedOffset
  where
    adjustedOffset = offset - 4  -- Subtract header size

-- | Get 16-bit word at offset (little-endian)
getStructureWord :: SmbiosStructure -> Int -> Maybe Word16
getStructureWord struct offset
  | adjustedOffset < 0 = Nothing
  | adjustedOffset + 1 >= BS.length (structFormatted struct) = Nothing
  | otherwise = Just $ getWord16LE (structFormatted struct) adjustedOffset
  where
    adjustedOffset = offset - 4

-- | Get 32-bit dword at offset (little-endian)
getStructureDWord :: SmbiosStructure -> Int -> Maybe Word32
getStructureDWord struct offset
  | adjustedOffset < 0 = Nothing
  | adjustedOffset + 3 >= BS.length (structFormatted struct) = Nothing
  | otherwise = Just $ getWord32LE (structFormatted struct) adjustedOffset
  where
    adjustedOffset = offset - 4

-- | Get 64-bit qword at offset (little-endian)
getStructureQWord :: SmbiosStructure -> Int -> Maybe Word64
getStructureQWord struct offset
  | adjustedOffset < 0 = Nothing
  | adjustedOffset + 7 >= BS.length (structFormatted struct) = Nothing
  | otherwise = Just $ getWord64LE (structFormatted struct) adjustedOffset
  where
    adjustedOffset = offset - 4

-- | Extract System Information (Type 1)
extractSystemInfo :: SmbiosTable -> Maybe PlatformInfo
extractSystemInfo table =
  case findStructuresByType 1 table of
    [] -> Nothing
    (s:_) -> Just PlatformInfo
      { platformManufacturer = fromMaybe "" $ getStringAt s 0x04
      , platformModel        = fromMaybe "" $ getStringAt s 0x05
      , platformVersion      = fromMaybe "" $ getStringAt s 0x06
      , platformSerial       = getStringAt s 0x07
      , platformUUID         = extractUUID s
      , platformSKU          = getStringAt s 0x19
      , platformFamily       = getStringAt s 0x1A
      }

-- | Extract Baseboard Information (Type 2)
extractBaseboardInfo :: SmbiosTable -> Maybe Component
extractBaseboardInfo table =
  case findStructuresByType 2 table of
    [] -> Nothing
    (s:_) -> Just Component
      { componentClass        = ClassBaseboard
      , componentManufacturer = fromMaybe "" $ getStringAt s 0x04
      , componentModel        = fromMaybe "" $ getStringAt s 0x05
      , componentSerial       = getStringAt s 0x07
      , componentRevision     = getStringAt s 0x06
      , componentFieldReplaceable = Nothing
      , componentAddresses    = []
      }

-- | Extract BIOS Information (Type 0)
extractBiosInfo :: SmbiosTable -> Maybe Component
extractBiosInfo table =
  case findStructuresByType 0 table of
    [] -> Nothing
    (s:_) -> Just Component
      { componentClass        = ClassBIOS
      , componentManufacturer = fromMaybe "" $ getStringAt s 0x04
      , componentModel        = fromMaybe "" $ getStringAt s 0x05  -- Version as model
      , componentSerial       = Nothing
      , componentRevision     = getStringAt s 0x06  -- Release date
      , componentFieldReplaceable = Just False
      , componentAddresses    = []
      }

-- | Extract Processor Information (Type 4)
extractProcessorInfo :: SmbiosTable -> [Component]
extractProcessorInfo table =
  mapMaybe extractOneProcessor (findStructuresByType 4 table)
  where
    extractOneProcessor s = Just Component
      { componentClass        = ClassCPU
      , componentManufacturer = fromMaybe "" $ getStringAt s 0x07
      , componentModel        = fromMaybe "" $ getStringAt s 0x10
      , componentSerial       = getStringAt s 0x20
      , componentRevision     = Nothing
      , componentFieldReplaceable = Just True
      , componentAddresses    = []
      }

-- | Extract Memory Devices (Type 17)
extractMemoryDevices :: SmbiosTable -> [Component]
extractMemoryDevices table =
  mapMaybe extractOneMemory (findStructuresByType 17 table)
  where
    extractOneMemory s =
      -- Skip empty slots (size = 0)
      case getStructureWord s 0x0C of
        Just 0 -> Nothing
        Just 0xFFFF -> Nothing  -- Unknown size
        _ -> Just Component
          { componentClass        = ClassRAM
          , componentManufacturer = fromMaybe "" $ getStringAt s 0x17
          , componentModel        = fromMaybe "" $ getStringAt s 0x1A  -- Part number
          , componentSerial       = getStringAt s 0x18
          , componentRevision     = Nothing
          , componentFieldReplaceable = Just True
          , componentAddresses    = []
          }

-- | Extract Chassis Information (Type 3)
extractChassisInfo :: SmbiosTable -> Maybe Component
extractChassisInfo table =
  case findStructuresByType 3 table of
    [] -> Nothing
    (s:_) -> Just Component
      { componentClass        = ClassChassis
      , componentManufacturer = fromMaybe "" $ getStringAt s 0x04
      , componentModel        = fromMaybe "" $ getStringAt s 0x06  -- Version as model
      , componentSerial       = getStringAt s 0x07
      , componentRevision     = Nothing
      , componentFieldReplaceable = Just False
      , componentAddresses    = []
      }

-- | Extract TPM Information (Type 43)
extractTpmInfo :: SmbiosTable -> Maybe Component
extractTpmInfo table =
  case findStructuresByType 43 table of
    [] -> Nothing
    (s:_) -> Just Component
      { componentClass        = ClassTPM
      , componentManufacturer = extractTpmVendor s
      , componentModel        = "TPM"
      , componentSerial       = Nothing
      , componentRevision     = extractTpmVersion s
      , componentFieldReplaceable = Just False
      , componentAddresses    = []
      }
  where
    extractTpmVendor s =
      case getStructureDWord s 0x04 of
        Just v -> T.pack $ show v  -- Vendor ID as numeric string
        Nothing -> ""
    extractTpmVersion s =
      case (getStructureByte s 0x08, getStructureByte s 0x09) of
        (Just major, Just minor) -> Just $ T.pack $ show major ++ "." ++ show minor
        _ -> Nothing

-- | Extract Power Supply Information (Type 39)
extractPowerSupplyInfo :: SmbiosTable -> [Component]
extractPowerSupplyInfo table =
  mapMaybe extractOnePowerSupply (findStructuresByType 39 table)
  where
    extractOnePowerSupply s = Just Component
      { componentClass        = ClassPowerSupply
      , componentManufacturer = fromMaybe "" $ getStringAt s 0x07
      , componentModel        = fromMaybe "" $ getStringAt s 0x0A  -- Model Part Number
      , componentSerial       = getStringAt s 0x08
      , componentRevision     = getStringAt s 0x0B  -- Revision Level
      , componentFieldReplaceable = Just True
      , componentAddresses    = []
      }

-- | Extract Battery Information (Type 22)
extractBatteryInfo :: SmbiosTable -> [Component]
extractBatteryInfo table =
  mapMaybe extractOneBattery (findStructuresByType 22 table)
  where
    extractOneBattery s = Just Component
      { componentClass        = ClassBattery
      , componentManufacturer = fromMaybe "" $ getStringAt s 0x05
      , componentModel        = fromMaybe "" $ getStringAt s 0x08  -- Device Name
      , componentSerial       = getStringAt s 0x07
      , componentRevision     = getStringAt s 0x0E  -- SBDS Version String
      , componentFieldReplaceable = Just True
      , componentAddresses    = []
      }

-- | Extract Cooling Devices (Type 27)
extractCoolingDevices :: SmbiosTable -> [Component]
extractCoolingDevices table =
  mapMaybe extractOneCooling (findStructuresByType 27 table)
  where
    extractOneCooling s =
      let desc = getStringAt s 0x0E  -- Description (SMBIOS 2.7+)
          deviceType = getStructureByte s 0x06
          -- Device type is in bits 0-4, status in bits 5-7
          typeVal = fmap (\t -> t .&. 0x1F) deviceType
          cls = case typeVal of
                  Just 0x03 -> ClassChassisFan   -- Fan
                  Just 0x04 -> ClassChassisFan   -- Centrifugal Blower
                  Just 0x05 -> ClassChassisFan   -- Chip Fan
                  Just 0x06 -> ClassSocketFan    -- Cabinet Fan
                  Just 0x07 -> ClassSocketFan    -- Power Supply Fan
                  _         -> ClassGeneralCooling
      in Just Component
        { componentClass        = cls
        , componentManufacturer = ""
        , componentModel        = fromMaybe "Cooling Device" desc
        , componentSerial       = Nothing
        , componentRevision     = Nothing
        , componentFieldReplaceable = Just True
        , componentAddresses    = []
        }

-- | Extract BMC Information (Type 38 - IPMI Device)
extractBmcInfo :: SmbiosTable -> Maybe Component
extractBmcInfo table =
  case findStructuresByType 38 table of
    [] -> Nothing
    (s:_) ->
      let ifaceType = getStructureByte s 0x04
          specRev = getStructureByte s 0x05
          revStr = case specRev of
                     Just r -> Just $ T.pack $ show (r `shiftR` 4) ++ "." ++ show (r .&. 0x0F)
                     Nothing -> Nothing
          ifaceName = case ifaceType of
                        Just 0x00 -> "Unknown"
                        Just 0x01 -> "KCS"
                        Just 0x02 -> "SMIC"
                        Just 0x03 -> "BT"
                        Just 0x04 -> "SSIF"
                        _         -> "IPMI"
      in Just Component
        { componentClass        = ClassBMC
        , componentManufacturer = ""
        , componentModel        = T.pack $ "BMC (" ++ ifaceName ++ ")"
        , componentSerial       = Nothing
        , componentRevision     = revStr
        , componentFieldReplaceable = Just False
        , componentAddresses    = []
        }

-- Helper functions

getStringAt :: SmbiosStructure -> Int -> Maybe Text
getStringAt s offset = do
  idx <- getStructureByte s offset
  getStructureString s (fromIntegral idx)

extractUUID :: SmbiosStructure -> Maybe Text
extractUUID s = do
  -- UUID is at offset 0x08, 16 bytes
  let formatted = structFormatted s
      uuidOffset = 0x08 - 4  -- Adjust for header
  if BS.length formatted < uuidOffset + 16
    then Nothing
    else
      let uuidBytes = BS.take 16 $ BS.drop uuidOffset formatted
      in Just $ formatUUID uuidBytes

formatUUID :: ByteString -> Text
formatUUID bs
  | BS.length bs < 16 = ""
  | otherwise = T.pack $ concat
      [ hexByte (BS.index bs 3), hexByte (BS.index bs 2)
      , hexByte (BS.index bs 1), hexByte (BS.index bs 0), "-"
      , hexByte (BS.index bs 5), hexByte (BS.index bs 4), "-"
      , hexByte (BS.index bs 7), hexByte (BS.index bs 6), "-"
      , hexByte (BS.index bs 8), hexByte (BS.index bs 9), "-"
      , hexByte (BS.index bs 10), hexByte (BS.index bs 11)
      , hexByte (BS.index bs 12), hexByte (BS.index bs 13)
      , hexByte (BS.index bs 14), hexByte (BS.index bs 15)
      ]
  where
    hexByte b = let h = "0123456789ABCDEF"
                in [h !! fromIntegral (b `div` 16), h !! fromIntegral (b `mod` 16)]

getWord16LE :: ByteString -> Int -> Word16
getWord16LE bs offset =
  fromIntegral (BS.index bs offset)
    .|. (fromIntegral (BS.index bs (offset + 1)) `shiftL` 8)

getWord32LE :: ByteString -> Int -> Word32
getWord32LE bs offset =
  fromIntegral (BS.index bs offset)
    .|. (fromIntegral (BS.index bs (offset + 1)) `shiftL` 8)
    .|. (fromIntegral (BS.index bs (offset + 2)) `shiftL` 16)
    .|. (fromIntegral (BS.index bs (offset + 3)) `shiftL` 24)

getWord64LE :: ByteString -> Int -> Word64
getWord64LE bs offset =
  fromIntegral (BS.index bs offset)
    .|. (fromIntegral (BS.index bs (offset + 1)) `shiftL` 8)
    .|. (fromIntegral (BS.index bs (offset + 2)) `shiftL` 16)
    .|. (fromIntegral (BS.index bs (offset + 3)) `shiftL` 24)
    .|. (fromIntegral (BS.index bs (offset + 4)) `shiftL` 32)
    .|. (fromIntegral (BS.index bs (offset + 5)) `shiftL` 40)
    .|. (fromIntegral (BS.index bs (offset + 6)) `shiftL` 48)
    .|. (fromIntegral (BS.index bs (offset + 7)) `shiftL` 56)

decodeText :: ByteString -> Text
decodeText bs = case TE.decodeUtf8' bs of
  Right t -> t
  Left _  -> TE.decodeLatin1 bs  -- Fallback for non-UTF8

-- | Sanitize string (trim whitespace, handle OEM placeholders)
sanitizeString :: Text -> Text
sanitizeString t =
  let trimmed = T.strip t
  in if isPlaceholder trimmed
       then ""
       else trimmed
  where
    isPlaceholder s = s `elem`
      [ "To Be Filled By O.E.M."
      , "To be filled by O.E.M."
      , "Default string"
      , "Not Specified"
      , "None"
      , "Unknown"
      , "N/A"
      , ""
      ]

fromMaybe :: a -> Maybe a -> a
fromMaybe def Nothing  = def
fromMaybe _   (Just x) = x
