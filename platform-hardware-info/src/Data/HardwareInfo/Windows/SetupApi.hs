{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Windows.SetupApi
-- Description : Windows PCI device enumeration via SetupAPI
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to enumerate PCI devices on Windows
-- using the SetupAPI (SetupDiGetClassDevs, SetupDiEnumDeviceInfo, etc.).
-- This includes GPUs, storage controllers, USB controllers, etc.

#ifdef WINDOWS
module Data.HardwareInfo.Windows.SetupApi
  ( -- * Device enumeration
    getGpuDevices
  , getStorageControllers
  , getUsbControllers
  , getNetworkControllers
    -- * Low-level functions
  , enumerateDevicesByClass
  , PciDeviceInfo(..)
  ) where

import Control.Exception (try, SomeException, bracket, finally)
import Control.Monad (forM, when)
import Data.Bits ((.|.), (.&.))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word8, Word16, Word32)
import Foreign.C.Types (CUInt(..), CULong(..), CInt(..), CWchar(..))
import Foreign.Marshal.Alloc (alloca, allocaBytes, malloc, free)
import Foreign.Marshal.Array (allocaArray, peekArray)
import Foreign.Ptr (Ptr, nullPtr, castPtr, plusPtr)
import Foreign.Storable (peek, poke, peekByteOff, pokeByteOff, sizeOf)
import qualified Data.ByteString as BS
import System.Win32.Types (DWORD, BOOL, HANDLE, LPCTSTR, LPDWORD)
import Numeric (readHex)

import Data.HardwareInfo.Types

-- | PCI device information from SetupAPI
data PciDeviceInfo = PciDeviceInfo
  { pciDescription    :: !Text
  , pciManufacturer   :: !Text
  , pciHardwareId     :: !Text
  , pciVendorId       :: !(Maybe Word16)
  , pciDeviceId       :: !(Maybe Word16)
  , pciSubsystemId    :: !(Maybe Word32)
  } deriving (Show, Eq)

-- | GUID structure (16 bytes)
data GUID = GUID
  { guidData1 :: !Word32
  , guidData2 :: !Word16
  , guidData3 :: !Word16
  , guidData4 :: !BS.ByteString  -- 8 bytes
  }

-- | Device class GUIDs
-- Display adapters: {4d36e968-e325-11ce-bfc1-08002be10318}
guidDisplay :: GUID
guidDisplay = GUID 0x4d36e968 0xe325 0x11ce (BS.pack [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18])

-- Storage controllers: {4d36e97b-e325-11ce-bfc1-08002be10318}
guidStorageController :: GUID
guidStorageController = GUID 0x4d36e97b 0xe325 0x11ce (BS.pack [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18])

-- USB controllers: {36fc9e60-c465-11cf-8056-444553540000}
guidUsbController :: GUID
guidUsbController = GUID 0x36fc9e60 0xc465 0x11cf (BS.pack [0x80, 0x56, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00])

-- Network adapters: {4d36e972-e325-11ce-bfc1-08002be10318}
guidNetworkAdapter :: GUID
guidNetworkAdapter = GUID 0x4d36e972 0xe325 0x11ce (BS.pack [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18])

-- | SetupAPI constants
dIGCF_PRESENT :: DWORD
dIGCF_PRESENT = 0x00000002

dIGCF_DEVICEINTERFACE :: DWORD
dIGCF_DEVICEINTERFACE = 0x00000010

-- Device registry property IDs
sPDRP_DEVICEDESC :: DWORD
sPDRP_DEVICEDESC = 0x00000000

sPDRP_HARDWAREID :: DWORD
sPDRP_HARDWAREID = 0x00000001

sPDRP_MFG :: DWORD
sPDRP_MFG = 0x0000000B

sPDRP_FRIENDLYNAME :: DWORD
sPDRP_FRIENDLYNAME = 0x0000000C

-- | SP_DEVINFO_DATA structure
-- typedef struct _SP_DEVINFO_DATA {
--   DWORD cbSize;           // 4 bytes
--   GUID  ClassGuid;        // 16 bytes
--   DWORD DevInst;          // 4 bytes
--   ULONG_PTR Reserved;     // 8 bytes on x64, 4 bytes on x86
-- } SP_DEVINFO_DATA;
spDevinfoDataSize :: Int
#if defined(x86_64_HOST_ARCH) || defined(aarch64_HOST_ARCH)
spDevinfoDataSize = 32  -- 4 + 16 + 4 + 8 = 32 bytes on x64/arm64
#else
spDevinfoDataSize = 28  -- 4 + 16 + 4 + 4 = 28 bytes on x86
#endif

-- | Invalid handle value for SetupAPI
iNVALID_HANDLE_VALUE_SETUP :: HANDLE
iNVALID_HANDLE_VALUE_SETUP = castPtr (nullPtr `plusPtrHack` (-1))
  where
    -- Workaround for creating invalid handle
    plusPtrHack :: Ptr a -> Int -> Ptr a
    plusPtrHack p n = castPtr (castPtr p `plusPtr` n)

-- | FFI imports for SetupAPI
foreign import stdcall "setupapi.h SetupDiGetClassDevsW"
  c_SetupDiGetClassDevsW :: Ptr GUID -> LPCTSTR -> HANDLE
                         -> DWORD -> IO HANDLE

foreign import stdcall "setupapi.h SetupDiEnumDeviceInfo"
  c_SetupDiEnumDeviceInfo :: HANDLE -> DWORD -> Ptr Word8
                          -> IO BOOL

foreign import stdcall "setupapi.h SetupDiGetDeviceRegistryPropertyW"
  c_SetupDiGetDeviceRegistryPropertyW :: HANDLE -> Ptr Word8 -> DWORD
                                      -> Ptr DWORD -> Ptr Word8 -> DWORD
                                      -> Ptr DWORD -> IO BOOL

foreign import stdcall "setupapi.h SetupDiDestroyDeviceInfoList"
  c_SetupDiDestroyDeviceInfoList :: HANDLE -> IO BOOL

-- | Write GUID to memory
pokeGuid :: Ptr Word8 -> GUID -> IO ()
pokeGuid ptr (GUID d1 d2 d3 d4) = do
  pokeByteOff ptr 0 d1
  pokeByteOff ptr 4 d2
  pokeByteOff ptr 6 d3
  let d4bytes = BS.unpack d4
  mapM_ (\(i, b) -> pokeByteOff ptr (8 + i) b) (zip [0..] d4bytes)

-- | Initialize SP_DEVINFO_DATA structure
initSpDevinfoData :: Ptr Word8 -> IO ()
initSpDevinfoData ptr = do
  -- Zero out the structure
  mapM_ (\i -> pokeByteOff ptr i (0 :: Word8)) [0..spDevinfoDataSize-1]
  -- Set cbSize
  pokeByteOff ptr 0 (fromIntegral spDevinfoDataSize :: Word32)

-- | Get GPU devices via SetupAPI
getGpuDevices :: IO [Component]
getGpuDevices = do
  devices <- enumerateDevicesByGuid guidDisplay
  return $ map toGpuComponent devices

-- | Get storage controllers via SetupAPI
getStorageControllers :: IO [Component]
getStorageControllers = do
  devices <- enumerateDevicesByGuid guidStorageController
  return $ map toStorageControllerComponent devices

-- | Get USB controllers via SetupAPI
getUsbControllers :: IO [Component]
getUsbControllers = do
  devices <- enumerateDevicesByGuid guidUsbController
  return $ map toUsbControllerComponent devices

-- | Get network controllers via SetupAPI
getNetworkControllers :: IO [Component]
getNetworkControllers = do
  devices <- enumerateDevicesByGuid guidNetworkAdapter
  return $ map toNetworkControllerComponent devices

-- | Enumerate devices by class GUID
enumerateDevicesByGuid :: GUID -> IO [PciDeviceInfo]
enumerateDevicesByGuid guid = do
  result <- try $ allocaBytes 16 $ \guidPtr -> do
    pokeGuid guidPtr guid

    -- Get device info set
    hDevInfo <- c_SetupDiGetClassDevsW
                  (castPtr guidPtr)
                  nullPtr
                  nullPtr
                  dIGCF_PRESENT

    if hDevInfo == iNVALID_HANDLE_VALUE_SETUP
      then return []
      else enumerateDevices hDevInfo `finally`
             c_SetupDiDestroyDeviceInfoList hDevInfo

  case result of
    Left (_ :: SomeException) -> return []
    Right devices -> return devices

-- | Enumerate all devices in a device info set
enumerateDevices :: HANDLE -> IO [PciDeviceInfo]
enumerateDevices hDevInfo = allocaBytes spDevinfoDataSize $ \devInfoData -> do
  initSpDevinfoData devInfoData
  go 0 devInfoData []
  where
    go :: DWORD -> Ptr Word8 -> [PciDeviceInfo] -> IO [PciDeviceInfo]
    go index devInfoData acc = do
      initSpDevinfoData devInfoData
      success <- c_SetupDiEnumDeviceInfo hDevInfo index devInfoData
      if success == 0
        then return (reverse acc)
        else do
          mDevice <- getDeviceInfo hDevInfo devInfoData
          case mDevice of
            Just device -> go (index + 1) devInfoData (device : acc)
            Nothing -> go (index + 1) devInfoData acc

-- | Get information for a single device
getDeviceInfo :: HANDLE -> Ptr Word8 -> IO (Maybe PciDeviceInfo)
getDeviceInfo hDevInfo devInfoData = do
  -- Get device description
  desc <- getDeviceProperty hDevInfo devInfoData sPDRP_DEVICEDESC

  -- Get manufacturer
  mfg <- getDeviceProperty hDevInfo devInfoData sPDRP_MFG

  -- Get hardware ID
  hwId <- getDeviceProperty hDevInfo devInfoData sPDRP_HARDWAREID

  -- Parse vendor/device IDs from hardware ID
  let (vendorId, deviceId) = parseHardwareId hwId

  -- Only return if we have some description
  if T.null desc
    then return Nothing
    else return $ Just PciDeviceInfo
      { pciDescription = desc
      , pciManufacturer = mfg
      , pciHardwareId = hwId
      , pciVendorId = vendorId
      , pciDeviceId = deviceId
      , pciSubsystemId = Nothing
      }

-- | Get a device registry property as text
getDeviceProperty :: HANDLE -> Ptr Word8 -> DWORD -> IO Text
getDeviceProperty hDevInfo devInfoData propertyId = do
  let bufSize = 512
  allocaBytes bufSize $ \buffer ->
    alloca $ \requiredSizePtr -> do
      success <- c_SetupDiGetDeviceRegistryPropertyW
                   hDevInfo
                   devInfoData
                   propertyId
                   nullPtr
                   buffer
                   (fromIntegral bufSize)
                   requiredSizePtr

      if success == 0
        then return ""
        else do
          -- Read as wide string (UTF-16LE)
          requiredSize <- peek requiredSizePtr
          let charCount = fromIntegral requiredSize `div` 2
          if charCount <= 0
            then return ""
            else do
              -- Read UTF-16LE bytes and convert to Text
              bytes <- BS.packCStringLen (castPtr buffer, fromIntegral requiredSize)
              -- Remove null terminators and decode
              let cleanBytes = BS.takeWhile (/= 0) $
                               BS.filter (/= 0) $
                               bytes
              return $ decodeUtf16LE bytes

-- | Decode UTF-16LE ByteString to Text (simplified)
decodeUtf16LE :: BS.ByteString -> Text
decodeUtf16LE bs =
  case TE.decodeUtf16LE' (trimNulls bs) of
    Right t -> T.strip t
    Left _ -> ""
  where
    -- Trim trailing nulls
    trimNulls b =
      let len = BS.length b
          -- Find first double-null (end of string)
          findEnd i
            | i >= len - 1 = len
            | BS.index b i == 0 && BS.index b (i+1) == 0 = i
            | otherwise = findEnd (i + 2)
      in BS.take (findEnd 0) b

-- | Parse hardware ID to extract vendor and device IDs
-- Format: PCI\VEN_XXXX&DEV_YYYY&SUBSYS_ZZZZZZZZ&REV_RR
parseHardwareId :: Text -> (Maybe Word16, Maybe Word16)
parseHardwareId hwId =
  let upperHwId = T.toUpper hwId
      vendorId = extractHexValue "VEN_" upperHwId
      deviceId = extractHexValue "DEV_" upperHwId
  in (vendorId, deviceId)

-- | Extract hex value after a prefix
extractHexValue :: Text -> Text -> Maybe Word16
extractHexValue prefix t =
  case T.breakOn prefix t of
    (_, rest) | T.null rest -> Nothing
              | otherwise ->
                  let afterPrefix = T.drop (T.length prefix) rest
                      hexPart = T.take 4 afterPrefix
                  in case readHex (T.unpack hexPart) of
                       [(v, "")] -> Just (fromIntegral (v :: Integer))
                       _ -> Nothing

-- | Enumerate devices by class name (alternative method)
enumerateDevicesByClass :: Text -> IO [PciDeviceInfo]
enumerateDevicesByClass className
  | className == "Display" = enumerateDevicesByGuid guidDisplay
  | className == "hdc" || className == "SCSIAdapter" = enumerateDevicesByGuid guidStorageController
  | className == "USB" = enumerateDevicesByGuid guidUsbController
  | className == "Net" = enumerateDevicesByGuid guidNetworkAdapter
  | otherwise = return []

-- | Convert to GPU Component
toGpuComponent :: PciDeviceInfo -> Component
toGpuComponent dev = Component
  { componentClass = ClassGPU
  , componentManufacturer = cleanManufacturer $ pciManufacturer dev
  , componentModel = pciDescription dev
  , componentSerial = Nothing
  , componentRevision = Nothing
  , componentFieldReplaceable = Just True
  , componentAddresses = []
  }

-- | Convert to Storage Controller Component
toStorageControllerComponent :: PciDeviceInfo -> Component
toStorageControllerComponent dev = Component
  { componentClass = detectStorageControllerClass dev
  , componentManufacturer = cleanManufacturer $ pciManufacturer dev
  , componentModel = pciDescription dev
  , componentSerial = Nothing
  , componentRevision = Nothing
  , componentFieldReplaceable = Just True
  , componentAddresses = []
  }

-- | Convert to USB Controller Component
toUsbControllerComponent :: PciDeviceInfo -> Component
toUsbControllerComponent dev = Component
  { componentClass = ClassUSBController
  , componentManufacturer = cleanManufacturer $ pciManufacturer dev
  , componentModel = pciDescription dev
  , componentSerial = Nothing
  , componentRevision = Nothing
  , componentFieldReplaceable = Just False
  , componentAddresses = []
  }

-- | Convert to Network Controller Component
toNetworkControllerComponent :: PciDeviceInfo -> Component
toNetworkControllerComponent dev = Component
  { componentClass = ClassEthernetController
  , componentManufacturer = cleanManufacturer $ pciManufacturer dev
  , componentModel = pciDescription dev
  , componentSerial = Nothing
  , componentRevision = Nothing
  , componentFieldReplaceable = Just True
  , componentAddresses = []
  }

-- | Detect storage controller class from description
detectStorageControllerClass :: PciDeviceInfo -> ComponentClass
detectStorageControllerClass dev =
  let desc = T.toUpper (pciDescription dev)
  in if "SATA" `T.isInfixOf` desc || "AHCI" `T.isInfixOf` desc
       then ClassSATAController
     else if "SAS" `T.isInfixOf` desc
       then ClassSASController
     else if "RAID" `T.isInfixOf` desc
       then ClassRAIDController
     else if "SCSI" `T.isInfixOf` desc
       then ClassSCSIController
     else if "NVME" `T.isInfixOf` desc || "NVM EXPRESS" `T.isInfixOf` desc
       then ClassNVMe
     else ClassGeneralController

-- | Clean up manufacturer string
cleanManufacturer :: Text -> Text
cleanManufacturer mfg
  | T.null mfg = ""
  | "NVIDIA" `T.isInfixOf` T.toUpper mfg = "NVIDIA"
  | "AMD" `T.isInfixOf` T.toUpper mfg = "AMD"
  | "ATI" `T.isInfixOf` T.toUpper mfg = "AMD/ATI"
  | "INTEL" `T.isInfixOf` T.toUpper mfg = "Intel"
  | "MICROSOFT" `T.isInfixOf` T.toUpper mfg = "Microsoft"
  | "REALTEK" `T.isInfixOf` T.toUpper mfg = "Realtek"
  | "BROADCOM" `T.isInfixOf` T.toUpper mfg = "Broadcom"
  | "QUALCOMM" `T.isInfixOf` T.toUpper mfg = "Qualcomm"
  | "MARVELL" `T.isInfixOf` T.toUpper mfg = "Marvell"
  | "LSI" `T.isInfixOf` T.toUpper mfg = "LSI/Broadcom"
  | otherwise = T.strip mfg

#else
-- Non-Windows stub
module Data.HardwareInfo.Windows.SetupApi
  ( getGpuDevices
  , getStorageControllers
  , getUsbControllers
  , getNetworkControllers
  , enumerateDevicesByClass
  , PciDeviceInfo(..)
  ) where

import Data.Text (Text)
import Data.Word (Word16, Word32)
import Data.HardwareInfo.Types

data PciDeviceInfo = PciDeviceInfo
  { pciDescription    :: !Text
  , pciManufacturer   :: !Text
  , pciHardwareId     :: !Text
  , pciVendorId       :: !(Maybe Word16)
  , pciDeviceId       :: !(Maybe Word16)
  , pciSubsystemId    :: !(Maybe Word32)
  } deriving (Show, Eq)

getGpuDevices :: IO [Component]
getGpuDevices = return []

getStorageControllers :: IO [Component]
getStorageControllers = return []

getUsbControllers :: IO [Component]
getUsbControllers = return []

getNetworkControllers :: IO [Component]
getNetworkControllers = return []

enumerateDevicesByClass :: Text -> IO [PciDeviceInfo]
enumerateDevicesByClass _ = return []
#endif
