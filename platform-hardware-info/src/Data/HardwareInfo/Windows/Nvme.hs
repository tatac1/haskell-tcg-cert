{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Windows.Nvme
-- Description : Windows NVMe device information collection
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to collect NVMe device information
-- on Windows systems using DeviceIoControl and STORAGE_QUERY_PROPERTY.

#ifdef WINDOWS
module Data.HardwareInfo.Windows.Nvme
  ( -- * NVMe device enumeration
    getNvmeDevices
  , NvmeDeviceInfo(..)
    -- * All storage device enumeration
  , getAllStorageDevices
  , getSataDevices
  , getSasDevices
    -- * Low-level functions
  , enumeratePhysicalDrives
  , queryStorageProperty
    -- * Bus type constants
  , busTypeNvme
  , busTypeSata
  , busTypeSas
  , busTypeScsi
  , busTypeUsb
  , busTypeRAID
  ) where

import Control.Exception (try, SomeException, bracket)
import Control.Monad (forM, filterM)
import Data.Bits (shiftL, (.|.))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word8, Word32)
import Foreign.C.Types (CUInt(..), CULong(..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Utils (with)
import Foreign.Ptr (Ptr, nullPtr, plusPtr, castPtr)
import Foreign.Storable (Storable(..), peek, poke, peekByteOff)
import qualified Data.ByteString as BS
import System.Win32.Types (HANDLE, DWORD, BOOL, LPDWORD, iNVALID_HANDLE_VALUE)
import System.Win32.File (closeHandle)

import Data.HardwareInfo.Types

-- | NVMe device information
data NvmeDeviceInfo = NvmeDeviceInfo
  { nvmeDeviceName     :: !Text
  , nvmeModelNumber    :: !Text
  , nvmeSerialNumber   :: !Text
  , nvmeFirmwareRev    :: !Text
  , nvmeBusType        :: !Word32
  } deriving (Show, Eq)

-- | IOCTL codes
iOCTL_STORAGE_QUERY_PROPERTY :: DWORD
iOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400

-- | Storage property query types
data StoragePropertyQuery = StoragePropertyQuery
  { propertyId :: !Word32
  , queryType  :: !Word32
  , additionalParameters :: ![Word8]
  } deriving (Show)

-- | Bus types (from winioctl.h)
busTypeUnknown, busTypeScsi, busTypeAtapi, busTypeAta, busType1394 :: Word32
busTypeSsa, busTypeFibre, busTypeUsb, busTypeRAID, busTypeiScsi :: Word32
busTypeSas, busTypeSata, busTypeSd, busTypeMmc, busTypeVirtual :: Word32
busTypeFileBackedVirtual, busTypeSpaces, busTypeNvme, busTypeSCM :: Word32
busTypeUfs, busTypeMax :: Word32

busTypeUnknown = 0
busTypeScsi = 1
busTypeAtapi = 2
busTypeAta = 3
busType1394 = 4
busTypeSsa = 5
busTypeFibre = 6
busTypeUsb = 7
busTypeRAID = 8
busTypeiScsi = 9
busTypeSas = 10
busTypeSata = 11
busTypeSd = 12
busTypeMmc = 13
busTypeVirtual = 14
busTypeFileBackedVirtual = 15
busTypeSpaces = 16
busTypeNvme = 17
busTypeSCM = 18
busTypeUfs = 19
busTypeMax = 20

-- | Storage device descriptor offsets
storageDeviceDescriptorSize :: Int
storageDeviceDescriptorSize = 1024

-- | FFI imports
-- Note: On x64 Windows, stdcall is not supported; use ccall instead
foreign import ccall "windows.h CreateFileW"
  c_CreateFileW :: Ptr CUInt -> DWORD -> DWORD -> Ptr ()
                -> DWORD -> DWORD -> HANDLE -> IO HANDLE

foreign import ccall "windows.h DeviceIoControl"
  c_DeviceIoControl :: HANDLE -> DWORD -> Ptr a -> DWORD
                    -> Ptr b -> DWORD -> LPDWORD -> Ptr () -> IO BOOL

-- | Access rights
gENERIC_READ :: DWORD
gENERIC_READ = 0x80000000

-- | Share modes
fILE_SHARE_READ, fILE_SHARE_WRITE :: DWORD
fILE_SHARE_READ = 0x00000001
fILE_SHARE_WRITE = 0x00000002

-- | Creation disposition
oPEN_EXISTING :: DWORD
oPEN_EXISTING = 3

-- | Get NVMe devices on Windows
getNvmeDevices :: IO [Component]
getNvmeDevices = do
  drives <- enumeratePhysicalDrives
  nvmeInfos <- forM drives $ \driveNum -> do
    result <- queryStorageProperty driveNum
    return result

  -- Filter only NVMe devices and convert to Components
  let nvmeDevices = [info | Right info <- nvmeInfos, nvmeBusType info == busTypeNvme]
  return $ map toComponent nvmeDevices

-- | Get all storage devices (NVMe, SATA, SAS, SCSI, USB, RAID)
getAllStorageDevices :: IO [Component]
getAllStorageDevices = do
  drives <- enumeratePhysicalDrives
  deviceInfos <- forM drives $ \driveNum -> do
    result <- queryStorageProperty driveNum
    return result

  -- Filter physical storage devices (exclude virtual)
  let validBusTypes = [busTypeNvme, busTypeSata, busTypeSas, busTypeScsi,
                       busTypeUsb, busTypeRAID, busTypeAta, busTypeAtapi]
  let storageDevices = [info | Right info <- deviceInfos,
                               nvmeBusType info `elem` validBusTypes]
  return $ map toStorageComponent storageDevices

-- | Get SATA devices on Windows
getSataDevices :: IO [Component]
getSataDevices = do
  drives <- enumeratePhysicalDrives
  deviceInfos <- forM drives $ \driveNum -> do
    result <- queryStorageProperty driveNum
    return result

  let sataDevices = [info | Right info <- deviceInfos,
                           nvmeBusType info `elem` [busTypeSata, busTypeAta, busTypeAtapi]]
  return $ map toStorageComponent sataDevices

-- | Get SAS devices on Windows
getSasDevices :: IO [Component]
getSasDevices = do
  drives <- enumeratePhysicalDrives
  deviceInfos <- forM drives $ \driveNum -> do
    result <- queryStorageProperty driveNum
    return result

  let sasDevices = [info | Right info <- deviceInfos,
                          nvmeBusType info `elem` [busTypeSas, busTypeScsi]]
  return $ map toStorageComponent sasDevices

-- | Convert NvmeDeviceInfo to Component (for NVMe devices)
toComponent :: NvmeDeviceInfo -> Component
toComponent nvme = Component
  { componentClass = ClassNVMe
  , componentManufacturer = extractManufacturer (nvmeModelNumber nvme)
  , componentModel = nvmeModelNumber nvme
  , componentSerial = Just $ nvmeSerialNumber nvme
  , componentRevision = Just $ nvmeFirmwareRev nvme
  , componentFieldReplaceable = Just True
  , componentAddresses = []
  }

-- | Convert storage device info to Component with appropriate class
toStorageComponent :: NvmeDeviceInfo -> Component
toStorageComponent dev = Component
  { componentClass = busTypeToClass (nvmeBusType dev)
  , componentManufacturer = extractManufacturer (nvmeModelNumber dev)
  , componentModel = nvmeModelNumber dev
  , componentSerial = Just $ nvmeSerialNumber dev
  , componentRevision = Just $ nvmeFirmwareRev dev
  , componentFieldReplaceable = Just True
  , componentAddresses = []
  }

-- | Map bus type to TCG Component Class
busTypeToClass :: Word32 -> ComponentClass
busTypeToClass bt
  | bt == busTypeNvme  = ClassNVMe
  | bt == busTypeSata  = ClassSSD        -- Could be HDD, but assume SSD for SATA
  | bt == busTypeAta   = ClassHDD        -- Legacy ATA is typically HDD
  | bt == busTypeAtapi = ClassStorageDrive
  | bt == busTypeSas   = ClassStorageDrive
  | bt == busTypeScsi  = ClassStorageDrive
  | bt == busTypeUsb   = ClassStorageDrive
  | bt == busTypeRAID  = ClassStorageDrive
  | otherwise          = ClassGeneralStorage

-- | Extract manufacturer from model number (heuristic)
extractManufacturer :: Text -> Text
extractManufacturer model
  | "Samsung" `T.isInfixOf` model = "Samsung"
  | "WD" `T.isPrefixOf` model = "Western Digital"
  | "WDC" `T.isPrefixOf` model = "Western Digital"
  | "Intel" `T.isInfixOf` model = "Intel"
  | "Micron" `T.isInfixOf` model = "Micron"
  | "SK hynix" `T.isInfixOf` model = "SK hynix"
  | "HYNIX" `T.isInfixOf` model = "SK hynix"
  | "Toshiba" `T.isInfixOf` model = "Toshiba"
  | "KIOXIA" `T.isInfixOf` model = "KIOXIA"
  | "Crucial" `T.isInfixOf` model = "Crucial"
  | "Kingston" `T.isInfixOf` model = "Kingston"
  | "Seagate" `T.isInfixOf` model = "Seagate"
  | "ADATA" `T.isInfixOf` model = "ADATA"
  | "Sabrent" `T.isInfixOf` model = "Sabrent"
  | otherwise = ""

-- | Enumerate physical drives (0-15)
enumeratePhysicalDrives :: IO [Int]
enumeratePhysicalDrives = do
  filterM driveExists [0..15]
  where
    driveExists :: Int -> IO Bool
    driveExists n = do
      let path = "\\\\.\\PhysicalDrive" ++ show n
      result <- try $ withPhysicalDrive n $ \_ -> return ()
      case result of
        Left (_ :: SomeException) -> return False
        Right _ -> return True

-- | Open a physical drive handle
withPhysicalDrive :: Int -> (HANDLE -> IO a) -> IO a
withPhysicalDrive driveNum action = do
  let pathStr = "\\\\.\\PhysicalDrive" ++ show driveNum
  -- Convert to wide string (UTF-16)
  let pathBS = TE.encodeUtf16LE (T.pack pathStr <> "\0")
  BS.useAsCString pathBS $ \pathPtr -> do
    handle <- c_CreateFileW
      (castPtr pathPtr)
      gENERIC_READ
      (fILE_SHARE_READ .|. fILE_SHARE_WRITE)
      nullPtr
      oPEN_EXISTING
      0
      nullPtr

    if handle == iNVALID_HANDLE_VALUE
      then error $ "Failed to open " ++ pathStr
      else bracket (return handle) closeHandle action

-- | Query storage property for a physical drive
queryStorageProperty :: Int -> IO (Either Text NvmeDeviceInfo)
queryStorageProperty driveNum = do
  result <- try $ withPhysicalDrive driveNum $ \handle -> do
    -- Allocate query structure (PropertyStandardQuery = 0, StorageDeviceProperty = 0)
    allocaBytes 12 $ \queryPtr -> do
      -- Set PropertyId = 0 (StorageDeviceProperty)
      poke (castPtr queryPtr :: Ptr Word32) 0
      -- Set QueryType = 0 (PropertyStandardQuery)
      poke (castPtr (queryPtr `plusPtr` 4) :: Ptr Word32) 0
      -- Additional parameters = 0
      poke (castPtr (queryPtr `plusPtr` 8) :: Ptr Word32) 0

      -- Allocate output buffer
      allocaBytes storageDeviceDescriptorSize $ \outPtr -> do
        alloca $ \bytesReturnedPtr -> do
          success <- c_DeviceIoControl
            handle
            iOCTL_STORAGE_QUERY_PROPERTY
            queryPtr
            12
            outPtr
            (fromIntegral storageDeviceDescriptorSize)
            bytesReturnedPtr
            nullPtr

          if not success
            then return $ Left "DeviceIoControl failed"
            else parseStorageDeviceDescriptor driveNum outPtr

  case result of
    Left (e :: SomeException) -> return $ Left $ T.pack $ show e
    Right r -> return r

-- | Parse STORAGE_DEVICE_DESCRIPTOR structure
parseStorageDeviceDescriptor :: Int -> Ptr Word8 -> IO (Either Text NvmeDeviceInfo)
parseStorageDeviceDescriptor driveNum ptr = do
  -- STORAGE_DEVICE_DESCRIPTOR structure:
  -- DWORD Version (0)
  -- DWORD Size (4)
  -- BYTE DeviceType (8)
  -- BYTE DeviceTypeModifier (9)
  -- BOOLEAN RemovableMedia (10)
  -- BOOLEAN CommandQueueing (11)
  -- DWORD VendorIdOffset (12)
  -- DWORD ProductIdOffset (16)
  -- DWORD ProductRevisionOffset (20)
  -- DWORD SerialNumberOffset (24)
  -- STORAGE_BUS_TYPE BusType (28)
  -- ... more fields

  busType <- peekByteOff ptr 28 :: IO Word32
  vendorOffset <- peekByteOff ptr 12 :: IO Word32
  productOffset <- peekByteOff ptr 16 :: IO Word32
  revisionOffset <- peekByteOff ptr 20 :: IO Word32
  serialOffset <- peekByteOff ptr 24 :: IO Word32

  vendor <- if vendorOffset > 0 && vendorOffset < fromIntegral storageDeviceDescriptorSize
    then readNullTerminatedString ptr (fromIntegral vendorOffset)
    else return ""

  product' <- if productOffset > 0 && productOffset < fromIntegral storageDeviceDescriptorSize
    then readNullTerminatedString ptr (fromIntegral productOffset)
    else return ""

  revision <- if revisionOffset > 0 && revisionOffset < fromIntegral storageDeviceDescriptorSize
    then readNullTerminatedString ptr (fromIntegral revisionOffset)
    else return ""

  serial <- if serialOffset > 0 && serialOffset < fromIntegral storageDeviceDescriptorSize
    then readNullTerminatedString ptr (fromIntegral serialOffset)
    else return ""

  -- Combine vendor and product for model name
  let modelName = T.strip $ T.pack $ vendor ++ " " ++ product'

  return $ Right NvmeDeviceInfo
    { nvmeDeviceName = T.pack $ "\\\\.\\PhysicalDrive" ++ show driveNum
    , nvmeModelNumber = modelName
    , nvmeSerialNumber = T.strip $ T.pack serial
    , nvmeFirmwareRev = T.strip $ T.pack revision
    , nvmeBusType = busType
    }

-- | Read a null-terminated string from a buffer
readNullTerminatedString :: Ptr Word8 -> Int -> IO String
readNullTerminatedString basePtr offset = do
  let ptr = basePtr `plusPtr` offset
  go ptr 0 []
  where
    go :: Ptr Word8 -> Int -> String -> IO String
    go p n acc
      | n >= 256 = return $ reverse acc  -- Safety limit
      | otherwise = do
          c <- peekByteOff p n :: IO Word8
          if c == 0
            then return $ reverse acc
            else go p (n + 1) (toEnum (fromIntegral c) : acc)

#else
-- Non-Windows stub
module Data.HardwareInfo.Windows.Nvme
  ( getNvmeDevices
  , NvmeDeviceInfo(..)
  , getAllStorageDevices
  , getSataDevices
  , getSasDevices
  , busTypeNvme
  , busTypeSata
  , busTypeSas
  , busTypeScsi
  , busTypeUsb
  , busTypeRAID
  ) where

import Data.Text (Text)
import Data.Word (Word32)
import Data.HardwareInfo.Types

data NvmeDeviceInfo = NvmeDeviceInfo
  { nvmeDeviceName     :: !Text
  , nvmeModelNumber    :: !Text
  , nvmeSerialNumber   :: !Text
  , nvmeFirmwareRev    :: !Text
  , nvmeBusType        :: !Word32
  } deriving (Show, Eq)

getNvmeDevices :: IO [Component]
getNvmeDevices = return []

getAllStorageDevices :: IO [Component]
getAllStorageDevices = return []

getSataDevices :: IO [Component]
getSataDevices = return []

getSasDevices :: IO [Component]
getSasDevices = return []

busTypeNvme, busTypeSata, busTypeSas, busTypeScsi, busTypeUsb, busTypeRAID :: Word32
busTypeNvme = 17
busTypeSata = 11
busTypeSas = 10
busTypeScsi = 1
busTypeUsb = 7
busTypeRAID = 8
#endif
