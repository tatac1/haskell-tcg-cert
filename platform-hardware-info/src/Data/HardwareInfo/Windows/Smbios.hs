{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Windows.Smbios
-- Description : Windows SMBIOS access via GetSystemFirmwareTable
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides Windows-specific functions to read SMBIOS data
-- using the GetSystemFirmwareTable Win32 API.

#ifdef WINDOWS
module Data.HardwareInfo.Windows.Smbios
  ( -- * SMBIOS access
    getRawSmbiosData
  , WindowsSmbiosData(..)
  ) where

import Foreign
import Foreign.C.Types
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe (unsafePackCStringLen)
import Data.Word (Word8, Word32)

-- | GetSystemFirmwareTable from kernel32.dll
-- UINT GetSystemFirmwareTable(
--   DWORD FirmwareTableProviderSignature,
--   DWORD FirmwareTableID,
--   PVOID pFirmwareTableBuffer,
--   DWORD BufferSize
-- );
-- Note: On x64 Windows, stdcall is not supported; use ccall instead
foreign import ccall "GetSystemFirmwareTable"
  c_GetSystemFirmwareTable :: CUInt -> CUInt -> Ptr () -> CUInt -> IO CUInt

-- | 'RSMB' signature for SMBIOS (Raw SMBIOS)
rsmb :: CUInt
rsmb = 0x52534D42  -- 'RSMB' in little-endian

-- | Windows SMBIOS data structure
data WindowsSmbiosData = WindowsSmbiosData
  { wsMajorVersion :: !Word8
  , wsMinorVersion :: !Word8
  , wsDmiRevision  :: !Word8
  , wsTableData    :: !ByteString
  } deriving (Show)

-- | Get raw SMBIOS data from Windows
getRawSmbiosData :: IO (Either String WindowsSmbiosData)
getRawSmbiosData = do
  -- First call: get required buffer size
  requiredSize <- c_GetSystemFirmwareTable rsmb 0 nullPtr 0
  if requiredSize == 0
    then return $ Left "GetSystemFirmwareTable failed to get size"
    else do
      -- Allocate buffer and get data
      allocaBytes (fromIntegral requiredSize) $ \buf -> do
        actualSize <- c_GetSystemFirmwareTable rsmb 0 buf requiredSize
        if actualSize == 0
          then return $ Left "GetSystemFirmwareTable failed to get data"
          else do
            -- Parse RawSMBIOSData structure:
            -- Byte 0: Used20CallingMethod
            -- Byte 1: SMBIOSMajorVersion
            -- Byte 2: SMBIOSMinorVersion
            -- Byte 3: DmiRevision
            -- Bytes 4-7: Length (DWORD)
            -- Bytes 8+: SMBIOSTableData
            majorVer <- peekByteOff buf 1 :: IO Word8
            minorVer <- peekByteOff buf 2 :: IO Word8
            dmiRev   <- peekByteOff buf 3 :: IO Word8
            tableLen <- peekByteOff buf 4 :: IO Word32

            -- Copy table data to ByteString
            tableData <- unsafePackCStringLen
              (buf `plusPtr` 8, fromIntegral tableLen)

            return $ Right WindowsSmbiosData
              { wsMajorVersion = majorVer
              , wsMinorVersion = minorVer
              , wsDmiRevision  = dmiRev
              , wsTableData    = BS.copy tableData  -- make a safe copy
              }

#else
-- Non-Windows stub
module Data.HardwareInfo.Windows.Smbios
  ( getRawSmbiosData
  , WindowsSmbiosData(..)
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word8)

data WindowsSmbiosData = WindowsSmbiosData
  { wsMajorVersion :: !Word8
  , wsMinorVersion :: !Word8
  , wsDmiRevision  :: !Word8
  , wsTableData    :: !ByteString
  } deriving (Show)

getRawSmbiosData :: IO (Either String WindowsSmbiosData)
getRawSmbiosData = return $ Left "Windows support not compiled"
#endif
