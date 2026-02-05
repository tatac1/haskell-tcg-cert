{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.Block
-- Description : Linux block device enumeration (SATA, SAS, etc.)
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to enumerate block storage devices on Linux
-- systems using the sysfs interface (/sys/class/block/).

#ifdef LINUX
module Data.HardwareInfo.Linux.Block
  ( -- * Block device enumeration
    getBlockDevices
  , BlockDevice(..)
  , BlockTransport(..)
    -- * Filtering functions
  , getSataDevices
  , getScsiDevices
  , getAllStorageDevices
  , getOpticalDrives
  ) where

import Control.Applicative ((<|>))
import Control.Exception (try, SomeException)
import Control.Monad (forM)
import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import Data.Word (Word64, Word8)
import System.Directory (listDirectory, doesFileExist, doesDirectoryExist)
import System.FilePath ((</>))
import Text.Printf (printf)
import Text.Read (readMaybe)

import Data.HardwareInfo.Types
import Data.HardwareInfo.Linux.Sysfs (getBlockDeviceWWN, getBlockDeviceBusPath, getBlockDeviceSerial)

-- | Block device information
data BlockDevice = BlockDevice
  { blockName       :: !Text           -- ^ Device name (e.g., "sda", "nvme0n1")
  , blockModel      :: !Text           -- ^ Model name
  , blockVendor     :: !Text           -- ^ Vendor name
  , blockSerial     :: !(Maybe Text)   -- ^ Serial number
  , blockRevision   :: !(Maybe Text)   -- ^ Firmware revision
  , blockSize       :: !Word64         -- ^ Size in bytes
  , blockTransport  :: !BlockTransport -- ^ Transport type
  , blockRotational :: !Bool           -- ^ True if rotational (HDD)
  , blockWWN        :: !(Maybe Text)   -- ^ World Wide Name (from udev)
  , blockBusPath    :: !(Maybe Text)   -- ^ Bus path (e.g., "pci-0000:00:1f.2-ata-1")
  } deriving (Show, Eq)

-- | Block device transport type
data BlockTransport
  = TransportSATA      -- ^ SATA
  | TransportSAS       -- ^ SAS
  | TransportSCSI      -- ^ SCSI
  | TransportUSB       -- ^ USB
  | TransportNVMe      -- ^ NVMe (handled separately)
  | TransportMMC       -- ^ MMC/SD card
  | TransportVirtual   -- ^ Virtual device
  | TransportUnknown   -- ^ Unknown
  deriving (Show, Eq)

-- | Sysfs block devices path
blockDevicesPath :: FilePath
blockDevicesPath = "/sys/class/block"

-- | Get all block devices (excluding partitions)
getBlockDevices :: IO [BlockDevice]
getBlockDevices = do
  result <- try $ listDirectory blockDevicesPath
  case result of
    Left (_ :: SomeException) -> return []
    Right names -> do
      -- Filter out partitions (those with digits in name like sda1)
      let diskNames = filter isDiskDevice names
      devices <- forM diskNames $ \name -> do
        let devPath = blockDevicesPath </> name
        mDev <- readBlockDevice (T.pack name) devPath
        return mDev
      return [d | Just d <- devices]
  where
    -- Filter out partitions and virtual devices like loop, ram
    isDiskDevice name =
      not (any (`T.isPrefixOf` T.pack name) ["loop", "ram", "dm-", "md"]) &&
      not (hasTrailingDigit name && hasDiskPrefix name)

    hasTrailingDigit s = not (null s) && last s `elem` ['0'..'9'] &&
                         any (`T.isPrefixOf` T.pack s) ["sd", "hd", "vd", "xvd"]

    hasDiskPrefix s = any (`T.isPrefixOf` T.pack s) ["sd", "hd", "vd", "xvd", "nvme"]

-- | Read block device information from sysfs
readBlockDevice :: Text -> FilePath -> IO (Maybe BlockDevice)
readBlockDevice name devPath = do
  -- Check if this is a real disk (has a device subdirectory)
  let devicePath = devPath </> "device"
  hasDevice <- doesDirectoryExist devicePath

  if not hasDevice
    then return Nothing
    else do
      -- Read device attributes
      model <- readSysfsText (devicePath </> "model")
      vendor <- readSysfsText (devicePath </> "vendor")
      rev <- readSysfsText (devicePath </> "rev")

      -- Try to get serial from different locations (sysfs first, then udev)
      serial <- getSerial devicePath
      udevSerial <- getBlockDeviceSerial name
      let finalSerial = serial <|> udevSerial

      -- Get size
      sizeStr <- readSysfsText (devPath </> "size")
      let size = case sizeStr of
                   Just s -> maybe 0 (* 512) (readMaybe (T.unpack s) :: Maybe Word64)
                   Nothing -> 0

      -- Check if rotational
      rotStr <- readSysfsText (devPath </> "queue" </> "rotational")
      let rotational = case rotStr of
                         Just "1" -> True
                         _ -> False

      -- Determine transport type
      transport <- detectTransport devicePath name

      -- Get WWN and bus path from udev
      wwn <- getBlockDeviceWWN name
      busPath <- getBlockDeviceBusPath name

      -- Skip if no useful info
      if T.null (maybe "" id model) && T.null (maybe "" id vendor)
        then return Nothing
        else return $ Just BlockDevice
          { blockName = name
          , blockModel = maybe "" T.strip model
          , blockVendor = maybe "" T.strip vendor
          , blockSerial = fmap T.strip finalSerial
          , blockRevision = fmap T.strip rev
          , blockSize = size
          , blockTransport = transport
          , blockRotational = rotational
          , blockWWN = wwn
          , blockBusPath = busPath
          }

-- | Get serial number from various locations
-- Tries multiple sources in order of reliability:
-- 1. Direct serial attribute (plain text)
-- 2. VPD Page 80 (SCSI serial number, binary format)
-- 3. WWID (World Wide Identifier)
getSerial :: FilePath -> IO (Maybe Text)
getSerial devicePath = do
  -- Try direct serial attribute first (usually plain text)
  s1 <- readSysfsText (devicePath </> "serial")
  case s1 of
    Just s -> return $ Just s
    Nothing -> do
      -- Try VPD Page 80 (binary format, needs parsing)
      s2 <- parseVpdPage80 (devicePath </> "vpd_pg80")
      case s2 of
        Just s -> return $ Just s
        Nothing -> readSysfsText (devicePath </> "wwid")

-- | Parse VPD Page 80 (Unit Serial Number)
-- VPD Page 80 structure:
-- Byte 0: Peripheral qualifier + device type
-- Byte 1: Page code (0x80)
-- Byte 2: Reserved
-- Byte 3: Page length (N)
-- Bytes 4 to 4+N-1: Serial number (ASCII)
parseVpdPage80 :: FilePath -> IO (Maybe Text)
parseVpdPage80 path = do
  exists <- doesFileExist path
  if not exists
    then return Nothing
    else do
      result <- try $ BS.readFile path
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right content ->
          if BS.length content < 4
            then return Nothing
            else do
              -- Check page code (byte 1 should be 0x80)
              let pageCode = BS.index content 1
              if pageCode /= 0x80
                then return Nothing
                else do
                  -- Get page length and extract serial
                  let pageLen = fromIntegral (BS.index content 3) :: Int
                  if BS.length content < 4 + pageLen
                    then return Nothing
                    else do
                      let serialBytes = BS.take pageLen $ BS.drop 4 content
                      -- Filter to printable ASCII and trim whitespace
                      let serial = T.strip $ TE.decodeUtf8Lenient $
                                     BS.filter isPrintableAscii serialBytes
                      if T.null serial
                        then return Nothing
                        else return $ Just serial
  where
    isPrintableAscii :: Word8 -> Bool
    isPrintableAscii b = b >= 0x20 && b <= 0x7E

-- | Parse VPD Page 83 (Device Identification) for NAA identifier
-- VPD Page 83 contains multiple identification descriptors
-- We look for NAA (Name Address Authority) identifiers which are globally unique
parseVpdPage83Naa :: FilePath -> IO (Maybe Text)
parseVpdPage83Naa path = do
  exists <- doesFileExist path
  if not exists
    then return Nothing
    else do
      result <- try $ BS.readFile path
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right content ->
          if BS.length content < 4
            then return Nothing
            else do
              -- Check page code (byte 1 should be 0x83)
              let pageCode = BS.index content 1
              if pageCode /= 0x83
                then return Nothing
                else do
                  -- Parse identification descriptors starting at byte 4
                  let pageLen = fromIntegral (BS.index content 3) :: Int
                  let descriptorData = BS.take pageLen $ BS.drop 4 content
                  return $ findNaaIdentifier descriptorData
  where
    -- Parse descriptors looking for NAA type (code type 3)
    findNaaIdentifier :: ByteString -> Maybe Text
    findNaaIdentifier bs
      | BS.length bs < 4 = Nothing
      | otherwise =
          let codeSet = BS.index bs 0 .&. 0x0F
              idType = BS.index bs 1 .&. 0x0F
              idLen = fromIntegral (BS.index bs 3) :: Int
          in if BS.length bs < 4 + idLen
               then Nothing
               else if codeSet == 1 && idType == 3  -- Binary, NAA
                      then Just $ formatNaa $ BS.take idLen $ BS.drop 4 bs
                      else findNaaIdentifier $ BS.drop (4 + idLen) bs

    formatNaa :: ByteString -> Text
    formatNaa bs = T.pack $ "naa." ++ concatMap (printf "%02x") (BS.unpack bs)

-- | Detect transport type
detectTransport :: FilePath -> Text -> IO BlockTransport
detectTransport devicePath name
  | "nvme" `T.isPrefixOf` name = return TransportNVMe
  | "mmcblk" `T.isPrefixOf` name = return TransportMMC
  | "vd" `T.isPrefixOf` name = return TransportVirtual
  | otherwise = do
      -- Check for SATA/SAS by looking at the device tree
      -- SATA devices usually have ata* in their path
      -- SAS devices usually have sas* in their path
      transport <- readSysfsText (devicePath </> "transport")
      case transport of
        Just t | "sata" `T.isInfixOf` T.toLower t -> return TransportSATA
               | "sas" `T.isInfixOf` T.toLower t -> return TransportSAS
               | "usb" `T.isInfixOf` T.toLower t -> return TransportUSB
        _ -> do
          -- Check by looking at symlink target
          subsystem <- readSysfsText (devicePath </> "subsystem")
          case subsystem of
            Just s | "usb" `T.isInfixOf` T.toLower s -> return TransportUSB
            _ -> return TransportSATA  -- Default to SATA for sd* devices

-- | Read text from sysfs file
readSysfsText :: FilePath -> IO (Maybe Text)
readSysfsText path = do
  exists <- doesFileExist path
  if not exists
    then return Nothing
    else do
      result <- try $ TIO.readFile path
      case result of
        Left (_ :: SomeException) -> return Nothing
        Right content ->
          let stripped = T.strip content
          in if T.null stripped then return Nothing else return $ Just stripped

-- | Get SATA devices
getSataDevices :: IO [Component]
getSataDevices = do
  devices <- getBlockDevices
  let sata = filter (\d -> blockTransport d == TransportSATA) devices
  return $ map (blockToComponent ClassSSD) sata

-- | Get SCSI/SAS devices
getScsiDevices :: IO [Component]
getScsiDevices = do
  devices <- getBlockDevices
  let sas = filter (\d -> blockTransport d `elem` [TransportSAS, TransportSCSI]) devices
  return $ map (blockToComponent ClassStorageDrive) sas

-- | Get all storage devices (excluding NVMe, which is handled separately)
getAllStorageDevices :: IO [Component]
getAllStorageDevices = do
  devices <- getBlockDevices
  -- Exclude NVMe (handled by Nvme module) and virtual devices
  let storage = filter (\d -> blockTransport d `notElem` [TransportNVMe, TransportVirtual]) devices
  return $ map toComponent storage
  where
    toComponent dev =
      let cls = case (blockTransport dev, blockRotational dev) of
                  (TransportSATA, True)  -> ClassHDD
                  (TransportSATA, False) -> ClassSSD
                  (TransportSAS, True)   -> ClassHDD
                  (TransportSAS, False)  -> ClassSSD
                  (TransportUSB, _)      -> ClassStorageDrive
                  (TransportMMC, _)      -> ClassStorageDrive
                  _                      -> ClassStorageDrive
      in blockToComponent cls dev

-- | Convert BlockDevice to Component
blockToComponent :: ComponentClass -> BlockDevice -> Component
blockToComponent cls dev = Component
  { componentClass = cls
  , componentManufacturer = blockVendor dev
  , componentModel = if T.null (blockModel dev)
                       then blockName dev
                       else blockModel dev
  , componentSerial = blockSerial dev
  , componentRevision = blockRevision dev
  , componentFieldReplaceable = Just True
  , componentAddresses = buildAddresses dev
  }
  where
    -- Build list of addresses from WWN and bus path
    buildAddresses :: BlockDevice -> [ComponentAddress]
    buildAddresses d =
      let wwnAddr = case blockWWN d of
                      Just w -> [WWNAddress w]
                      Nothing -> []
          busAddr = case blockBusPath d of
                      Just p -> [SATAAddress p]
                      Nothing -> []
      in wwnAddr ++ busAddr

-- | Get optical drives (CD/DVD/Blu-Ray)
-- These are SCSI CDROM devices showing as sr* in /sys/class/block/
getOpticalDrives :: IO [Component]
getOpticalDrives = do
  result <- try $ listDirectory blockDevicesPath
  case result of
    Left (_ :: SomeException) -> return []
    Right names -> do
      -- Filter to sr* devices (SCSI CDROM)
      let cdromNames = filter ("sr" `T.isPrefixOf`) $ map T.pack names
      drives <- forM (map T.unpack cdromNames) $ \name -> do
        let devPath = blockDevicesPath </> name
        readOpticalDrive (T.pack name) devPath
      return [d | Just d <- drives]

-- | Read optical drive information
readOpticalDrive :: Text -> FilePath -> IO (Maybe Component)
readOpticalDrive name devPath = do
  let devicePath = devPath </> "device"
  hasDevice <- doesDirectoryExist devicePath

  if not hasDevice
    then return Nothing
    else do
      -- Read device attributes
      model <- readSysfsText (devicePath </> "model")
      vendor <- readSysfsText (devicePath </> "vendor")
      rev <- readSysfsText (devicePath </> "rev")

      -- Determine drive type from capabilities
      driveType <- detectOpticalDriveType devicePath

      return $ Just Component
        { componentClass = driveType
        , componentManufacturer = maybe "" T.strip vendor
        , componentModel = maybe name T.strip model
        , componentSerial = Nothing  -- Optical drives rarely have serial in sysfs
        , componentRevision = fmap T.strip rev
        , componentFieldReplaceable = Just True
        , componentAddresses = []
        }

-- | Detect optical drive type (DVD, Blu-Ray, CD-ROM)
-- Check /sys/class/block/sr*/device/type and capabilities
detectOpticalDriveType :: FilePath -> IO ComponentClass
detectOpticalDriveType devicePath = do
  -- Check media info from capabilities
  caps <- readSysfsText (devicePath </> "capabilities")
  model <- readSysfsText (devicePath </> "model")

  let modelLower = maybe "" T.toLower model

  -- Heuristics based on model name
  return $ case () of
    _ | "bd" `T.isInfixOf` modelLower -> ClassBluRayDrive
      | "blu" `T.isInfixOf` modelLower -> ClassBluRayDrive
      | "dvd" `T.isInfixOf` modelLower -> ClassDVDDrive
      | otherwise -> ClassDVDDrive  -- Default to DVD for modern drives

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Block
  ( getBlockDevices
  , getSataDevices
  , getScsiDevices
  , getAllStorageDevices
  , getOpticalDrives
  , BlockDevice(..)
  , BlockTransport(..)
  ) where

import Data.Text (Text)
import Data.Word (Word64)
import Data.HardwareInfo.Types

data BlockDevice = BlockDevice
  { blockName       :: !Text
  , blockModel      :: !Text
  , blockVendor     :: !Text
  , blockSerial     :: !(Maybe Text)
  , blockRevision   :: !(Maybe Text)
  , blockSize       :: !Word64
  , blockTransport  :: !BlockTransport
  , blockRotational :: !Bool
  , blockWWN        :: !(Maybe Text)
  , blockBusPath    :: !(Maybe Text)
  } deriving (Show, Eq)

data BlockTransport = TransportUnknown deriving (Show, Eq)

getBlockDevices :: IO [BlockDevice]
getBlockDevices = return []

getSataDevices :: IO [Component]
getSataDevices = return []

getScsiDevices :: IO [Component]
getScsiDevices = return []

getAllStorageDevices :: IO [Component]
getAllStorageDevices = return []

getOpticalDrives :: IO [Component]
getOpticalDrives = return []
#endif
