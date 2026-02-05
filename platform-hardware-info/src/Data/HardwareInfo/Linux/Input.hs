{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Data.HardwareInfo.Linux.Input
-- Description : Linux input device enumeration
-- Copyright   : (c) Toru Tomita, 2024
-- License     : BSD3
--
-- This module provides functions to enumerate input devices on Linux
-- systems using the sysfs interface (/sys/class/input/).

#ifdef LINUX
module Data.HardwareInfo.Linux.Input
  ( -- * Input device enumeration
    getInputDevices
  , InputDevice(..)
  , InputDeviceType(..)
  ) where

import Control.Exception (try, SomeException)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Directory (doesDirectoryExist, listDirectory, doesFileExist)
import System.FilePath ((</>), takeFileName)
import System.Posix.Files (readSymbolicLink)
import Data.List (isInfixOf)

import Data.HardwareInfo.Types

-- | Input device type classification
data InputDeviceType
  = InputKeyboard
  | InputMouse
  | InputTouchpad
  | InputTouchscreen
  | InputTablet
  | InputJoystick
  | InputOther
  deriving (Show, Eq)

-- | Input device information
data InputDevice = InputDevice
  { inputName       :: !Text           -- ^ Device name
  , inputType       :: !InputDeviceType -- ^ Device type
  , inputPhys       :: !(Maybe Text)   -- ^ Physical path
  , inputUniq       :: !(Maybe Text)   -- ^ Unique identifier
  , inputVendor     :: !(Maybe Text)   -- ^ Vendor ID
  , inputProduct    :: !(Maybe Text)   -- ^ Product ID
  , inputBusType    :: !(Maybe Text)   -- ^ Bus type (USB, PS/2, etc.)
  , inputUsbAddress :: !(Maybe Text)   -- ^ USB address if USB device
  } deriving (Show, Eq)

-- | Sysfs input path
inputPath :: FilePath
inputPath = "/sys/class/input"

-- | Get all input devices
getInputDevices :: IO [Component]
getInputDevices = do
  exists <- doesDirectoryExist inputPath
  if not exists
    then return []
    else do
      result <- try $ listDirectory inputPath
      case result of
        Left (_ :: SomeException) -> return []
        Right entries -> do
          -- Filter to event* devices (these have the detailed info)
          let eventDevs = filter ("event" `T.isPrefixOf`) $ map T.pack entries
          devices <- mapM readInputDevice eventDevs
          -- Filter out virtual/duplicate devices and convert to components
          let physicalDevs = filter isPhysicalDevice [d | Just d <- devices]
          return $ map toComponent physicalDevs

-- | Read input device information from sysfs
readInputDevice :: Text -> IO (Maybe InputDevice)
readInputDevice eventName = do
  let devPath = inputPath </> T.unpack eventName </> "device"

  -- Check if device directory exists
  exists <- doesDirectoryExist devPath
  if not exists
    then return Nothing
    else do
      -- Read device name
      name <- readSysfsFile (devPath </> "name")
      case name of
        Nothing -> return Nothing
        Just devName -> do
          -- Read other attributes
          phys <- readSysfsFile (devPath </> "phys")
          uniq <- readSysfsFile (devPath </> "uniq")

          -- Read ID information
          vendorId <- readSysfsFile (devPath </> "id" </> "vendor")
          productId <- readSysfsFile (devPath </> "id" </> "product")
          busType <- readSysfsFile (devPath </> "id" </> "bustype")

          -- Determine device type from capabilities or name
          devType <- determineInputType devPath devName

          -- Get USB address if applicable
          usbAddr <- getInputUsbAddress devPath

          return $ Just InputDevice
            { inputName = devName
            , inputType = devType
            , inputPhys = phys
            , inputUniq = uniq
            , inputVendor = vendorId
            , inputProduct = productId
            , inputBusType = busType
            , inputUsbAddress = usbAddr
            }

-- | Determine input device type from capabilities and name
determineInputType :: FilePath -> Text -> IO InputDeviceType
determineInputType devPath name = do
  -- Read capabilities
  capsKey <- readSysfsFile (devPath </> "capabilities" </> "key")
  capsAbs <- readSysfsFile (devPath </> "capabilities" </> "abs")
  capsRel <- readSysfsFile (devPath </> "capabilities" </> "rel")

  let nameLower = T.toLower name

  -- Heuristics based on name and capabilities
  return $ case () of
    _ | "keyboard" `T.isInfixOf` nameLower -> InputKeyboard
      | "touchpad" `T.isInfixOf` nameLower -> InputTouchpad
      | "trackpad" `T.isInfixOf` nameLower -> InputTouchpad
      | "touchscreen" `T.isInfixOf` nameLower -> InputTouchscreen
      | "tablet" `T.isInfixOf` nameLower -> InputTablet
      | "wacom" `T.isInfixOf` nameLower -> InputTablet
      | "joystick" `T.isInfixOf` nameLower -> InputJoystick
      | "gamepad" `T.isInfixOf` nameLower -> InputJoystick
      | "mouse" `T.isInfixOf` nameLower -> InputMouse
      | "pointing" `T.isInfixOf` nameLower -> InputMouse
      -- Check capabilities for mice (has REL_X, REL_Y)
      | hasRelativeAxes capsRel -> InputMouse
      -- Check for touchpad/touchscreen (has ABS_X, ABS_Y, ABS_MT_*)
      | hasAbsoluteAxes capsAbs && hasTouchCapability capsAbs -> InputTouchpad
      -- Has keyboard keys
      | hasKeyboardKeys capsKey -> InputKeyboard
      | otherwise -> InputOther

-- | Check if device has relative axes (mouse)
hasRelativeAxes :: Maybe Text -> Bool
hasRelativeAxes Nothing = False
hasRelativeAxes (Just caps) = caps /= "0" && not (T.null $ T.strip caps)

-- | Check if device has absolute axes
hasAbsoluteAxes :: Maybe Text -> Bool
hasAbsoluteAxes Nothing = False
hasAbsoluteAxes (Just caps) = caps /= "0" && not (T.null $ T.strip caps)

-- | Check for touch capability (simplified)
hasTouchCapability :: Maybe Text -> Bool
hasTouchCapability Nothing = False
hasTouchCapability (Just caps) =
  -- Multi-touch devices have significant ABS capabilities
  T.length (T.filter (/= '0') caps) > 4

-- | Check if device has keyboard keys
hasKeyboardKeys :: Maybe Text -> Bool
hasKeyboardKeys Nothing = False
hasKeyboardKeys (Just caps) =
  -- Keyboards have many key capabilities
  T.length (T.filter (/= '0') $ T.filter (/= ' ') caps) > 8

-- | Get USB address for input device
getInputUsbAddress :: FilePath -> IO (Maybe Text)
getInputUsbAddress devPath = do
  -- Follow symlinks to find USB device
  result <- try $ readSymbolicLink devPath
  case result of
    Left (_ :: SomeException) -> return Nothing
    Right target ->
      -- Look for USB path pattern like "usb1/1-2/1-2:1.0"
      if "usb" `isInfixOf` target
        then extractUsbAddress target
        else return Nothing
  where
    extractUsbAddress :: String -> IO (Maybe Text)
    extractUsbAddress path =
      -- Extract USB bus-port pattern
      let parts = filter (not . null) $ splitOn '/' path
          usbParts = dropWhile (not . isUsbPort) parts
      in case usbParts of
           (port:_) -> return $ Just $ T.pack port
           _ -> return Nothing

    isUsbPort :: String -> Bool
    isUsbPort s = case s of
      (d:'-':rest) -> d `elem` ['0'..'9'] && any (`elem` ("0123456789.:-" :: String)) rest
      _ -> False

    splitOn :: Char -> String -> [String]
    splitOn c s = case break (== c) s of
      (a, [])   -> [a]
      (a, _:bs) -> a : splitOn c bs

-- | Check if input device is physical (not virtual)
isPhysicalDevice :: InputDevice -> Bool
isPhysicalDevice dev =
  -- Filter out power buttons, PC speakers, virtual devices
  let name = T.toLower $ inputName dev
  in not $ any (`T.isInfixOf` name)
       [ "power button"
       , "sleep button"
       , "lid switch"
       , "pc speaker"
       , "video bus"
       , "virtual"
       , "dummy"
       ]

-- | Read a sysfs file safely
readSysfsFile :: FilePath -> IO (Maybe Text)
readSysfsFile path = do
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

-- | Convert InputDevice to Component
toComponent :: InputDevice -> Component
toComponent dev = Component
  { componentClass = inputTypeToClass (inputType dev)
  , componentManufacturer = lookupInputVendor (inputVendor dev)
  , componentModel = inputName dev
  , componentSerial = inputUniq dev
  , componentRevision = Nothing
  , componentFieldReplaceable = Just True
  , componentAddresses = buildAddresses dev
  }
  where
    buildAddresses :: InputDevice -> [ComponentAddress]
    buildAddresses d = case inputUsbAddress d of
      Just addr -> [USBAddress addr]
      Nothing -> []

-- | Convert input type to TCG component class
inputTypeToClass :: InputDeviceType -> ComponentClass
inputTypeToClass InputKeyboard = ClassGeneralInput
inputTypeToClass InputMouse = ClassGeneralInput
inputTypeToClass InputTouchpad = ClassGeneralInput
inputTypeToClass InputTouchscreen = ClassGeneralInput
inputTypeToClass InputTablet = ClassGeneralInput
inputTypeToClass InputJoystick = ClassGeneralInput
inputTypeToClass InputOther = ClassGeneralInput

-- | Lookup vendor name from vendor ID
lookupInputVendor :: Maybe Text -> Text
lookupInputVendor Nothing = ""
lookupInputVendor (Just vid) =
  case T.toLower vid of
    "0001" -> "AT Translated Set 2"  -- PS/2 keyboard
    "0002" -> "Serial"
    "0003" -> "USB"
    "0005" -> "Bluetooth"
    "0011" -> "I2C"
    "046d" -> "Logitech"
    "045e" -> "Microsoft"
    "413c" -> "Dell"
    "04f2" -> "Chicony"
    "17ef" -> "Lenovo"
    "06cb" -> "Synaptics"
    "2808" -> "ELAN"
    "04b4" -> "Cypress"
    "056a" -> "Wacom"
    "1532" -> "Razer"
    "1b1c" -> "Corsair"
    "258a" -> "SINO WEALTH"
    _ -> vid

#else
-- Non-Linux stub
module Data.HardwareInfo.Linux.Input
  ( getInputDevices
  , InputDevice(..)
  , InputDeviceType(..)
  ) where

import Data.Text (Text)
import Data.HardwareInfo.Types

data InputDeviceType = InputOther deriving (Show, Eq)

data InputDevice = InputDevice
  { inputName       :: !Text
  , inputType       :: !InputDeviceType
  , inputPhys       :: !(Maybe Text)
  , inputUniq       :: !(Maybe Text)
  , inputVendor     :: !(Maybe Text)
  , inputProduct    :: !(Maybe Text)
  , inputBusType    :: !(Maybe Text)
  , inputUsbAddress :: !(Maybe Text)
  } deriving (Show, Eq)

getInputDevices :: IO [Component]
getInputDevices = return []
#endif
