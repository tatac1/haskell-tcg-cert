{-# LANGUAGE OverloadedStrings #-}

-- |
-- Main entry point for tcg-platform-cert-util
-- 
-- This utility provides command-line tools for generating, validating, and inspecting
-- TCG Platform Certificates according to the TCG Platform Certificate Profile specification.
--
-- Commands:
-- - generate: Generate new platform certificates
-- - generate-delta: Generate delta certificates for platform updates
-- - show: Display certificate information
-- - validate: Validate certificate compliance
-- - components: Extract component information
-- - create-config: Create example YAML configuration
-- - convert: Convert paccor JSON to YAML format

module Main where

import System.Environment (getArgs)
import System.Exit (exitFailure)

-- Module imports
import Data.X509.TCG.Util.CLI

-- | Command implementations
generateMain :: [String] -> IO ()
generateMain = getoptMain optionsGenerate $ \o n -> doGenerate o n

generateDeltaMain :: [String] -> IO ()
generateDeltaMain = getoptMain optionsGenerateDelta $ \o n -> doGenerateDelta o n

showMain :: [String] -> IO ()
showMain = getoptMain optionsShow $ \o n -> doShow o n

validateMain :: [String] -> IO ()
validateMain = getoptMain optionsValidate $ \o n -> doValidate o n

componentsMain :: [String] -> IO ()
componentsMain = getoptMain optionsComponents $ \o n -> doComponents o n

createConfigMain :: [String] -> IO ()
createConfigMain [] = createExampleConfig "platform-config.yaml"
createConfigMain [filename] = createExampleConfig filename
createConfigMain _ = do
  putStrLn "Usage: tcg-platform-cert-util create-config [filename]"
  putStrLn "  filename: Output YAML file (default: platform-config.yaml)"
  exitFailure

convertMain :: [String] -> IO ()
convertMain = getoptMain optionsConvert $ \o n -> doConvert o n

-- | Main entry point
main :: IO ()
main = do
  args <- getArgs
  case args of
    [] -> usage
    "generate" : as -> generateMain as
    "generate-delta" : as -> generateDeltaMain as
    "show" : as -> showMain as
    "validate" : as -> validateMain as
    "components" : as -> componentsMain as
    "create-config" : as -> createConfigMain as
    "convert" : as -> convertMain as
    "help" : _ -> usage
    "--help" : _ -> usage
    _ -> do
      putStrLn $ "Unknown command: " ++ unwords args
      usage
      exitFailure