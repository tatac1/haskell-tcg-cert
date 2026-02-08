{-# LANGUAGE DisambiguateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Data.X509.TCG.Util.CLI
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Utility
-- Stability   : experimental
-- Portability : unknown
--
-- Command line interface processing for TCG Platform Certificate utility.
-- This module provides option parsing, command dispatch, and high-level command implementations.
module Data.X509.TCG.Util.CLI
  ( -- * CLI Types
    TCGOpts (..),

    -- * Command Implementations
    doGenerate,
    doGenerateDelta,
    doShow,
    doValidate,
    doComponents,
    doConvert,
    doCompliance,
    doLint,
    doHwinfo,
    doCreateConfig,
    createExampleConfig,

    -- * Option Parsers
    optionsGenerate,
    optionsGenerateDelta,
    optionsShow,
    optionsValidate,
    optionsComponents,
    optionsConvert,
    optionsCompliance,
    optionsLint,
    optionsHwinfo,
    optionsCreateConfig,

    -- * Utility Functions
    extractOpt,
    getoptMain,
    usage,
  )
where

import Control.Monad (forM_, when)
import Data.Aeson (Value(..), encode, object, (.=))
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as LBS
import Data.Hourglass (Date (..), DateTime (..), TimeOfDay (..))
import qualified Data.Hourglass as HG
import Data.Maybe (fromMaybe, listToMaybe, mapMaybe)
import Text.Read (readMaybe)
import qualified Data.Text as T
import Data.PEM (PEM (..), pemContent, pemParseBS, pemWriteBS)
import Data.Time.Clock (getCurrentTime)
import Data.X509 (AltName(..), DistinguishedName, Extensions(..), decodeSignedCertificate, getCertificate)
import Data.X509.AttCert (AttCertIssuer(..), IssuerSerial(IssuerSerial), V2Form(..))
import Data.X509.TCG
import Data.X509.TCG.Compliance
-- Local imports
import Data.X509.TCG.Util.ASN1
import Data.X509.TCG.Util.Certificate
import Data.X509.TCG.Util.Config
import Data.X509.TCG.Util.ConfigLint
import Data.X509.TCG.Util.Display
import Data.X509.TCG.Util.PreIssuance (preIssuanceLintOnly, shouldBlockLint)
import Data.X509.TCG.Util.JsonReport
import Data.X509.TCG.Util.Paccor
import qualified Data.X509.TCG.Util.HardwareCollector as HC
import qualified Data.Yaml as Yaml
import System.Console.GetOpt
import System.Directory (doesFileExist)
import System.Exit
import System.FilePath (takeDirectory, (</>))

-- | Command line options
data TCGOpts
  = Help
  | Verbose
  | Output String
  | KeySize Int
  | ValidityDays Int
  | Manufacturer String
  | Model String
  | Version String
  | Serial String
  | CAPrivateKey String
  | CACertificate String
  | -- Delta certificate options
    BaseCertificate String
  | BaseSerial String
  | ComponentChanges String
  | -- EK certificate option
    TPMEKCertificate String
  | ConfigFile String
  | -- Hash algorithm option
    HashAlgorithm String
  | -- Convert options
    FromPaccor
  | -- Compliance mode option
    Compat
  | StrictV11Mode
  | InputFile String
  | -- Pre-issuance compliance options
    SkipCompliance
  | JsonOutput
  | ChainMode
  | Detect
  | ExtensionsFile String
  | PolicyRefFile String
  | CertSerialNumber String
  | NotBefore String
  | NotAfter String
  deriving (Show, Eq)

-- | Generate a new platform certificate
doGenerate :: [TCGOpts] -> [String] -> IO ()
doGenerate opts _ = do
  when (Help `elem` opts) $ do
    putStrLn $ usageInfo "usage: tcg-platform-cert-util generate [options]" optionsGenerate
    exitSuccess

  let jsonMode' = JsonOutput `elem` opts
  when (not jsonMode') $ putStrLn "Generating platform certificate..."

  -- Check for config file option first
  let configFile = extractOpt "config" (\case ConfigFile f -> Just f; _ -> Nothing) opts ""

  -- Load configuration from config file (YAML or paccor JSON) or command line options
  (manufacturer, model, version, serial, _keySize, _validityDays, components, mExtAttrs, mYamlConfig) <-
    if null configFile
      then do
        -- Use command line options
        let manufacturer = extractOpt "manufacturer" (\case Manufacturer m -> Just m; _ -> Nothing) opts "Unknown"
            model = extractOpt "model" (\case Model m -> Just m; _ -> Nothing) opts "Unknown"
            version = extractOpt "version" (\case Version v -> Just v; _ -> Nothing) opts "1.0"
            serial = extractOpt "serial" (\case Serial s -> Just s; _ -> Nothing) opts "0001"
            keySize = extractOpt "key-size" (\case KeySize k -> Just (show k); _ -> Nothing) opts "2048"
            validityDays = extractOpt "validity" (\case ValidityDays d -> Just (show d); _ -> Nothing) opts "365"
        return (manufacturer, model, version, serial, keySize, validityDays, [], Nothing, Nothing)
      else do
        -- Load from config file (auto-detect YAML or paccor JSON format)
        when (not jsonMode') $ putStrLn $ "Loading configuration from: " ++ configFile
        result <- loadAnyConfig configFile
        case result of
          Left err -> do
            putStrLn $ "Error loading config file: " ++ err
            exitFailure
          Right config0 -> do
            -- Auto-detect and merge PolicyReference.json if available
            let configDir = takeDirectory configFile
                policyFileOpt = extractOpt "policy-ref" (\case PolicyRefFile f -> Just f; _ -> Nothing) opts ""
                extFileOpt = extractOpt "extensions" (\case ExtensionsFile f -> Just f; _ -> Nothing) opts ""
                policyFile = if null policyFileOpt then configDir </> "PolicyReference.json" else policyFileOpt
                extFile = if null extFileOpt then configDir </> "Extensions.json" else extFileOpt

            -- Merge PolicyReference if the file exists
            policyExists <- doesFileExist policyFile
            config <- if policyExists
              then do
                prResult <- loadPaccorPolicyReference policyFile
                case prResult of
                  Left err -> do
                    when (not jsonMode') $ putStrLn $ "  Warning: Could not parse PolicyReference: " ++ err
                    return config0
                  Right pr -> do
                    when (not jsonMode') $ putStrLn $ "  Merged PolicyReference from: " ++ policyFile
                    return $ mergePolicyReference pr config0
              else return config0

            -- Load Extensions if the file exists
            extExists <- doesFileExist extFile
            mExtensions <- if extExists
              then do
                extResult <- loadPaccorExtensions extFile
                case extResult of
                  Left err -> do
                    when (not jsonMode') $ putStrLn $ "  Warning: Could not parse Extensions: " ++ err
                    return Nothing
                  Right ext -> do
                    when (not jsonMode') $ putStrLn $ "  Loaded Extensions from: " ++ extFile
                    return $ Just (paccorExtensionsToX509 ext)
              else return Nothing

            let keySize = show $ fromMaybe 2048 (pccKeySize config)
                validityDays = show $ fromMaybe 365 (pccValidityDays config)
                -- Extract extended TCG attributes from config, with extensions
                extAttrs0 = configToExtendedAttrs config
                -- Build SAN extension from platform config attributes
                sanExt = buildSanExtension config
                -- Combine SAN with any paccor-loaded extensions
                baseExts = case mExtensions of
                  Just (Extensions (Just exts)) -> exts
                  _ -> []
                allExts = Extensions (Just (baseExts ++ [sanExt]))
                -- Apply CLI overrides for serial number and validity period
                mSerialNum = listToMaybe [read s | CertSerialNumber s <- opts]
                mNotBefore = listToMaybe [s | NotBefore s <- opts] >>= parseDateYYYYMMDD
                mNotAfter  = listToMaybe [s | NotAfter s <- opts] >>= parseDateYYYYMMDD
                extAttrs = extAttrs0
                  { etaExtensions = Just allExts
                  , etaSerialNumber = mSerialNum
                  , etaNotBefore = mNotBefore
                  , etaNotAfter = mNotAfter
                  }
            when (not jsonMode') $ putStrLn "  Extended TCG attributes loaded from config file"
            return
              ( pccManufacturer config,
                pccModel config,
                pccVersion config,
                pccSerial config,
                keySize,
                validityDays,
                pccComponents config,
                Just extAttrs,
                Just config
              )

  -- Extract remaining options
  let outputFile = extractOpt "output" (\case Output o -> Just o; _ -> Nothing) opts "platform-cert.pem"
      caKeyFile = extractOpt "ca-key" (\case CAPrivateKey k -> Just k; _ -> Nothing) opts ""
      caCertFile = extractOpt "ca-cert" (\case CACertificate c -> Just c; _ -> Nothing) opts ""
      ekCertFile = extractOpt "ek-cert" (\case TPMEKCertificate e -> Just e; _ -> Nothing) opts ""
      hashAlg = extractOpt "hash" (\case HashAlgorithm h -> Just h; _ -> Nothing) opts "sha384"

  let tpmInfo = createDefaultTPMInfo

  -- Check if CA key, certificate, and EK certificate are provided (now required)
  if null caKeyFile || null caCertFile || null ekCertFile
    then do
      putStrLn "Error: CA private key, CA certificate, and TPM EK certificate are required for certificate generation"
      putStrLn "Please provide --ca-key, --ca-cert, and --ek-cert options"
      putStrLn ""
      putStrLn "Usage:"
      putStrLn "  tcg-platform-cert-util generate --manufacturer \"Company\" --model \"Model\" --version \"1.0\" --serial \"001\" --ca-key ca-key.pem --ca-cert ca-cert.pem --ek-cert ek-cert.pem --output cert.pem"
      exitFailure
    else do
      when (not jsonMode') $ do
        putStrLn $ "Loading CA private key from: " ++ caKeyFile
        putStrLn $ "Loading CA certificate from: " ++ caCertFile
        putStrLn $ "Loading TPM EK certificate from: " ++ ekCertFile

      -- Load CA key, CA certificate, and EK certificate
      keyResult <- loadPrivateKey caKeyFile
      certResult <- loadCACertificate caCertFile
      ekCertResult <- loadCACertificate ekCertFile -- Reuse the same function for loading EK cert
      case (keyResult, certResult, ekCertResult) of
        (Right caPrivKey, Right caCert, Right ekCert) -> do
          when (not jsonMode') $ do
            putStrLn "CA credentials and TPM EK certificate loaded successfully"
            when (not $ null components) $ do
              putStrLn $ "Including " ++ show (length components) ++ " component(s) from configuration:"
              forM_ components $ \comp -> do
                putStrLn $ "  - " ++ ccManufacturer comp ++ " " ++ ccModel comp ++ " (Class: " ++ ccClass comp ++ ")"

          -- Create config structure with components from YAML or empty list
          let componentIdentifiers = map yamlComponentToComponentIdentifier components
              platformConfig =
                PlatformConfiguration
                  { pcManufacturer = BC.pack manufacturer,
                    pcModel = BC.pack model,
                    pcVersion = BC.pack version,
                    pcSerial = BC.pack serial,
                    pcComponents = componentIdentifiers
                  }

          -- Pre-issuance Layer 1: Config lint
          let skipCompliance = SkipCompliance `elem` opts
              compMode = if StrictV11Mode `elem` opts then StrictV11 else OperationalCompatibility
              jsonMode = JsonOutput `elem` opts

          when (Compat `elem` opts && StrictV11Mode `elem` opts) $ do
            putStrLn "Error: --compat and --strict-v11 cannot be used together."
            exitFailure

          case mYamlConfig of
            Just yamlConfig | not skipCompliance -> do
              when (not jsonMode') $ do
                putStrLn ""
                putStrLn "Running pre-issuance config lint..."
              let lintResults = preIssuanceLintOnly yamlConfig
              when (shouldBlockLint compMode lintResults) $ do
                putStrLn ""
                putStrLn "Pre-issuance config lint FAILED:"
                displayLintResults lintResults
                exitFailure
              let passCount = length [r | r <- lintResults, clrStatus r == LintPass]
                  warnCount = length [r | r <- lintResults, clrStatus r == LintWarn]
              when (not jsonMode') $ putStrLn $ "  Config lint: " ++ show passCount ++ " passed, " ++ show warnCount ++ " warnings"
            _ -> return ()

          -- Pre-generation validation (hash and key compatibility only; other checks covered by Layer 1/2)
          when (not jsonMode) $ do
            putStrLn ""
            putStrLn " Performing pre-generation validation..."

          hashValidation <- validateHashAlgorithm hashAlg
          case hashValidation of
            Left err -> do { putStrLn err; exitFailure }
            Right _ -> return ()

          keyValidation <- validatePrivateKeyCompatibility caPrivKey hashAlg
          case keyValidation of
            Left err -> do { putStrLn err; exitFailure }
            Right _ -> return ()

          when (not jsonMode) $ do
            putStrLn ""
            putStrLn " Pre-generation validation passed."
            putStrLn " Generating certificate with real signature and proper EK certificate binding..."

          -- Generate certificate
          -- Add AKI extension from CA cert's SKI (CHN-001)
          let mExtAttrsWithAki = case mExtAttrs of
                Just ea -> case etaExtensions ea of
                  Just (Extensions (Just exts)) ->
                    let akiExts = case buildAkiExtension caCert of
                          Just aki -> [aki] ++ exts  -- AKI first
                          Nothing  -> exts
                    in Just ea { etaExtensions = Just (Extensions (Just akiExts)) }
                  _ -> case buildAkiExtension caCert of
                    Just aki -> Just ea { etaExtensions = Just (Extensions (Just [aki])) }
                    Nothing  -> Just ea
                Nothing -> Nothing

          when (not jsonMode') $ putStrLn $ "Using hash algorithm: " ++ hashAlg
          result <- case mExtAttrsWithAki of
            Just extAttrs -> do
              when (not jsonMode') $ putStrLn "  Using extended TCG attributes for IWG v1.1 compliance"
              createSignedPlatformCertificateExt platformConfig componentIdentifiers tpmInfo caPrivKey caCert ekCert hashAlg extAttrs
            Nothing -> do
              when (not jsonMode') $ putStrLn "  Using default TCG attributes"
              createSignedPlatformCertificate platformConfig componentIdentifiers tpmInfo caPrivKey caCert ekCert hashAlg
          case result of
            Left err -> do
              putStrLn $ "Certificate generation failed: " ++ err
              exitFailure
            Right cert -> do
              when (not jsonMode') $ putStrLn "Certificate generated successfully"

              -- Post-generation verification
              verificationResult <- verifyGeneratedCertificate cert platformConfig componentIdentifiers
              case verificationResult of
                Left err -> do
                  putStrLn err
                  putStrLn "  Certificate generation completed but verification failed"
                  exitFailure
                Right _ -> return ()

              -- Pre-issuance Layer 2: Post-generation compliance check
              when (not skipCompliance) $ do
                when (not jsonMode') $ do
                  putStrLn ""
                  putStrLn "Running post-generation compliance check..."
                let compOpts = defaultComplianceOptions
                      { coMode = compMode
                      , coVerbose = Verbose `elem` opts
                      }
                compResult <- runComplianceTest cert compOpts
                when (not (resCompliant compResult)) $ do
                  putStrLn "Post-generation compliance check FAILED."
                  putStrLn $ "  " ++ show (resTotalFailedRequired compResult) ++ " required checks failed"
                  exitFailure
                when (not jsonMode') $ putStrLn "  Post-generation compliance check PASSED."

              -- Write certificate
              let derBytes = encodeSignedPlatformCertificate cert
                  pem =
                    PEM
                      { pemName = "ATTRIBUTE CERTIFICATE",
                        pemHeader = [],
                        pemContent = derBytes
                      }
              writePEMFile outputFile [pem]
              if jsonMode'
                then do
                  now <- getCurrentTime
                  let lintResults' = case mYamlConfig of
                        Just yamlConfig | not skipCompliance -> preIssuanceLintOnly yamlConfig
                        _ -> []
                      mCompValue = Nothing  -- compliance result already checked above
                      report = buildGenerateReport compMode lintResults' mCompValue (Just outputFile) True now
                  BC.putStrLn $ LBS.toStrict $ renderJsonReport report
                else putStrLn $ "Certificate written to: " ++ outputFile
        (Left keyErr, _, _) -> do
          putStrLn $ "Error loading CA private key: " ++ keyErr
          exitFailure
        (_, Left certErr, _) -> do
          putStrLn $ "Error loading CA certificate: " ++ certErr
          exitFailure
        (_, _, Left ekCertErr) -> do
          putStrLn $ "Error loading TPM EK certificate: " ++ ekCertErr
          exitFailure

-- | Generate a new delta platform certificate
doGenerateDelta :: [TCGOpts] -> [String] -> IO ()
doGenerateDelta opts _ = do
  when (Help `elem` opts) $ do
    putStrLn $ usageInfo "usage: tcg-platform-cert-util generate-delta [options]" optionsGenerateDelta
    exitSuccess

  putStrLn "Generating delta platform certificate..."

  let configFile = extractOpt "config" (\case ConfigFile f -> Just f; _ -> Nothing) opts ""
      baseCertFile = extractOpt "base-cert" (\case BaseCertificate f -> Just f; _ -> Nothing) opts ""
      outputFile = extractOpt "output" (\case Output o -> Just o; _ -> Nothing) opts "delta-cert.pem"
      caKeyFile = extractOpt "ca-key" (\case CAPrivateKey k -> Just k; _ -> Nothing) opts ""
      caCertFile = extractOpt "ca-cert" (\case CACertificate c -> Just c; _ -> Nothing) opts ""
      hashAlg = extractOpt "hash" (\case HashAlgorithm h -> Just h; _ -> Nothing) opts "sha384"
      extFileOpt = extractOpt "extensions" (\case ExtensionsFile f -> Just f; _ -> Nothing) opts ""

  when (null baseCertFile) $ do
    putStrLn "Error: Base platform certificate is required for delta certificate generation"
    putStrLn "Please provide --base-cert option"
    exitFailure

  when (null configFile) $ do
    putStrLn "Error: Delta configuration file is required"
    putStrLn "Please provide --config option"
    exitFailure

  when (null caKeyFile || null caCertFile) $ do
    putStrLn "Error: CA private key and certificate are required for delta certificate generation"
    putStrLn "Please provide both --ca-key and --ca-cert options"
    exitFailure

  putStrLn $ "Loading base platform certificate from: " ++ baseCertFile
  putStrLn $ "Loading delta configuration from: " ++ configFile
  putStrLn $ "Loading CA private key from: " ++ caKeyFile
  putStrLn $ "Loading CA certificate from: " ++ caCertFile

  keyResult <- loadPrivateKey caKeyFile
  certResult <- loadCACertificate caCertFile
  baseCertResult <- loadBasePlatformCertificate baseCertFile
  configResult <- loadAnyDeltaConfig configFile

  case (keyResult, certResult, baseCertResult, configResult) of
    (Right caPrivKey, Right caCert, Right baseCert, Right deltaConfig) -> do
      -- Build SAN + optional Extensions.json + AKI extension
      let configDir = takeDirectory configFile
          extFile = if null extFileOpt then configDir </> "Extensions.json" else extFileOpt

      extExists <- doesFileExist extFile
      mExtensions <- if extExists
        then do
          extResult <- loadPaccorExtensions extFile
          case extResult of
            Left err -> do
              putStrLn $ "  Warning: Could not parse Extensions: " ++ err
              return Nothing
            Right ext -> do
              putStrLn $ "  Loaded Extensions from: " ++ extFile
              return $ Just (paccorExtensionsToX509 ext)
        else return Nothing

      case deltaConfigToExtendedAttrs deltaConfig of
        Left err -> do
          putStrLn $ "Error in delta configuration: " ++ err
          exitFailure
        Right extAttrs0 -> do
          holderRef <- case mkHolderReferenceFromBase baseCert of
            Left err -> do
              putStrLn $ "Error deriving Holder reference from base certificate: " ++ err
              exitFailure
            Right ref -> return ref

          let sanExt = buildSanExtension (deltaConfigToPlatformConfig deltaConfig)
              baseExts = case mExtensions of
                Just (Extensions (Just exts)) -> exts
                _ -> []
              extsWithSan = baseExts ++ [sanExt]  -- SAN last
              extsWithAki = case buildAkiExtension caCert of
                Just aki -> [aki] ++ extsWithSan  -- AKI first
                Nothing -> extsWithSan
              -- Apply CLI overrides for serial number and validity period
              mSerialNum = listToMaybe [read s | CertSerialNumber s <- opts]
              mNotBefore = listToMaybe [s | NotBefore s <- opts] >>= parseDateYYYYMMDD
              mNotAfter  = listToMaybe [s | NotAfter s <- opts] >>= parseDateYYYYMMDD
              extAttrs =
                extAttrs0
                  { etaHolderBaseCertificateID = Just holderRef,
                    etaExtensions = Just (Extensions (Just extsWithAki)),
                    etaSerialNumber = mSerialNum,
                    etaNotBefore = mNotBefore,
                    etaNotAfter = mNotAfter
                  }
              platformConfig = PlatformConfiguration
                { pcManufacturer = BC.pack (dccManufacturer deltaConfig),
                  pcModel = BC.pack (dccModel deltaConfig),
                  pcVersion = BC.pack (dccVersion deltaConfig),
                  pcSerial = BC.pack (dccSerial deltaConfig),
                  pcComponents = map yamlComponentToComponentIdentifier (dccComponents deltaConfig)
                }
              componentIdentifiers = map yamlComponentToComponentIdentifier (dccComponents deltaConfig)
              tpmInfo = createDefaultTPMInfo

          putStrLn $ "Base certificate serial: " ++ show (pciSerialNumber $ getPlatformCertificate baseCert)
          putStrLn $ "Including " ++ show (length componentIdentifiers) ++ " component change(s)"
          putStrLn $ "Using hash algorithm: " ++ hashAlg

          -- For Delta generation, Holder is overridden via etaHolderBaseCertificateID.
          -- The EK cert argument is not used in that path, so pass CA cert as placeholder.
          certGenResult <- createSignedPlatformCertificateExt
            platformConfig
            componentIdentifiers
            tpmInfo
            caPrivKey
            caCert
            caCert
            hashAlg
            extAttrs

          case certGenResult of
            Left err -> do
              putStrLn $ "Delta certificate generation failed: " ++ err
              exitFailure
            Right cert -> do
              let derBytes = encodeSignedPlatformCertificate cert
                  pem =
                    PEM
                      { pemName = "ATTRIBUTE CERTIFICATE",
                        pemHeader = [],
                        pemContent = derBytes
                      }
              writePEMFile outputFile [pem]
              putStrLn $ "Delta certificate written to: " ++ outputFile
    (Left keyErr, _, _, _) -> do
      putStrLn $ "Error loading CA private key: " ++ keyErr
      exitFailure
    (_, Left certErr, _, _) -> do
      putStrLn $ "Error loading CA certificate: " ++ certErr
      exitFailure
    (_, _, Left baseErr, _) -> do
      putStrLn $ "Error loading base platform certificate: " ++ baseErr
      exitFailure
    (_, _, _, Left cfgErr) -> do
      putStrLn $ "Error loading delta config file: " ++ cfgErr
      exitFailure
  where
    deltaConfigToPlatformConfig :: DeltaCertConfig -> PlatformCertConfig
    deltaConfigToPlatformConfig dcc =
      PlatformCertConfig
        { pccManufacturer = dccManufacturer dcc,
          pccModel = dccModel dcc,
          pccVersion = dccVersion dcc,
          pccSerial = dccSerial dcc,
          pccManufacturerId = Nothing,
          pccValidityDays = dccValidityDays dcc,
          pccKeySize = dccKeySize dcc,
          pccComponents = dccComponents dcc,
          pccProperties = Nothing,
          pccPlatformConfigUri = dccPlatformConfigUri dcc,
          pccComponentsUri = Nothing,
          pccPropertiesUri = Nothing,
          pccPlatformClass = dccPlatformClass dcc,
          pccSpecificationVersion = dccSpecificationVersion dcc,
          pccMajorVersion = dccMajorVersion dcc,
          pccMinorVersion = dccMinorVersion dcc,
          pccPatchVersion = dccPatchVersion dcc,
          pccPlatformQualifier = dccPlatformQualifier dcc,
          pccCredentialSpecMajor = Nothing,
          pccCredentialSpecMinor = Nothing,
          pccCredentialSpecRevision = Nothing,
          pccPlatformSpecMajor = Nothing,
          pccPlatformSpecMinor = Nothing,
          pccPlatformSpecRevision = Nothing,
          pccSecurityAssertions = Nothing
        }

    platformToDeltaConfig :: PlatformCertConfig -> DeltaCertConfig
    platformToDeltaConfig cfg =
      DeltaCertConfig
        { dccManufacturer = pccManufacturer cfg
        , dccModel = pccModel cfg
        , dccVersion = pccVersion cfg
        , dccSerial = pccSerial cfg
        , dccValidityDays = pccValidityDays cfg
        , dccKeySize = pccKeySize cfg
        , dccComponents = pccComponents cfg
        , dccPlatformConfigUri = pccPlatformConfigUri cfg
        , dccPlatformClass = pccPlatformClass cfg
        , dccSpecificationVersion = pccSpecificationVersion cfg
        , dccMajorVersion = pccMajorVersion cfg
        , dccMinorVersion = pccMinorVersion cfg
        , dccPatchVersion = pccPatchVersion cfg
        , dccPlatformQualifier = pccPlatformQualifier cfg
        , dccBaseCertificateSerial = Nothing
        , dccDeltaSequenceNumber = Nothing
        , dccChangeDescription = Nothing
        }

    loadAnyDeltaConfig :: FilePath -> IO (Either String DeltaCertConfig)
    loadAnyDeltaConfig fp = do
      deltaParsed <- loadDeltaConfig fp
      case deltaParsed of
        Right cfg -> return (Right cfg)
        Left deltaErr -> do
          anyParsed <- loadAnyConfig fp
          return $ case anyParsed of
            Right baseLikeCfg -> Right (platformToDeltaConfig baseLikeCfg)
            Left anyErr ->
              Left $
                "Could not parse delta config as Delta YAML or base-style YAML/JSON. "
                  ++ "Delta parse error: " ++ deltaErr
                  ++ " / Generic parse error: " ++ anyErr

    mkHolderReferenceFromBase :: SignedPlatformCertificate -> Either String IssuerSerial
    mkHolderReferenceFromBase baseCert =
      let baseInfo = getPlatformCertificate baseCert
          issuerDns = extractIssuerDns (pciIssuer baseInfo)
          serialNum = pciSerialNumber baseInfo
      in if null issuerDns
           then Left "base certificate issuer does not contain a directoryName"
           else Right $ IssuerSerial (map AltDirectoryName issuerDns) serialNum Nothing

    extractIssuerDns :: AttCertIssuer -> [DistinguishedName]
    extractIssuerDns (AttCertIssuerV1 gns) = extractDnsFromGeneralNames gns
    extractIssuerDns (AttCertIssuerV2 v2form) =
      case v2formBaseCertificateID v2form of
        Just (IssuerSerial gns _ _) -> extractDnsFromGeneralNames gns
        Nothing -> extractDnsFromGeneralNames (v2formIssuerName v2form)

    extractDnsFromGeneralNames :: [AltName] -> [DistinguishedName]
    extractDnsFromGeneralNames [] = []
    extractDnsFromGeneralNames (AltDirectoryName dn : rest) = dn : extractDnsFromGeneralNames rest
    extractDnsFromGeneralNames (_ : rest) = extractDnsFromGeneralNames rest

-- | Show certificate information
doShow :: [TCGOpts] -> [String] -> IO ()
doShow opts files = do
  when (Help `elem` opts) $ do
    putStrLn $ usageInfo "usage: tcg-platform-cert-util show [options] <certificate-file>" optionsShow
    exitSuccess

  when (null files) $ do
    putStrLn "Error: No certificate file specified"
    exitFailure

  let file = case files of
        (f : _) -> f
        [] -> error "No files provided"

  putStrLn $ "Reading certificate from: " ++ file

  -- Read and parse the PEM file
  -- TODO Too nested case - refactor
  result <- readPEMFile file
  case result of
    [] -> do
      putStrLn "Error: No certificates found in file"
      exitFailure
    (pem : _) -> do
      -- Try to decode as Platform Certificate
      case decodeSignedPlatformCertificate (pemContent pem) of
        Left err -> do
          putStrLn $ "Error: Failed to parse as Platform Certificate: " ++ err
          putStrLn ""
          putStrLn "Attempting to display certificate as raw ASN.1 structure:"
          putStrLn ""
          case decodeASN1' BER (pemContent pem) of
            Left asn1err -> do
              putStrLn $ "ASN.1 parsing also failed: " ++ show asn1err
              putStrLn ""
              putStrLn "Certificate raw information:"
              putStrLn $ "PEM Name: " ++ show (pemName pem)
              putStrLn $ "Content length: " ++ show (B.length (pemContent pem))
              putStrLn $ "Content (hex): " ++ hexdump (B.take 64 (pemContent pem)) ++ "..."
            Right asn1 -> do
              putStrLn "ASN.1 Structure:"
              showASN1 0 asn1
              putStrLn ""

              -- Try to extract basic information from ASN.1
              analyzeBasicCertificateInfo asn1

              putStrLn ""
              putStrLn "Certificate information:"
              putStrLn $ "PEM Name: " ++ show (pemName pem)
              putStrLn $ "Content length: " ++ show (B.length (pemContent pem))
              putStrLn ""
              putStrLn "Full content (hex):"
              putStrLn $ hexdump (pemContent pem)
        Right cert -> do
          -- Always show detailed information (verbose is now the default)
          showPlatformCert cert

-- | Validate certificate
doValidate :: [TCGOpts] -> [String] -> IO ()
doValidate opts files = do
  when (Help `elem` opts) $ do
    putStrLn $ usageInfo "usage: tcg-platform-cert-util validate [options] <certificate-file>" optionsValidate
    exitSuccess

  when (null files) $ do
    putStrLn "Error: No certificate file specified"
    exitFailure

  let file = case files of
        (f : _) -> f
        [] -> error "No files provided"
      verbose = Verbose `elem` opts
      caCertFile = extractOpt "CA certificate" (\case CACertificate f -> Just f; _ -> Nothing) opts ""

  putStrLn $ "Validating certificate: " ++ file
  putStrLn ""

  -- Load CA certificate if provided
  mCaCert <-
    if null caCertFile
      then return Nothing
      else do
        -- TODO Too nested case - refactor
        putStrLn $ "Loading CA certificate from: " ++ caCertFile
        caPemResult <- readPEMFile caCertFile
        case caPemResult of
          [] -> do
            putStrLn " FAILED: No CA certificate found in file"
            exitFailure
          (caPem : _) -> do
            case decodeSignedCertificate (pemContent caPem) of
              Left caCertErr -> do
                putStrLn $ " FAILED: CA certificate parsing failed: " ++ show caCertErr
                exitFailure
              Right signedCaCert -> do
                let caCert = getCertificate signedCaCert
                putStrLn " CA certificate loaded successfully"
                return (Just caCert)

  -- Read and parse the platform certificate file
  result <- readPEMFile file
  case result of
    [] -> do
      putStrLn " FAILED: No certificates found in file"
      exitFailure
    (pem : _) -> do
      currentTime <- getCurrentTime

      -- Try to decode as Platform Certificate
      case decodeSignedPlatformCertificate (pemContent pem) of
        Left err -> do
          putStrLn " FAILED: Certificate parsing failed"
          putStrLn $ "   Error: " ++ err
          putStrLn ""

          -- Try basic ASN.1 validation
          case decodeASN1' BER (pemContent pem) of
            Left asn1err -> do
              putStrLn " FAILED: ASN.1 parsing also failed"
              putStrLn $ "   ASN.1 Error: " ++ show asn1err
              exitFailure
            Right asn1 -> do
              validateBasicASN1Structure asn1 verbose
        Right cert -> do
          validatePlatformCertificateUtil cert currentTime verbose mCaCert

-- | Show components
doComponents :: [TCGOpts] -> [String] -> IO ()
doComponents opts files = do
  when (Help `elem` opts) $ do
    putStrLn $ usageInfo "usage: tcg-platform-cert-util components [options] <certificate-file>" optionsComponents
    exitSuccess

  when (null files) $ do
    putStrLn "Error: No certificate file specified"
    exitFailure

  let file = case files of
        (f : _) -> f
        [] -> error "No files provided"
      verbose = Verbose `elem` opts

  putStrLn $ "Extracting components from: " ++ file

  -- Read and parse the PEM file
  result <- readPEMFile file
  -- TODO Too nested case - refactor
  case result of
    [] -> do
      putStrLn "Error: No certificates found in file"
      exitFailure
    (pem : _) -> do
      -- Try to decode as Platform Certificate
      case decodeSignedPlatformCertificate (pemContent pem) of
        Left err -> do
          putStrLn $ "Error: Failed to parse as Platform Certificate: " ++ err
          putStrLn ""
          putStrLn "Attempting to extract components from raw ASN.1 structure:"
          case decodeASN1' BER (pemContent pem) of
            Left asn1err -> do
              putStrLn $ "ASN.1 parsing failed: " ++ show asn1err
              exitFailure
            Right asn1 -> do
              extractComponentsFromASN1 asn1 verbose
        Right cert -> do
          showComponentInformation cert verbose

-- | Generate a platform certificate using paccor signer directly.
-- This mode consumes paccor JSON files (ComponentList + Extensions + PolicyReference)
-- and delegates certificate construction/signing to paccor for compatibility.
-- | Write PEM file
writePEMFile :: FilePath -> [PEM] -> IO ()
writePEMFile file pems = do
  let content = BC.concat $ map pemWriteBS pems
  B.writeFile file content

-- | Read PEM file and parse
readPEMFile :: FilePath -> IO [PEM]
readPEMFile file = do
  content <- B.readFile file
  case pemParseBS content of
    Left err -> error ("PEM parsing failed: " ++ err)
    Right pems -> return pems

-- | Extract option value helper
extractOpt :: String -> (TCGOpts -> Maybe String) -> [TCGOpts] -> String -> String
extractOpt _ f options defaultValue = maybe defaultValue id $ listToMaybe $ mapMaybe f options

-- | Generic getopt handler
getoptMain :: [OptDescr a] -> ([a] -> [String] -> IO ()) -> [String] -> IO ()
getoptMain opts f as =
  case getOpt Permute opts as of
    (o, n, []) -> f o n
    (_, _, err) -> error (show err)

-- | Command line option definitions
optionsGenerate :: [OptDescr TCGOpts]
optionsGenerate =
  [ Option ['o'] ["output"] (ReqArg Output "FILE") "output file (default: platform-cert.pem)",
    Option ['m'] ["manufacturer"] (ReqArg Manufacturer "NAME") "platform manufacturer",
    Option [] ["model"] (ReqArg Model "NAME") "platform model",
    Option [] ["version"] (ReqArg Version "VER") "platform version",
    Option ['s'] ["serial"] (ReqArg Serial "NUM") "platform serial number",
    Option [] ["key-size"] (ReqArg (KeySize . read) "BITS") "key size in bits (default: 2048)",
    Option [] ["validity"] (ReqArg (ValidityDays . read) "DAYS") "validity period in days (default: 365)",
    Option ['k'] ["ca-key"] (ReqArg CAPrivateKey "FILE") "CA private key file (PEM format) [REQUIRED]",
    Option ['c'] ["ca-cert"] (ReqArg CACertificate "FILE") "CA certificate file (PEM format) [REQUIRED]",
    Option ['e'] ["ek-cert"] (ReqArg TPMEKCertificate "FILE") "TPM EK certificate file (PEM format) [REQUIRED]",
    Option ['f'] ["config"] (ReqArg ConfigFile "FILE") "YAML configuration file (alternative to individual options)",
    Option [] ["hash"] (ReqArg HashAlgorithm "ALGORITHM") "Hash algorithm (sha256|sha384|sha512, default: sha384)",
    Option [] ["skip-compliance"] (NoArg SkipCompliance) "skip pre-issuance compliance checks",
    Option [] ["compat"] (NoArg Compat) "operational compatibility profile (default)",
    Option [] ["strict-v11"] (NoArg StrictV11Mode) "strict v1.1 profile",
    Option [] ["policy-ref"] (ReqArg PolicyRefFile "FILE") "PolicyReference.json path (auto-detected from --config dir)",
    Option [] ["extensions"] (ReqArg ExtensionsFile "FILE") "Extensions.json path (auto-detected from --config dir)",
    Option [] ["json"] (NoArg JsonOutput) "output results in JSON format",
    Option [] ["serial-number"] (ReqArg CertSerialNumber "NUM") "certificate serial number (default: 1)",
    Option [] ["not-before"] (ReqArg NotBefore "YYYYMMDD") "validity start date (e.g. 20180101)",
    Option [] ["not-after"] (ReqArg NotAfter "YYYYMMDD") "validity end date (e.g. 20680101)",
    Option ['h'] ["help"] (NoArg Help) "show help"
  ]

optionsGenerateDelta :: [OptDescr TCGOpts]
optionsGenerateDelta =
  [ Option ['o'] ["output"] (ReqArg Output "FILE") "output file (default: delta-cert.pem)",
    Option ['f'] ["config"] (ReqArg ConfigFile "FILE") "Delta YAML/JSON configuration file [REQUIRED]",
    Option ['b'] ["base-cert"] (ReqArg BaseCertificate "FILE") "base platform certificate file (PEM format) [REQUIRED]",
    Option [] ["base-serial"] (ReqArg BaseSerial "NUM") "base certificate serial number",
    Option [] ["component-changes"] (ReqArg ComponentChanges "CHANGES") "component changes description",
    Option ['k'] ["ca-key"] (ReqArg CAPrivateKey "FILE") "CA private key file (PEM format) [REQUIRED]",
    Option ['c'] ["ca-cert"] (ReqArg CACertificate "FILE") "CA certificate file (PEM format) [REQUIRED]",
    Option [] ["extensions"] (ReqArg ExtensionsFile "FILE") "Extensions.json path (auto-detected from --config dir)",
    Option [] ["hash"] (ReqArg HashAlgorithm "ALGORITHM") "Hash algorithm (sha256|sha384|sha512, default: sha384)",
    Option [] ["serial-number"] (ReqArg CertSerialNumber "NUM") "certificate serial number",
    Option [] ["not-before"] (ReqArg NotBefore "YYYYMMDD") "validity start date (e.g. 20180101)",
    Option [] ["not-after"] (ReqArg NotAfter "YYYYMMDD") "validity end date (e.g. 20680101)",
    Option ['h'] ["help"] (NoArg Help) "show help"
  ]

optionsShow :: [OptDescr TCGOpts]
optionsShow =
  [ Option ['v'] ["verbose"] (NoArg Verbose) "verbose output",
    Option ['h'] ["help"] (NoArg Help) "show help"
  ]

optionsValidate :: [OptDescr TCGOpts]
optionsValidate =
  [ Option ['v'] ["verbose"] (NoArg Verbose) "verbose output",
    Option ['c'] ["ca-cert"] (ReqArg CACertificate "FILE") "CA certificate file (PEM format) for signature verification",
    Option ['h'] ["help"] (NoArg Help) "show help"
  ]

optionsComponents :: [OptDescr TCGOpts]
optionsComponents =
  [ Option ['v'] ["verbose"] (NoArg Verbose) "verbose output",
    Option ['h'] ["help"] (NoArg Help) "show help"
  ]

optionsConvert :: [OptDescr TCGOpts]
optionsConvert =
  [ Option ['o'] ["output"] (ReqArg Output "FILE") "output YAML file",
    Option [] ["from-paccor"] (NoArg FromPaccor) "input is paccor JSON format (auto-detected if not specified)",
    Option ['h'] ["help"] (NoArg Help) "show help"
  ]

-- | Convert paccor JSON to YAML format
doConvert :: [TCGOpts] -> [String] -> IO ()
doConvert opts files = do
  when (Help `elem` opts) $ do
    putStrLn $ usageInfo "usage: tcg-platform-cert-util convert [options] <input-file>" optionsConvert
    putStrLn ""
    putStrLn "Converts paccor JSON format to tcg-platform-cert-util YAML format."
    putStrLn ""
    putStrLn "paccor is the NSA Cybersecurity Platform Attribute Certificate Creator."
    putStrLn "See: https://github.com/nsacyber/paccor"
    putStrLn ""
    putStrLn "Examples:"
    putStrLn "  tcg-platform-cert-util convert device.json -o platform.yaml"
    putStrLn "  tcg-platform-cert-util convert --from-paccor device.json"
    exitSuccess

  case files of
    [] -> do
      putStrLn "Error: No input file specified"
      putStrLn ""
      putStrLn $ usageInfo "usage: tcg-platform-cert-util convert [options] <input-file>" optionsConvert
      exitFailure
    (inputFile : _) -> do
      let outputFile = extractOpt "output" (\case Output o -> Just o; _ -> Nothing) opts ""
          defaultOutput = replaceExtension inputFile ".yaml"
          finalOutput = if null outputFile then defaultOutput else outputFile

      putStrLn $ "Converting: " ++ inputFile
      putStrLn $ "Output: " ++ finalOutput

      -- Load and convert
      result <- loadPaccorConfig inputFile
      case result of
        Left err -> do
          putStrLn $ "Error parsing paccor JSON: " ++ err
          exitFailure
        Right paccorConfig -> do
          savePaccorAsYaml paccorConfig finalOutput
          let platform = paccorPlatform paccorConfig
              componentCount = maybe 0 length (paccorComponents paccorConfig)
          putStrLn ""
          putStrLn "Conversion successful!"
          putStrLn $ "  Platform: " ++ show (platformManufacturerStr platform) ++ " " ++ show (platformModel platform)
          putStrLn $ "  Components: " ++ show componentCount
  where
    -- Replace file extension
    replaceExtension :: FilePath -> String -> FilePath
    replaceExtension path newExt =
      let base = reverse $ drop 1 $ dropWhile (/= '.') $ reverse path
      in if null base then path ++ newExt else base ++ newExt

-- | Compliance check options
optionsCompliance :: [OptDescr TCGOpts]
optionsCompliance =
  [ Option ['v'] ["verbose"] (NoArg Verbose) "verbose output with detailed check results",
    Option ['b'] ["base"] (ReqArg BaseCertificate "FILE") "base certificate for Delta comparison",
    Option [] ["compat"] (NoArg Compat) "operational compatibility profile (default)",
    Option [] ["strict-v11"] (NoArg StrictV11Mode) "strict v1.1 profile (tcg/ietf/dmtf only, v2 platformConfiguration OID)",
    Option [] ["chain"] (NoArg ChainMode) "chain compliance mode (first file = Base, rest = Deltas)",
    Option [] ["json"] (NoArg JsonOutput) "output results in JSON format",
    Option ['h'] ["help"] (NoArg Help) "show help"
  ]

-- | Run IWG Platform Certificate Profile v1.1 compliance checks
doCompliance :: [TCGOpts] -> [String] -> IO ()
doCompliance opts files = do
  when (Help `elem` opts) $ do
    putStrLn $ usageInfo "usage: tcg-platform-cert-util compliance [options] <certificate-file(s)>" optionsCompliance
    putStrLn ""
    putStrLn "Runs IWG Platform Certificate Profile v1.1 compliance checks."
    putStrLn "Default mode is OperationalCompatibility; use --strict-v11 for strict v1.1 behavior."
    putStrLn ""
    putStrLn "For Delta certificate testing, use --base to provide the base certificate:"
    putStrLn "  tcg-platform-cert-util compliance --base base.pem delta.pem"
    putStrLn ""
    putStrLn "For chain compliance, use --chain with Base + Delta files:"
    putStrLn "  tcg-platform-cert-util compliance --chain base.pem delta1.pem delta2.pem"
    exitSuccess

  let verbose = Verbose `elem` opts
      compatMode = Compat `elem` opts
      strictV11Mode = StrictV11Mode `elem` opts
      mode = if strictV11Mode then StrictV11 else OperationalCompatibility
      jsonMode = JsonOutput `elem` opts
      chainMode = ChainMode `elem` opts
      baseCertPath = listToMaybe [f | BaseCertificate f <- opts]

  when (compatMode && strictV11Mode) $ do
    putStrLn "Error: --compat and --strict-v11 cannot be used together."
    exitFailure

  when (chainMode && maybe False (const True) baseCertPath) $ do
    putStrLn "Error: --chain and --base cannot be used together."
    exitFailure

  case files of
    [] -> do
      putStrLn "Error: No certificate file specified"
      putStrLn ""
      putStrLn $ usageInfo "usage: tcg-platform-cert-util compliance [options] <certificate-file(s)>" optionsCompliance
      exitFailure
    _ | chainMode -> doChainCompliance opts files mode jsonMode verbose
    (file : _) -> doSingleCompliance file opts mode baseCertPath jsonMode verbose

-- | Run single-certificate compliance check
doSingleCompliance :: FilePath -> [TCGOpts] -> ComplianceMode -> Maybe FilePath -> Bool -> Bool -> IO ()
doSingleCompliance file _opts mode baseCertPath jsonMode verbose = do
  when (not jsonMode) $ do
    putStrLn $ "Running compliance checks on: " ++ file
    putStrLn $ "Compliance mode: " ++ T.unpack (complianceModeText mode)
    case baseCertPath of
      Just bp -> putStrLn $ "Using base certificate: " ++ bp
      Nothing -> return ()
    putStrLn ""

  -- Read and parse the certificate file
  result <- readPEMFile file
  case result of
    [] -> do
      putStrLn "Error: No certificates found in file"
      exitFailure
    (pem : _) -> do
      case decodeSignedPlatformCertificate (pemContent pem) of
        Left err -> do
          putStrLn $ "Error: Failed to parse as Platform Certificate: " ++ err
          exitFailure
        Right cert -> do
          -- Load base certificate if provided
          mBaseCert <- case baseCertPath of
            Nothing -> return Nothing
            Just bp -> do
              baseResult <- readPEMFile bp
              case baseResult of
                [] -> do
                  putStrLn $ "Warning: No certificates found in base file: " ++ bp
                  return Nothing
                (basePem : _) ->
                  case decodeSignedPlatformCertificate (pemContent basePem) of
                    Left err -> do
                      putStrLn $ "Warning: Failed to parse base certificate: " ++ err
                      return Nothing
                    Right baseCert -> return (Just baseCert)

          -- Run compliance test
          let compOpts = defaultComplianceOptions
                { coVerbose = verbose
                , coBaseCert = mBaseCert
                , coMode = mode
                }
          compResult <- runComplianceTest cert compOpts

          if jsonMode
            then do
              now <- getCurrentTime
              let report = buildComplianceReport "compliance" mode compResult now
              BC.putStrLn $ LBS.toStrict $ renderJsonReport report
            else do
              -- Display text results
              putStrLn "=========================================="
              putStrLn "  IWG Platform Certificate Profile v1.1"
              putStrLn "        Compliance Test Results"
              putStrLn "=========================================="
              putStrLn ""
              putStrLn $ "Subject: " ++ show (resSubject compResult)
              putStrLn $ "Serial:  " ++ show (resSerialNumber compResult)
              putStrLn $ "Type:    " ++ show (resCertType compResult)
              putStrLn $ "Mode:    " ++ T.unpack (complianceModeText (resComplianceMode compResult))
              putStrLn ""

              forM_ (resCategories compResult) $ \catResult -> do
                let catName' = show (catName catResult)
                    passed = catPassed catResult
                    failed = catFailed catResult
                    failedReq = catFailedRequired catResult
                    failedRec = catFailedRecommended catResult
                    skipped = catSkipped catResult
                    errors = catErrors catResult
                    total = passed + failed + skipped + errors
                putStrLn $ catName' ++ ": " ++ show passed ++ "/" ++ show total ++ " passed"
                        ++ (if failedReq > 0 then " (" ++ show failedReq ++ " required failed)" else "")
                        ++ (if failedRec > 0 then " (" ++ show failedRec ++ " recommended failed)" else "")
                        ++ (if errors > 0 then " (" ++ show errors ++ " errors)" else "")

                when verbose $ do
                  forM_ (catChecks catResult) $ \check -> do
                    let statusStr = case crStatus check of
                          Pass -> " [PASS] "
                          Fail reason -> " [FAIL] " ++ show reason
                          Skip reason -> " [SKIP] " ++ show reason
                          Error err' -> " [ERR]  " ++ show err'
                        refShort = formatReferenceShort (crReference check)
                        level = requirementLevelText (srLevel (crReference check))
                        refInfo = " (" ++ T.unpack refShort ++ " " ++ T.unpack level ++ ")"
                    putStrLn $ "    " ++ show (crId check) ++ statusStr ++ refInfo

              putStrLn ""
              putStrLn "=========================================="
              putStrLn $ "Total: " ++ show (resTotalPassed compResult) ++ " passed, "
                      ++ show (resTotalFailedRequired compResult) ++ " required failed, "
                      ++ show (resTotalFailedRecommended compResult) ++ " recommended failed, "
                      ++ show (resTotalSkipped compResult) ++ " skipped, "
                      ++ show (resTotalErrors compResult) ++ " errors"
              putStrLn ""

              if resCompliant compResult
                then do
                  putStrLn "  COMPLIANT with IWG Profile v1.1"
                  putStrLn "=========================================="
                else do
                  putStrLn "  NOT COMPLIANT with IWG Profile v1.1"
                  putStrLn "=========================================="
                  exitFailure

          when (not (resCompliant compResult) && jsonMode) exitFailure

-- | Run chain compliance checks across Base + Delta certificates
doChainCompliance :: [TCGOpts] -> [String] -> ComplianceMode -> Bool -> Bool -> IO ()
doChainCompliance _opts files mode jsonMode _verbose = do
  case files of
    [] -> do
      putStrLn "Error: --chain requires at least one certificate file (Base)"
      exitFailure
    (baseFile : deltaFiles) -> do
      -- Load Base certificate
      basePemResult <- readPEMFile baseFile
      baseCert <- case basePemResult of
        [] -> do { putStrLn $ "Error: No certificates in base file: " ++ baseFile; exitFailure }
        (pem:_) -> case decodeSignedPlatformCertificate (pemContent pem) of
          Left err -> do { putStrLn $ "Error: Failed to parse base cert: " ++ err; exitFailure }
          Right c -> return c

      -- Load Delta certificates
      deltaCerts <- mapM (\df -> do
        pemResult <- readPEMFile df
        case pemResult of
          [] -> do { putStrLn $ "Error: No certificates in delta file: " ++ df; exitFailure }
          (pem:_) -> case decodeSignedPlatformCertificate (pemContent pem) of
            Left err -> do { putStrLn $ "Error: Failed to parse delta cert " ++ df ++ ": " ++ err; exitFailure }
            Right c -> return c
        ) deltaFiles

      -- Extract identity from PlatformInfo
      let extractIdentity cert = case getPlatformInfo cert of
            Just pi' -> (piManufacturer pi', piModel pi', piVersion pi')
            Nothing  -> ("", "", "")
          baseIdentity = extractIdentity baseCert
          deltaIdentities = map extractIdentity deltaCerts

      -- Extract serial numbers
      let baseSerial = pciSerialNumber (getPlatformCertificate baseCert)
          deltaSerials = map (pciSerialNumber . getPlatformCertificate) deltaCerts

      -- Extract components as CompId tuples
      let extractCompIds cert = case getComponentStatus cert of
            Just comps -> map (\(cid, _st) -> (ci2Manufacturer cid, ci2Model cid, ci2Serial cid)) comps
            Nothing -> []
          extractDeltaChanges cert = case getComponentStatus cert of
            Just comps -> map (\(cid, st) -> ((ci2Manufacturer cid, ci2Model cid, ci2Serial cid), st)) comps
            Nothing -> []
          baseCompIds = extractCompIds baseCert
          deltaChanges = map extractDeltaChanges deltaCerts

      -- CHAIN-004: Holder reference validation
      -- TODO: Extract actual holder serial from Delta certificate structure
      -- For now, skip this check as holder extraction is not yet implemented
      let chain004 = ChainCheckResult "CHAIN-004" Must
            (Skip "Holder serial extraction not yet implemented")
            "Each Delta must reference Base or preceding Delta as holder"

      -- Run chain checks
      let chain001 = checkChainIdentity baseIdentity deltaIdentities
          chain002 = checkChainOrdering (baseSerial : deltaSerials)
          chain003 = checkStateTransitions baseCompIds deltaChanges mode
          finalState = computeFinalState baseCompIds deltaChanges
          allChecks = [chain001, chain002, chain003, chain004]
          allPassed = all (\r -> case ccrStatus r of { Pass -> True; Skip _ -> True; _ -> False }) allChecks

      if jsonMode
        then do
          now <- getCurrentTime
          -- Build a chain-specific JSON result
          let chainResult = object
                [ "base"       .= baseFile
                , "deltaCount" .= length deltaFiles
                , "mode"       .= complianceModeText mode
                , "checks"     .= map chainCheckToValue allChecks
                , "finalState" .= object
                    [ "activeComponents" .= length (psComponents finalState)
                    , "deltasApplied"    .= psDeltaCount finalState
                    ]
                , "compliant"  .= allPassed
                ]
              report = ComplianceReport
                { crTool = "tcg-platform-cert-util"
                , crVersion = "0.1.0"
                , crCommand = "compliance --chain"
                , crTimestamp = now
                , crMode = mode
                , crCertType = Nothing
                , crSubject = Nothing
                , crLayers = ReportLayers Nothing (Just chainResult)
                , crCompliant = allPassed
                , crOutputFile = Nothing
                , crExitCode = if allPassed then 0 else 1
                }
          BC.putStrLn $ LBS.toStrict $ renderJsonReport report
          when (not allPassed) exitFailure
        else do
          putStrLn "=========================================="
          putStrLn "  Chain Compliance Results"
          putStrLn "=========================================="
          putStrLn ""
          putStrLn $ "Base: " ++ baseFile
          putStrLn $ "Deltas: " ++ show (length deltaFiles) ++ " certificate(s)"
          putStrLn $ "Mode: " ++ T.unpack (complianceModeText mode)
          putStrLn ""

          forM_ allChecks $ \check -> do
            let statusStr = case ccrStatus check of
                  Pass -> "[PASS]"
                  Fail reason -> "[FAIL] " ++ T.unpack reason
                  Skip reason -> "[SKIP] " ++ T.unpack reason
                  Error err' -> "[ERR]  " ++ T.unpack err'
            putStrLn $ "  " ++ T.unpack (ccrCheckId check)
                    ++ " (" ++ show (ccrLevel check) ++ ") "
                    ++ statusStr
            putStrLn $ "    " ++ T.unpack (ccrMessage check)

          putStrLn ""
          putStrLn $ "Final platform state: "
                  ++ show (length (psComponents finalState)) ++ " active component(s)"
                  ++ " after " ++ show (psDeltaCount finalState) ++ " delta(s)"
          putStrLn ""

          if allPassed
            then do
              putStrLn "  CHAIN COMPLIANT"
              putStrLn "=========================================="
            else do
              putStrLn "  CHAIN NOT COMPLIANT"
              putStrLn "=========================================="
              exitFailure

-- | Convert a chain check result to a JSON value.
chainCheckToValue :: ChainCheckResult -> Value
chainCheckToValue r = object
  [ "checkId"  .= ccrCheckId r
  , "level"    .= show (ccrLevel r)
  , "status"   .= (case ccrStatus r of
      Pass -> String "Pass"
      Fail reason -> String ("Fail: " <> reason)
      Skip reason -> String ("Skip: " <> reason)
      Error err' -> String ("Error: " <> err'))
  , "message"  .= ccrMessage r
  ]

-- ============================================================
-- Lint command
-- ============================================================

-- | Options for the lint command
optionsLint :: [OptDescr TCGOpts]
optionsLint =
  [ Option ['b'] ["base"] (ReqArg BaseCertificate "FILE") "base certificate (implies Delta config mode)"
  , Option [] ["compat"]     (NoArg Compat)       "operational compatibility profile (default)"
  , Option [] ["strict-v11"] (NoArg StrictV11Mode) "strict v1.1 profile"
  , Option [] ["json"]       (NoArg JsonOutput)    "output results in JSON format"
  , Option ['v'] ["verbose"] (NoArg Verbose)       "verbose output"
  , Option ['h'] ["help"]    (NoArg Help)          "show help"
  ]

-- | Run config-level lint (Layer 1 only)
doLint :: [TCGOpts] -> [String] -> IO ()
doLint opts nonOpts = do
  when (Help `elem` opts) $ do
    putStrLn $ usageInfo "usage: tcg-platform-cert-util lint [options] <config-file>" optionsLint
    exitSuccess

  let configFile = case nonOpts of
        (f:_) -> f
        []    -> ""
      jsonMode = JsonOutput `elem` opts
      verbose = Verbose `elem` opts
      strictV11 = StrictV11Mode `elem` opts
      compMode = if strictV11 then StrictV11 else OperationalCompatibility
      baseCertPath = listToMaybe [f | BaseCertificate f <- opts]

  when (Compat `elem` opts && StrictV11Mode `elem` opts) $ do
    putStrLn "Error: --compat and --strict-v11 cannot be used together."
    exitFailure

  when (null configFile) $ do
    putStrLn "Error: no configuration file specified."
    putStrLn "Usage: tcg-platform-cert-util lint [options] <config-file>"
    exitFailure

  case baseCertPath of
    Nothing -> doLintBase configFile compMode jsonMode verbose
    Just bp -> doLintDelta configFile bp compMode jsonMode verbose

-- | Lint a Base Platform Certificate config
doLintBase :: FilePath -> ComplianceMode -> Bool -> Bool -> IO ()
doLintBase configFile compMode jsonMode verbose = do
  configResult <- loadConfig configFile
  case configResult of
    Left err -> do
      putStrLn $ "Error loading config: " ++ err
      exitFailure
    Right config -> do
      let lintResults = lintPlatformConfig config
      displayAndExitLint "Base" lintResults compMode jsonMode verbose

-- | Lint a Delta Certificate config against a Base certificate
doLintDelta :: FilePath -> FilePath -> ComplianceMode -> Bool -> Bool -> IO ()
doLintDelta configFile baseCertPath compMode jsonMode verbose = do
  configResult <- loadDeltaConfig configFile
  case configResult of
    Left err -> do
      putStrLn $ "Error loading delta config: " ++ err
      exitFailure
    Right config -> do
      -- Load base certificate
      baseCertData <- B.readFile baseCertPath
      case loadPEMCertificate baseCertData of
        Left err -> do
          putStrLn $ "Error loading base certificate: " ++ err
          exitFailure
        Right baseCert -> do
          let lintResults = lintDeltaConfig config (Just baseCert)
          displayAndExitLint "Delta" lintResults compMode jsonMode verbose

-- | Display lint results and exit with appropriate code (shared by doLintBase/doLintDelta)
displayAndExitLint :: String -> [ConfigLintResult] -> ComplianceMode -> Bool -> Bool -> IO ()
displayAndExitLint label lintResults compMode jsonMode verbose = do
  let hasFailures = any (\r -> clrStatus r == LintFail) lintResults
      hasWarnings = any (\r -> clrStatus r == LintWarn) lintResults

  if jsonMode
    then do
      now <- getCurrentTime
      let report = buildLintReport "lint" compMode lintResults now
      BC.putStrLn $ LBS.toStrict $ renderJsonReport report
    else do
      putStrLn "=========================================="
      putStrLn $ "  Config Lint Results (" ++ label ++ ")"
      putStrLn "=========================================="
      putStrLn ""
      if verbose
        then displayLintResults lintResults
        else displayLintResults [r | r <- lintResults, clrStatus r /= LintPass]
      putStrLn ""

      let passCount = length [r | r <- lintResults, clrStatus r == LintPass]
          failCount = length [r | r <- lintResults, clrStatus r == LintFail]
          warnCount = length [r | r <- lintResults, clrStatus r == LintWarn]
      putStrLn $ "Total: " ++ show passCount ++ " passed, "
                ++ show failCount ++ " failed, "
                ++ show warnCount ++ " warnings"
      putStrLn ""

  -- M-14: Exit code respects ComplianceMode
  case compMode of
    StrictV11
      | hasFailures || hasWarnings -> exitFailure
      | otherwise -> return ()
    OperationalCompatibility
      | hasFailures -> exitFailure
      | hasWarnings -> exitWith (ExitFailure 2)
      | otherwise -> return ()

-- | Load a PEM-encoded platform certificate
loadPEMCertificate :: B.ByteString -> Either String SignedPlatformCertificate
loadPEMCertificate pemData =
  case pemParseBS pemData of
    Left err -> Left $ "PEM parse error: " ++ err
    Right [] -> Left "No PEM entries found"
    Right (pem:_) -> decodeSignedPlatformCertificate (pemContent pem)

-- ============================================================
-- hwinfo command
-- ============================================================

optionsHwinfo :: [OptDescr TCGOpts]
optionsHwinfo =
  [ Option [] ["json"]    (NoArg JsonOutput) "output results in JSON format"
  , Option ['v'] ["verbose"] (NoArg Verbose) "verbose output (addresses, SMBIOS, TCG hex)"
  , Option ['h'] ["help"]    (NoArg Help)    "show help"
  ]

doHwinfo :: [TCGOpts] -> [String] -> IO ()
doHwinfo opts _ = do
  when (Help `elem` opts) $ do
    putStrLn $ usageInfo "usage: tcg-platform-cert-util hwinfo [options]" optionsHwinfo
    putStrLn ""
    putStrLn "Display hardware information from the current host."
    putStrLn "Collects CPU, memory, storage, network, and other components."
    exitSuccess

  let jsonMode = JsonOutput `elem` opts
      verbose  = Verbose `elem` opts

  result <- HC.collectHardware
  case result of
    Left err -> do
      putStrLn $ "Error collecting hardware info: " ++ show err
      exitFailure
    Right hw -> do
      if jsonMode
        then LBS.putStr (encode hw) >> putStrLn ""
        else displayHardwareInfo verbose hw

displayHardwareInfo :: Bool -> HC.HardwareInfo -> IO ()
displayHardwareInfo verbose hw = do
  let p = HC.hwPlatform hw
  putStrLn "Platform:"
  putStrLn $ "  Manufacturer: " ++ T.unpack (HC.platformManufacturer p)
  putStrLn $ "  Model:        " ++ T.unpack (HC.platformModel p)
  putStrLn $ "  Version:      " ++ T.unpack (HC.platformVersion p)
  case HC.platformSerial p of
    Just s  -> putStrLn $ "  Serial:       " ++ T.unpack s
    Nothing -> return ()
  when verbose $ do
    case HC.platformUUID p of
      Just u  -> putStrLn $ "  UUID:         " ++ T.unpack u
      Nothing -> return ()
    case HC.platformSKU p of
      Just s  -> putStrLn $ "  SKU:          " ++ T.unpack s
      Nothing -> return ()
    case HC.platformFamily p of
      Just f  -> putStrLn $ "  Family:       " ++ T.unpack f
      Nothing -> return ()
    case HC.hwSmbiosVersion hw of
      Just v  -> putStrLn $ "  SMBIOS:       " ++ show (HC.smbiosMajor v) ++ "."
                                               ++ show (HC.smbiosMinor v) ++ "."
                                               ++ show (HC.smbiosRevision v)
      Nothing -> return ()

  let comps = HC.hwComponents hw
  putStrLn ""
  putStrLn $ "Components (" ++ show (length comps) ++ " found):"
  forM_ comps $ \c -> do
    let clsName = T.unpack (HC.componentClassName (HC.componentClass c))
        mfr     = T.unpack (HC.componentManufacturer c)
        mdl     = T.unpack (HC.componentModel c)
        pad     = replicate (max 0 (20 - length clsName)) ' '
    putStrLn $ "  [" ++ clsName ++ "]" ++ pad ++ mfr ++ " / " ++ mdl
    when verbose $ do
      case HC.componentSerial c of
        Just s  -> putStrLn $ "                       Serial: " ++ T.unpack s
        Nothing -> return ()
      case HC.componentRevision c of
        Just r  -> putStrLn $ "                       Revision: " ++ T.unpack r
        Nothing -> return ()
      forM_ (HC.componentAddresses c) $ \addr ->
        putStrLn $ "                       Address: " ++ show addr

-- ============================================================
-- create-config command (extended with --detect)
-- ============================================================

optionsCreateConfig :: [OptDescr TCGOpts]
optionsCreateConfig =
  [ Option [] ["detect"] (NoArg Detect)  "auto-detect host hardware"
  , Option ['o'] ["output"] (ReqArg Output "FILE") "output file (default: platform-config.yaml)"
  , Option ['h'] ["help"]   (NoArg Help)   "show help"
  ]

doCreateConfig :: [TCGOpts] -> [String] -> IO ()
doCreateConfig opts files = do
  when (Help `elem` opts) $ do
    putStrLn $ usageInfo "usage: tcg-platform-cert-util create-config [options] [filename]" optionsCreateConfig
    putStrLn ""
    putStrLn "Create a YAML configuration file for platform certificate generation."
    putStrLn ""
    putStrLn "Without --detect: creates a sample config with placeholder data."
    putStrLn "With --detect:    auto-detects host hardware and populates the config."
    exitSuccess

  let outputFile = case extractOpt "output" (\case Output o -> Just o; _ -> Nothing) opts "" of
        "" -> case files of
          (f:_) -> f
          []    -> "platform-config.yaml"
        o -> o
      detectMode = Detect `elem` opts

  if detectMode
    then do
      result <- HC.collectHardware
      case result of
        Left err -> do
          putStrLn $ "Error collecting hardware info: " ++ show err
          exitFailure
        Right hw -> do
          let paccorConfig = HC.hardwareToPaccorConfig hw
              baseConfig = paccorToYamlConfig paccorConfig
              config = baseConfig
                { pccValidityDays = Just 365
                , pccKeySize = Just 2048
                , pccCredentialSpecMajor = Just 1
                , pccCredentialSpecMinor = Just 1
                , pccCredentialSpecRevision = Just 13
                , pccPlatformSpecMajor = Just 2
                , pccPlatformSpecMinor = Just 0
                , pccPlatformSpecRevision = Just 164
                , pccSpecificationVersion = Just "1.1"
                }
          Yaml.encodeFile outputFile config
          putStrLn $ "Configuration created from host hardware: " ++ outputFile
    else do
      createExampleConfig outputFile

-- | Usage information
usage :: IO ()
usage = do
  putStrLn "usage: tcg-platform-cert-util <command> [options]"
  putStrLn ""
  putStrLn "Commands:"
  putStrLn "  generate       : Generate a new platform certificate"
  putStrLn "  generate-delta : Generate a new delta platform certificate"
  putStrLn "  show           : Display certificate information"
  putStrLn "  validate       : Validate a certificate"
  putStrLn "  components     : Show component information"
  putStrLn "  compliance     : Run IWG Profile v1.1 compliance checks"
  putStrLn "  lint           : Validate a YAML configuration file"
  putStrLn "  hwinfo         : Display host hardware information"
  putStrLn "  create-config  : Create YAML configuration file (--detect for auto-detection)"
  putStrLn "  convert        : Convert paccor JSON to YAML format"
  putStrLn "  help           : Show this help"
  putStrLn ""
  putStrLn "Use 'tcg-platform-cert-util <command> --help' for command-specific options."

-- | Parse a YYYYMMDD string into a DateTime (midnight UTC)
parseDateYYYYMMDD :: String -> Maybe DateTime
parseDateYYYYMMDD s
  | length s == 8 =
    let yearStr  = take 4 s
        monthStr = take 2 (drop 4 s)
        dayStr   = take 2 (drop 6 s)
    in do
      y <- readMaybe yearStr
      m <- intToMonth =<< readMaybe monthStr
      d <- readMaybe dayStr
      return $ DateTime (Date y m d) (TimeOfDay 0 0 0 0)
  | otherwise = Nothing
  where
    intToMonth :: Int -> Maybe HG.Month
    intToMonth 1  = Just HG.January
    intToMonth 2  = Just HG.February
    intToMonth 3  = Just HG.March
    intToMonth 4  = Just HG.April
    intToMonth 5  = Just HG.May
    intToMonth 6  = Just HG.June
    intToMonth 7  = Just HG.July
    intToMonth 8  = Just HG.August
    intToMonth 9  = Just HG.September
    intToMonth 10 = Just HG.October
    intToMonth 11 = Just HG.November
    intToMonth 12 = Just HG.December
    intToMonth _  = Nothing
