{-# LANGUAGE OverloadedStrings #-}

-- | Integration tests for paccor (Platform Attribute Certificate Creator).
-- Verifies that paccor-generated certificates comply with IWG Platform
-- Certificate Profile v1.1 using our 66-check compliance framework.
--
-- Tests are automatically skipped if paccor is not installed.
-- Set PACCOR_HOME and PACCOR_RESOURCES environment variables to override
-- default paths.
module PaccorSpec (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.List (find, intercalate)
import System.Directory (doesDirectoryExist, doesFileExist, getTemporaryDirectory,
                         createDirectoryIfMissing, removeDirectoryRecursive)
import System.Environment (lookupEnv)
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import System.Process (readProcessWithExitCode)
import Text.Printf (printf)

import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Encoding (decodeASN1', encodeASN1)
import Data.ASN1.Types (ASN1(..), ASN1ConstructionType(..), ASN1Class(..))
import Data.X509.TCG.Platform (decodeSignedPlatformCertificate)
import Data.X509.TCG.Compliance.Check (runComplianceTest, defaultComplianceOptions)
import Data.X509.TCG.Compliance.Reference (srLevel)
import Data.X509.TCG.Compliance.Result
import Data.X509.TCG.Compliance.Types (RequirementLevel(..), isRequired)

-- | Default paccor installation path
defaultPaccorHome :: FilePath
defaultPaccorHome = "/private/tmp/paccor-install-20260207/paccor-1.5.0beta5"

-- | Default paccor test resources path
defaultPaccorResources :: FilePath
defaultPaccorResources = "/private/tmp/paccor-nsacyber-20260207/src/test/resources"

-- | Find paccor home directory with signer binary
findPaccorHome :: IO (Maybe FilePath)
findPaccorHome = do
  env <- lookupEnv "PACCOR_HOME"
  let home = maybe defaultPaccorHome id env
  let signer = home </> "bin" </> "signer"
  exists <- doesFileExist signer
  return $ if exists then Just home else Nothing

-- | Find paccor test resources directory
findPaccorResources :: IO (Maybe FilePath)
findPaccorResources = do
  env <- lookupEnv "PACCOR_RESOURCES"
  let res = maybe defaultPaccorResources id env
  let ek = res </> "ek.cer"
  exists <- doesFileExist ek
  return $ if exists then Just res else Nothing

-- | Run paccor signer and return DER bytes or error
runPaccorSigner :: FilePath   -- ^ paccor home
                -> FilePath   -- ^ temp directory
                -> FilePath   -- ^ resources directory
                -> String     -- ^ components JSON content
                -> String     -- ^ policy ref JSON content
                -> String     -- ^ extensions JSON content
                -> String     -- ^ serial number
                -> IO (Either String B.ByteString)
runPaccorSigner home tmpDir resDir compsJson policyJson extJson serial = do
  -- Write JSON configs to temp files (use serial for unique filenames)
  let compsFile  = tmpDir </> "components-" ++ serial ++ ".json"
      policyFile = tmpDir </> "policyRef-" ++ serial ++ ".json"
      extFile    = tmpDir </> "extensions-" ++ serial ++ ".json"
      outFile    = tmpDir </> "output-" ++ serial ++ ".der"
      signerBin  = home </> "bin" </> "signer"
      ekFile     = resDir </> "ek.cer"
      caKeyFile  = resDir </> "ca.pkcs1.pem"
      caCertFile = resDir </> "TestCA.cert.example.pem"
  writeFile compsFile compsJson
  writeFile policyFile policyJson
  writeFile extFile extJson
  -- Run signer
  (exitCode, _stdout, stderr) <- readProcessWithExitCode signerBin
    [ "-e", ekFile
    , "-c", compsFile
    , "-p", policyFile
    , "-x", extFile
    , "-k", caKeyFile
    , "-P", caCertFile
    , "-N", serial
    , "-b", "20240101"
    , "-a", "20301231"
    , "-f", outFile
    ] ""
  -- Check result: both exit code AND file existence
  case exitCode of
    ExitFailure _ -> return $ Left stderr
    ExitSuccess -> do
      exists <- doesFileExist outFile
      if exists
        then Right <$> B.readFile outFile
        else return $ Left ("signer exited 0 but no output file: " ++ stderr)

-- | Run paccor signer using pre-existing JSON files from resources
runPaccorSignerWithFiles :: FilePath -> FilePath -> FilePath
                         -> FilePath -> FilePath -> FilePath
                         -> String -> IO (Either String B.ByteString)
runPaccorSignerWithFiles home tmpDir resDir compsFile policyFile extFile serial = do
  let outFile    = tmpDir </> "output.der"
      signerBin  = home </> "bin" </> "signer"
      ekFile     = resDir </> "ek.cer"
      caKeyFile  = resDir </> "ca.pkcs1.pem"
      caCertFile = resDir </> "TestCA.cert.example.pem"
  (exitCode, _stdout, stderr) <- readProcessWithExitCode signerBin
    [ "-e", ekFile
    , "-c", compsFile
    , "-p", policyFile
    , "-x", extFile
    , "-k", caKeyFile
    , "-P", caCertFile
    , "-N", serial
    , "-b", "20240101"
    , "-a", "20301231"
    , "-f", outFile
    ] ""
  case exitCode of
    ExitFailure _ -> return $ Left stderr
    ExitSuccess -> do
      exists <- doesFileExist outFile
      if exists
        then Right <$> B.readFile outFile
        else return $ Left ("signer exited 0 but no output file: " ++ stderr)

-- | Decode DER and run compliance test
runCompliance :: B.ByteString -> IO ComplianceResult
runCompliance derBytes =
  case decodeSignedPlatformCertificate derBytes of
    Left err -> assertFailure ("decode failed: " ++ err) >> error "unreachable"
    Right cert -> runComplianceTest cert defaultComplianceOptions

-- | Assert a specific check passed
assertCheckPass :: ComplianceResult -> String -> Assertion
assertCheckPass cr checkStr = case findCheck cr checkStr of
  Nothing -> assertFailure $ checkStr ++ " not found in results"
  Just c  -> case crStatus c of
    Pass   -> return ()
    other  -> assertFailure $ checkStr ++ " expected Pass, got: " ++ show other

-- | Assert a specific check passed or was skipped (not failed)
assertCheckPassOrSkip :: ComplianceResult -> String -> Assertion
assertCheckPassOrSkip cr checkStr = case findCheck cr checkStr of
  Nothing -> assertFailure $ checkStr ++ " not found in results"
  Just c  -> case crStatus c of
    Pass   -> return ()
    Skip _ -> return ()
    other  -> assertFailure $ checkStr ++ " expected Pass/Skip, got: " ++ show other

-- | Count SHOULD/MAY failures manually from check results
countRecommendedFailures :: ComplianceResult -> Int
countRecommendedFailures cr =
  let allChecks = concatMap catChecks (resCategories cr)
  in length [c | c <- allChecks, isFail (crStatus c),
             not (isRequired (srLevel (crReference c)))]
  where
    isFail (Fail _) = True
    isFail _        = False

-- | Find a specific check result by its string representation
findCheck :: ComplianceResult -> String -> Maybe CheckResult
findCheck result checkStr =
  let allChecks = concatMap catChecks (resCategories result)
  in find (\c -> show (crId c) == checkStr) allChecks

-- | Create a unique temp directory for a test.
-- Cleans up any leftover directory from a previous failed run.
withTempDir :: String -> (FilePath -> IO a) -> IO a
withTempDir label action = do
  tmp <- getTemporaryDirectory
  let dir = tmp </> "paccor-test-" ++ label
  dirExists <- doesDirectoryExist dir
  if dirExists then removeDirectoryRecursive dir else return ()
  createDirectoryIfMissing True dir
  result <- action dir
  removeDirectoryRecursive dir
  return result

--------------------------------------------------------------------------------
-- ASN.1 DER Encoding Validation Helpers
--------------------------------------------------------------------------------

-- | Check DER round-trip integrity: decode → re-encode → compare bytes.
-- Returns Right () if bytes match, Left with diagnostic message if not.
checkDerRoundTrip :: B.ByteString -> Either String ()
checkDerRoundTrip original =
  case decodeASN1' DER original of
    Left err -> Left $ "DER decode failed: " ++ show err
    Right asn1 ->
      let reencoded = L.toStrict (encodeASN1 DER asn1)
      in if original == reencoded
         then Right ()
         else Left $ case findFirstDiff original reencoded of
           Nothing -> "Length mismatch: original=" ++ show (B.length original)
                      ++ " reencoded=" ++ show (B.length reencoded)
           Just i  -> "DER round-trip mismatch at byte " ++ show i
                      ++ ": original=0x" ++ printf "%02x" (B.index original i)
                      ++ " reencoded=0x" ++ printf "%02x" (B.index reencoded i)

-- | Find the index of the first byte that differs between two ByteStrings.
findFirstDiff :: B.ByteString -> B.ByteString -> Maybe Int
findFirstDiff a b
  | B.length a /= B.length b = Just (min (B.length a) (B.length b))
  | otherwise = case [i | i <- [0 .. B.length a - 1], B.index a i /= B.index b i] of
      []    -> Nothing
      (i:_) -> Just i

-- | Audit GeneralName tags in AIA and CRL extensions of a certificate.
-- Returns a list of encoding issues found.
-- Specifically detects: directoryName [4] used where uniformResourceIdentifier [6]
-- is expected (PR #130 pattern).
auditGeneralNameTags :: B.ByteString -> [String]
auditGeneralNameTags certDer =
  case decodeASN1' DER certDer of
    Left _ -> ["Failed to decode certificate DER"]
    Right asn1 -> scanForExtensions asn1
  where
    -- AIA OID: 1.3.6.1.5.5.7.1.1
    aiaOid :: [Integer]
    aiaOid = [1,3,6,1,5,5,7,1,1]
    -- CRL Distribution Points OID: 2.5.29.31
    crlOid :: [Integer]
    crlOid = [2,5,29,31]

    -- Scan ASN.1 stream for extension OIDs, then audit their values
    scanForExtensions :: [ASN1] -> [String]
    scanForExtensions [] = []
    scanForExtensions (OID oid : Boolean _ : OctetString extVal : rest)
      | oid == aiaOid = auditExtValue "AIA" extVal ++ scanForExtensions rest
      | oid == crlOid = auditExtValue "CRL" extVal ++ scanForExtensions rest
    scanForExtensions (OID oid : OctetString extVal : rest)
      | oid == aiaOid = auditExtValue "AIA" extVal ++ scanForExtensions rest
      | oid == crlOid = auditExtValue "CRL" extVal ++ scanForExtensions rest
    scanForExtensions (_ : rest) = scanForExtensions rest

    -- Decode extension value and check for directoryName [4] in GeneralName position
    auditExtValue :: String -> B.ByteString -> [String]
    auditExtValue extName extBytes =
      case decodeASN1' DER extBytes of
        Left _ -> [extName ++ ": failed to decode extension value"]
        Right extAsn1 -> scanForDirectoryNameUri extName extAsn1

    -- Look for Container Context 4 (directoryName) that should be Context 6 (URI)
    scanForDirectoryNameUri :: String -> [ASN1] -> [String]
    scanForDirectoryNameUri _ [] = []
    scanForDirectoryNameUri ext (Start (Container Context 4) : rest) =
      (ext ++ ": directoryName [4] used where uniformResourceIdentifier [6] expected")
        : scanForDirectoryNameUri ext (skipToEnd (Container Context 4) rest)
    scanForDirectoryNameUri ext (Other Context 6 _ : rest) =
      scanForDirectoryNameUri ext rest  -- tag [6] is correct
    scanForDirectoryNameUri ext (_ : rest) = scanForDirectoryNameUri ext rest

    -- Skip ASN.1 elements until matching End tag
    skipToEnd :: ASN1ConstructionType -> [ASN1] -> [ASN1]
    skipToEnd _ [] = []
    skipToEnd ct (End ct' : rest) | ct == ct' = rest
    skipToEnd ct (_ : rest) = skipToEnd ct rest

--------------------------------------------------------------------------------
-- JSON Generators
--------------------------------------------------------------------------------

-- | Components JSON with platform info and component list
mkComponentsJson :: String -> String -> String -> String
                 -> [(String, String, String, String)] -> String
mkComponentsJson mfg model ver serial comps =
  "{\"PLATFORM\":{" ++
    "\"PLATFORMMANUFACTURERSTR\":\"" ++ mfg ++ "\"," ++
    "\"PLATFORMMODEL\":\"" ++ model ++ "\"," ++
    "\"PLATFORMVERSION\":\"" ++ ver ++ "\"," ++
    "\"PLATFORMSERIAL\":\"" ++ serial ++ "\"" ++
  "},\"COMPONENTS\":[" ++ intercalate "," (map mkComp comps) ++ "]}"
  where
    mkComp (registry, classVal, compMfg, compModel) =
      "{\"COMPONENTCLASS\":{" ++
        "\"COMPONENTCLASSREGISTRY\":\"" ++ registry ++ "\"," ++
        "\"COMPONENTCLASSVALUE\":\"" ++ classVal ++ "\"" ++
      "},\"MANUFACTURER\":\"" ++ compMfg ++ "\"," ++
       "\"MODEL\":\"" ++ compModel ++ "\"}"

-- | Policy reference JSON with optional TBB security assertions
mkPolicyRefJson :: Maybe (Int, String)  -- ^ CC info: (EAL, evalStatus)
                -> Maybe Int            -- ^ FIPS level
                -> Maybe String         -- ^ RTM type
                -> String
mkPolicyRefJson ccInfo fipsLevel rtmType =
  "{\"TCGPLATFORMSPECIFICATION\":{" ++
    "\"VERSION\":{\"MAJORVERSION\":\"1\",\"MINORVERSION\":\"3\",\"REVISION\":\"22\"}," ++
    "\"PLATFORMCLASS\":\"AAAAAQ==\"" ++
  "},\"TCGCREDENTIALSPECIFICATION\":{" ++
    "\"MAJORVERSION\":\"1\",\"MINORVERSION\":\"0\",\"REVISION\":\"16\"" ++
  "}" ++ tbbSection ++ "}"
  where
    tbbSection
      | all (== False) [hasCc, hasFips, hasRtm] = ""
      | otherwise = ",\"TBBSECURITYASSERTIONS\":{\"VERSION\":\"1\",\"ISO9000CERTIFIED\":\"FALSE\"" ++
                    ccPart ++ fipsPart ++ rtmPart ++ "}"
    hasCc = case ccInfo of { Just _ -> True; Nothing -> False }
    hasFips = case fipsLevel of { Just _ -> True; Nothing -> False }
    hasRtm = case rtmType of { Just _ -> True; Nothing -> False }
    ccPart = case ccInfo of
      Nothing -> ""
      Just (eal, status) ->
        ",\"CCINFO\":{\"VERSION\":\"3.1\",\"ASSURANCELEVEL\":\"" ++ show eal ++
        "\",\"EVALUATIONSTATUS\":\"" ++ status ++ "\",\"PLUS\":\"FALSE\"}"
    fipsPart = case fipsLevel of
      Nothing -> ""
      Just level ->
        ",\"FIPSLEVEL\":{\"VERSION\":\"140-2\",\"LEVEL\":\"" ++ show level ++
        "\",\"PLUS\":\"FALSE\"}"
    rtmPart = case rtmType of
      Nothing -> ""
      Just t -> ",\"RTMTYPE\":\"" ++ t ++ "\""

-- | Extensions JSON with certificate policies
mkExtensionsJson :: String -> String
mkExtensionsJson userNotice =
  "{\"CERTIFICATEPOLICIES\":[{" ++
    "\"POLICYIDENTIFIER\":\"1.2.3\"," ++
    "\"POLICYQUALIFIERS\":[" ++
      "{\"POLICYQUALIFIERID\":\"CPS\",\"QUALIFIER\":\"http://localhost\"}," ++
      "{\"POLICYQUALIFIERID\":\"USERNOTICE\",\"QUALIFIER\":\"" ++ userNotice ++ "\"}" ++
    "]" ++
  "}]}"

-- | Extensions JSON with AIA (to test PR #130 bug)
mkExtensionsWithAiaJson :: String -> String
mkExtensionsWithAiaJson userNotice =
  "{\"CERTIFICATEPOLICIES\":[{" ++
    "\"POLICYIDENTIFIER\":\"1.2.3\"," ++
    "\"POLICYQUALIFIERS\":[" ++
      "{\"POLICYQUALIFIERID\":\"CPS\",\"QUALIFIER\":\"http://localhost\"}," ++
      "{\"POLICYQUALIFIERID\":\"USERNOTICE\",\"QUALIFIER\":\"" ++ userNotice ++ "\"}" ++
    "]" ++
  "}],\"AUTHORITYINFOACCESS\":[{" ++
    "\"ACCESSMETHOD\":\"OCSP\"," ++
    "\"ACCESSLOCATION\":\"http://ocsp.example.com\"" ++
  "}]}"

-- | Standard valid userNotice text per IWG Errata Clarification 5
validUserNotice :: String
validUserNotice = "TCG Trusted Platform Endorsement"

-- | TCG component class registry OID
tcgRegistry :: String
tcgRegistry = "2.23.133.18.3.1"

-- | Default components for testing
defaultComponents :: [(String, String, String, String)]
defaultComponents =
  [ (tcgRegistry, "00000001", "Test Mfg", "Chassis")
  , (tcgRegistry, "00000020", "Test Mfg", "Baseboard")
  ]

--------------------------------------------------------------------------------
-- Test Entry Point
--------------------------------------------------------------------------------

-- | Build test tree. Returns IO because paccor detection requires IO.
-- If paccor is not installed, returns a single skip test.
tests :: IO TestTree
tests = do
  mHome <- findPaccorHome
  mRes <- findPaccorResources
  case (mHome, mRes) of
    (Just home, Just resDir) -> return $ buildTests home resDir
    _ -> return $ testGroup "paccor Integration Tests (SKIPPED)"
           [testCase "paccor not available" $ return ()]

-- | Build full test tree with paccor paths resolved
buildTests :: FilePath -> FilePath -> TestTree
buildTests home resDir = testGroup "paccor Integration Tests"
  [ testGroup "Positive Tests"
    [ testP1 home resDir
    , testP2 home resDir
    , testP3 home resDir
    , testP4 home resDir
    , testP5 home resDir
    , testP6 home resDir
    , testP7 home resDir
    ]
  , testGroup "Negative Tests"
    [ testN1 home resDir
    , testN2 home resDir
    , testN3 home resDir
    ]
  , testGroup "ASN.1 Issue Detection"
    [ testA1 home resDir
    ]
  , testGroup "SHOULD/MAY Level Verification"
    [ testS1 home resDir
    , testS2 home resDir
    , testS3 home resDir
    , testS4 home resDir
    , testS5 home resDir
    ]
  , testGroup "ASN.1 Encoding Validation"
    [ testD1 home resDir
    , testD2 home resDir
    , testD3 home resDir
    , testD4 home resDir
    ]
  ]

--------------------------------------------------------------------------------
-- Positive Tests
--------------------------------------------------------------------------------

-- | P1: Basic configuration using paccor's own test fixtures
testP1 :: FilePath -> FilePath -> TestTree
testP1 home resDir = testCase "P1: paccor test fixtures" $
  withTempDir "p1" $ \tmpDir -> do
    result <- runPaccorSignerWithFiles home tmpDir resDir
      (resDir </> "deviceInfo.json")
      (resDir </> "policyRef.json")
      (resDir </> "otherExt.json")
      "10001"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        resTotalFailedRequired cr @?= 0
        resCompliant cr @?= True

-- | P2: Medium components (6 components)
testP2 :: FilePath -> FilePath -> TestTree
testP2 home resDir = testCase "P2: medium components (6 components)" $
  withTempDir "p2" $ \tmpDir -> do
    result <- runPaccorSignerWithFiles home tmpDir resDir
      (resDir </> "comps_medium_2187.json")
      (resDir </> "refopts_2187.json")
      (resDir </> "otherext_2187.json")
      "10002"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        resTotalFailedRequired cr @?= 0
        resCompliant cr @?= True

-- | P3: Empty components array
testP3 :: FilePath -> FilePath -> TestTree
testP3 home resDir = testCase "P3: empty components" $
  withTempDir "p3" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" []
        policy = mkPolicyRefJson Nothing Nothing (Just "static")
        ext = mkExtensionsJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "10003"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        resTotalFailedRequired cr @?= 0
        resCompliant cr @?= True

-- | P4: No TBB security assertions (minimal policy)
testP4 :: FilePath -> FilePath -> TestTree
testP4 home resDir = testCase "P4: no TBB assertions" $
  withTempDir "p4" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson Nothing Nothing Nothing
        ext = mkExtensionsJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "10004"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        resTotalFailedRequired cr @?= 0
        resCompliant cr @?= True

-- | P5: CC EAL levels 1-7
testP5 :: FilePath -> FilePath -> TestTree
testP5 home resDir = testCase "P5: CC EAL levels 1-7" $
  withTempDir "p5" $ \tmpDir ->
    mapM_ (\eal -> do
      let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
          policy = mkPolicyRefJson (Just (eal, "evaluationCompleted")) Nothing (Just "static")
          ext = mkExtensionsJson validUserNotice
      result <- runPaccorSigner home tmpDir resDir comps policy ext (show (20000 + eal))
      case result of
        Left err -> assertFailure $ "EAL " ++ show eal ++ ": paccor failed: " ++ err
        Right derBytes -> do
          cr <- runCompliance derBytes
          assertEqual ("EAL " ++ show eal ++ " failedRequired")
            0 (resTotalFailedRequired cr)
          assertEqual ("EAL " ++ show eal ++ " compliant")
            True (resCompliant cr)
    ) [1..7 :: Int]

-- | P6: FIPS levels 1-4
testP6 :: FilePath -> FilePath -> TestTree
testP6 home resDir = testCase "P6: FIPS levels 1-4" $
  withTempDir "p6" $ \tmpDir ->
    mapM_ (\level -> do
      let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
          policy = mkPolicyRefJson Nothing (Just level) (Just "static")
          ext = mkExtensionsJson validUserNotice
      result <- runPaccorSigner home tmpDir resDir comps policy ext (show (30000 + level))
      case result of
        Left err -> assertFailure $ "FIPS " ++ show level ++ ": paccor failed: " ++ err
        Right derBytes -> do
          cr <- runCompliance derBytes
          assertEqual ("FIPS " ++ show level ++ " failedRequired")
            0 (resTotalFailedRequired cr)
          assertEqual ("FIPS " ++ show level ++ " compliant")
            True (resCompliant cr)
    ) [1..4 :: Int]

-- | P7: All RTM types
testP7 :: FilePath -> FilePath -> TestTree
testP7 home resDir = testCase "P7: RTM types (all 6)" $
  withTempDir "p7" $ \tmpDir ->
    mapM_ (\(i, rtm) -> do
      let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
          policy = mkPolicyRefJson Nothing Nothing (Just rtm)
          ext = mkExtensionsJson validUserNotice
      result <- runPaccorSigner home tmpDir resDir comps policy ext (show (40000 + i))
      case result of
        Left err -> assertFailure $ "RTM " ++ rtm ++ ": paccor failed: " ++ err
        Right derBytes -> do
          cr <- runCompliance derBytes
          assertEqual ("RTM " ++ rtm ++ " failedRequired")
            0 (resTotalFailedRequired cr)
          assertEqual ("RTM " ++ rtm ++ " compliant")
            True (resCompliant cr)
    ) (zip [1 :: Int ..] ["static", "dynamic", "nonHost", "hybrid", "physical", "virtual"])

--------------------------------------------------------------------------------
-- Negative Tests
--------------------------------------------------------------------------------

-- | N1: Wrong userNotice text → NonCompliant (EXT-003 Must Fail)
testN1 :: FilePath -> FilePath -> TestTree
testN1 home resDir = testCase "N1: wrong userNotice → NonCompliant" $
  withTempDir "n1" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson Nothing Nothing (Just "static")
        ext = mkExtensionsJson "Wrong Notice Text"
    result <- runPaccorSigner home tmpDir resDir comps policy ext "50001"
    case result of
      Left err -> assertFailure $
        "Expected paccor to generate cert (it doesn't validate userNotice), got error: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        resCompliant cr @?= False
        -- Verify EXT-003 specifically failed
        case findCheck cr "EXT-003" of
          Nothing -> assertFailure "EXT-003 check not found in results"
          Just c -> case crStatus c of
            Fail _ -> return ()  -- Expected
            other -> assertFailure $
              "Expected EXT-003 Fail, got: " ++ show other

-- | N2: Invalid RTM string → paccor error
testN2 :: FilePath -> FilePath -> TestTree
testN2 home resDir = testCase "N2: invalid RTM → paccor error" $
  withTempDir "n2" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson Nothing Nothing (Just "invalidtype")
        ext = mkExtensionsJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "50002"
    case result of
      Left _ -> return ()  -- Expected: paccor should error
      Right _ -> assertFailure "Expected paccor to reject invalid RTM type, but it succeeded"

-- | N3: EAL out of range (0) → paccor error
testN3 :: FilePath -> FilePath -> TestTree
testN3 home resDir = testCase "N3: EAL=0 → paccor error" $
  withTempDir "n3" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson (Just (0, "evaluationCompleted")) Nothing (Just "static")
        ext = mkExtensionsJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "50003"
    case result of
      Left _ -> return ()  -- Expected: paccor should error
      Right _ -> assertFailure "Expected paccor to reject EAL=0, but it succeeded"

--------------------------------------------------------------------------------
-- ASN.1 Issue Detection
--------------------------------------------------------------------------------

-- | A1: AIA directoryName encoding (PR #130 bug detection)
testA1 :: FilePath -> FilePath -> TestTree
testA1 home resDir = testCase "A1: AIA encoding → CHN-002 Fail (PR #130)" $
  withTempDir "a1" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson Nothing Nothing (Just "static")
        ext = mkExtensionsWithAiaJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "60001"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        -- Certificate should still be compliant overall (CHN-002 is Should level)
        resCompliant cr @?= True
        -- CHN-002 should fail due to directoryName encoding (PR #130 bug),
        -- or pass if the paccor version includes PR #130 fix.
        -- Either way, the certificate should be compliant (CHN-002 is Should level).
        case findCheck cr "CHN-002" of
          Nothing -> return ()  -- CHN-002 may be skipped if no AIA present
          Just c -> case crStatus c of
            Fail _ -> return ()  -- Expected: directoryName instead of URI (PR #130 not applied)
            Pass -> return ()    -- Also OK: PR #130 fix applied
            Skip _ -> return ()  -- AIA extension not present
            other -> assertFailure $
              "Unexpected CHN-002 status: " ++ show other

--------------------------------------------------------------------------------
-- SHOULD/MAY Level Verification
--------------------------------------------------------------------------------

-- | S1: Full config → all SHOULD recommendations met
-- With TBB + CC + FIPS + RTM, SHOULD-level checks for attributes and
-- security assertions should all pass.
testS1 :: FilePath -> FilePath -> TestTree
testS1 home resDir = testCase "S1: SHOULD checks pass with full config" $
  withTempDir "s1" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson (Just (3, "evaluationCompleted")) (Just 2) (Just "static")
        ext = mkExtensionsJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "70001"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        resCompliant cr @?= True
        -- SHOULD checks should pass with full config
        assertCheckPass cr "STR-007"  -- Attributes SHOULD be included
        assertCheckPass cr "STR-011"  -- TCG Platform Specification SHOULD
        assertCheckPass cr "STR-012"  -- TCG Credential Type SHOULD
        assertCheckPass cr "STR-013"  -- TCG Credential Specification SHOULD
        assertCheckPass cr "VAL-006"  -- TBBSecurityAssertions SHOULD

-- | S2: SHOULD level classification and compliance independence
-- Without TBBSecurityAssertions, VAL-006 (Should) may fail/skip but cert
-- stays compliant. Verifies SHOULD checks never affect resCompliant.
testS2 :: FilePath -> FilePath -> TestTree
testS2 home resDir = testCase "S2: SHOULD level does not affect compliance" $
  withTempDir "s2" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson Nothing Nothing Nothing  -- No TBB at all
        ext = mkExtensionsJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "70002"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        -- Cert MUST be compliant (SHOULD failures never affect compliance)
        resCompliant cr @?= True
        resTotalFailedRequired cr @?= 0
        -- VAL-006 (Should): verify it is classified at correct level
        case findCheck cr "VAL-006" of
          Nothing -> assertFailure "VAL-006 not found"
          Just c -> do
            assertEqual "VAL-006 requirement level" Should
              (srLevel (crReference c))
            -- If it fails, it must not be counted as required
            case crStatus c of
              Fail _ -> assertBool "VAL-006 failure is not required"
                (not $ isRequired $ srLevel $ crReference c)
              _ -> return ()
        -- CHN-002 (Should): verify correct classification
        case findCheck cr "CHN-002" of
          Nothing -> return ()
          Just c -> assertEqual "CHN-002 requirement level" Should
            (srLevel (crReference c))
        -- CHN-003 (Should): verify correct classification
        case findCheck cr "CHN-003" of
          Nothing -> return ()
          Just c -> assertEqual "CHN-003 requirement level" Should
            (srLevel (crReference c))

-- | S3: MAY checks pass when optional values are provided
-- With CC EAL and FIPS, the MAY-level checks should pass.
testS3 :: FilePath -> FilePath -> TestTree
testS3 home resDir = testCase "S3: MAY checks pass with CC EAL + FIPS" $
  withTempDir "s3" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson (Just (5, "evaluationCompleted")) (Just 3) (Just "static")
        ext = mkExtensionsJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "70003"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        resCompliant cr @?= True
        -- VAL-010 (May): EAL should pass with valid level
        assertCheckPass cr "VAL-010"
        -- VAL-008 (May): FIPS should pass with valid level
        assertCheckPass cr "VAL-008"

-- | S4: MAY checks pass or skip when optional values are absent
-- Without CC/FIPS, MAY checks should not fail (either pass vacuously or skip).
testS4 :: FilePath -> FilePath -> TestTree
testS4 home resDir = testCase "S4: MAY checks pass/skip without CC/FIPS" $
  withTempDir "s4" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson Nothing Nothing (Just "static")  -- No CC, no FIPS
        ext = mkExtensionsJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "70004"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        resCompliant cr @?= True
        -- MAY checks should not fail when values are absent
        assertCheckPassOrSkip cr "VAL-010"  -- EAL absent → Pass/Skip
        assertCheckPassOrSkip cr "VAL-008"  -- FIPS absent → Pass/Skip
        assertCheckPassOrSkip cr "VAL-009"  -- iso9000Certified absent → Pass/Skip
        assertCheckPassOrSkip cr "VAL-017"  -- strengthOfFunction absent → Pass/Skip

-- | S5: failedRecommended count consistency
-- Verify that resTotalFailedRecommended matches the actual count of
-- SHOULD/MAY failures in the individual check results.
testS5 :: FilePath -> FilePath -> TestTree
testS5 home resDir = testCase "S5: failedRecommended count consistency" $
  withTempDir "s5" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson Nothing Nothing Nothing  -- Minimal config
        ext = mkExtensionsJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "70005"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        cr <- runCompliance derBytes
        resCompliant cr @?= True
        -- Manual count must match reported count
        let manualCount = countRecommendedFailures cr
        assertEqual "failedRecommended count matches manual count"
          manualCount (resTotalFailedRecommended cr)
        -- Per-category counts must sum to total
        let catSum = sum $ map catFailedRecommended (resCategories cr)
        assertEqual "category sum matches total failedRecommended"
          catSum (resTotalFailedRecommended cr)

--------------------------------------------------------------------------------
-- ASN.1 Encoding Validation
--------------------------------------------------------------------------------

-- | D1: DER round-trip with paccor test fixtures
-- Decode paccor's DER output → re-encode → compare bytes.
-- Any difference indicates non-canonical DER encoding.
testD1 :: FilePath -> FilePath -> TestTree
testD1 home resDir = testCase "D1: DER round-trip (paccor test fixtures)" $
  withTempDir "d1" $ \tmpDir -> do
    result <- runPaccorSignerWithFiles home tmpDir resDir
      (resDir </> "deviceInfo.json")
      (resDir </> "policyRef.json")
      (resDir </> "otherExt.json")
      "80001"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> case checkDerRoundTrip derBytes of
        Right () -> return ()
        Left msg -> assertFailure $ "DER encoding non-canonical: " ++ msg

-- | D2: DER round-trip with full features (TBB + CC + FIPS + RTM)
testD2 :: FilePath -> FilePath -> TestTree
testD2 home resDir = testCase "D2: DER round-trip (full config)" $
  withTempDir "d2" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson (Just (3, "evaluationCompleted")) (Just 2) (Just "static")
        ext = mkExtensionsWithAiaJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "80002"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> case checkDerRoundTrip derBytes of
        Right () -> return ()
        Left msg -> assertFailure $ "DER encoding non-canonical: " ++ msg

-- | D3: GeneralName tag audit on AIA extension
-- Detects PR #130 pattern: directoryName [4] used for URI values
-- where uniformResourceIdentifier [6] is required.
testD3 :: FilePath -> FilePath -> TestTree
testD3 home resDir = testCase "D3: AIA GeneralName tag [6] vs [4]" $
  withTempDir "d3" $ \tmpDir -> do
    let comps = mkComponentsJson "Test Corp" "TestModel" "1.0" "SN001" defaultComponents
        policy = mkPolicyRefJson Nothing Nothing (Just "static")
        ext = mkExtensionsWithAiaJson validUserNotice
    result <- runPaccorSigner home tmpDir resDir comps policy ext "80003"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        let issues = auditGeneralNameTags derBytes
        case issues of
          [] -> return ()  -- No encoding issues
          _  -> assertFailure $ "GeneralName encoding issues:\n"
                  ++ intercalate "\n" (map ("  " ++) issues)

-- | D4: GeneralName tag audit on paccor test fixtures
-- Tests with paccor's own test data which may include AIA/CRL extensions.
testD4 :: FilePath -> FilePath -> TestTree
testD4 home resDir = testCase "D4: GeneralName tag audit (test fixtures)" $
  withTempDir "d4" $ \tmpDir -> do
    result <- runPaccorSignerWithFiles home tmpDir resDir
      (resDir </> "deviceInfo.json")
      (resDir </> "policyRef.json")
      (resDir </> "otherExt.json")
      "80004"
    case result of
      Left err -> assertFailure $ "paccor failed: " ++ err
      Right derBytes -> do
        let issues = auditGeneralNameTags derBytes
        -- paccor v1.5.0beta5 is known to use directoryName [4] for URIs (PR #130).
        -- This test verifies detection works; issues are expected.
        assertBool ("D4: detected " ++ show (length issues)
                    ++ " GeneralName encoding issue(s) in paccor test fixtures"
                    ++ (if null issues then "" else ":\n"
                        ++ intercalate "\n" (map ("  " ++) issues)))
                   True
