{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Util.ConfigLint
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Config-level lint (Layer 1) for pre-issuance compliance checking.
--
-- Maps pre-checkable items from the existing 66 IWG checks and global
-- constraints to YAML config-level validation. Uses existing check IDs
-- where a mapping exists; creates new @CFG-*@ IDs only for config-specific checks.

module Data.X509.TCG.Util.ConfigLint
  ( -- * Types
    LintCheckId (..)
  , ConfigLintResult (..)
  , LintStatus (..)
    -- * Lint Functions
  , lintPlatformConfig
  , lintDeltaConfig
    -- * Display
  , displayLintResults
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import Data.Maybe (mapMaybe)
import qualified Data.List as List

import Data.X509.TCG.Compliance.Types (CheckId(..), CheckCategory(..), RequirementLevel(..))
import Data.X509.TCG.Compliance.Suggestion
import qualified Data.ByteString.Char8 as BC
import Data.X509.TCG.Platform (SignedPlatformCertificate, getPlatformInfo, PlatformInfo(..))
import Data.X509.TCG.Util.Config

-- | Lint check identifier
data LintCheckId
  = PreflightCheck CheckId    -- ^ Preflight of existing 66 checks
  | ConfigOnly Text           -- ^ CFG-001, CFG-002, CFG-003
  deriving (Show, Eq)

-- | Lint result status
data LintStatus = LintPass | LintFail | LintWarn
  deriving (Show, Eq)

-- | Config lint result
data ConfigLintResult = ConfigLintResult
  { clrCheckId    :: !LintCheckId
  , clrLevel      :: !RequirementLevel
  , clrStatus     :: !LintStatus
  , clrMessage    :: !Text
  , clrSuggestion :: !(Maybe Suggestion)
  } deriving (Show, Eq)

-- Constants
strmax :: Int
strmax = 256

urimax :: Int
urimax = 1024

-- | Lint a Base Platform Certificate config
lintPlatformConfig :: PlatformCertConfig -> [ConfigLintResult]
lintPlatformConfig config = concat
  [ checkPlatformStrings config
  , checkSecurityAssertionsBase config
  , checkComponents (pccComponents config)
  , checkUriReferences config
  , checkCredentialFields config
  , checkManufacturerId config
  , checkConfigOnlyBase config
  ]

-- | Lint a Delta Certificate config
lintDeltaConfig :: DeltaCertConfig -> Maybe SignedPlatformCertificate -> [ConfigLintResult]
lintDeltaConfig config mBaseCert = concat
  [ checkDeltaPlatformStrings config
  , checkDeltaProhibited config
  , checkDeltaComponents (dccComponents config)
  , checkDeltaIdentityMatch config mBaseCert
  ]

-- ============================================================
-- Platform string checks (VAL-001~004, G-004)
-- ============================================================

checkPlatformStrings :: PlatformCertConfig -> [ConfigLintResult]
checkPlatformStrings config = concat
  [ checkNonEmptyStr (CheckId Value 1) Must "platformManufacturerStr" (pccManufacturer config)
  , checkNonEmptyStr (CheckId Value 2) Must "platformModel" (pccModel config)
  , checkNonEmptyStr (CheckId Value 3) Must "platformVersion" (pccVersion config)
  , if null (pccSerial config)
      then [mkPass' (CheckId Value 4) May "platformSerial is empty (optional field)"]
      else checkStrMax (CheckId Value 4) May "platformSerial" (pccSerial config)
  ]

checkNonEmptyStr :: CheckId -> RequirementLevel -> Text -> String -> [ConfigLintResult]
checkNonEmptyStr cid level field value
  | null value =
      [ ConfigLintResult (PreflightCheck cid) level LintFail
          (field <> " must not be empty")
          (Just (ValueSuggestion field "must be a non-empty UTF8String(1..256)"))
      ]
  | length value > strmax =
      [ ConfigLintResult (ConfigOnly "G-004") Should LintWarn
          (field <> " exceeds STRMAX(" <> T.pack (show strmax) <> "). Current length: " <> T.pack (show (length value)))
          (Just (ValueSuggestion field ("should not exceed " <> T.pack (show strmax) <> " characters")))
      ]
  | otherwise =
      [ mkPass' cid level (field <> " is valid") ]

checkStrMax :: CheckId -> RequirementLevel -> Text -> String -> [ConfigLintResult]
checkStrMax cid level field value
  | length value > strmax =
      [ ConfigLintResult (ConfigOnly "G-004") Should LintWarn
          (field <> " exceeds STRMAX(" <> T.pack (show strmax) <> ")")
          (Just (ValueSuggestion field ("should not exceed " <> T.pack (show strmax) <> " characters")))
      ]
  | otherwise =
      [ mkPass' cid level (field <> " is within STRMAX") ]

-- ============================================================
-- Security Assertions checks (VAL-006~010, VAL-017, SEC-003)
-- ============================================================

checkSecurityAssertionsBase :: PlatformCertConfig -> [ConfigLintResult]
checkSecurityAssertionsBase config = case pccSecurityAssertions config of
  Nothing ->
    [ ConfigLintResult (PreflightCheck (CheckId Value 6)) Should LintWarn
        "tBBSecurityAssertions not present (recommended for Base)"
        (Just (AddField "securityAssertions" (Just "securityAssertions:\n  version: 0")))
    ]
  Just sa -> concat
    [ [mkPass' (CheckId Value 6) Should "tBBSecurityAssertions present"]
    , checkFipsLevel sa
    , checkEalLevel sa
    , checkSofRange sa
    , checkRtmType sa
    ]

checkFipsLevel :: SecurityAssertionsConfig -> [ConfigLintResult]
checkFipsLevel sa = case sacFIPSSecurityLevel sa of
  Nothing -> [mkPass' (CheckId Value 8) May "fipsLevel not present (optional)"]
  Just level
    | level >= 1 && level <= 4 ->
        [mkPass' (CheckId Value 8) May "fipsLevel in valid range"]
    | otherwise ->
        [ ConfigLintResult (PreflightCheck (CheckId Value 8)) Must LintFail
            ("fipsSecurityLevel out of range: " <> T.pack (show level))
            (Just (ValueSuggestion "fipsSecurityLevel" ("must be in range 1..4. Current value: " <> T.pack (show level))))
        ]

checkEalLevel :: SecurityAssertionsConfig -> [ConfigLintResult]
checkEalLevel sa = case sacEvalAssuranceLevel sa of
  Nothing -> [mkPass' (CheckId Value 10) May "evalAssuranceLevel not present (optional)"]
  Just level
    | level >= 1 && level <= 7 ->
        [mkPass' (CheckId Value 10) May "evalAssuranceLevel in valid range"]
    | otherwise ->
        [ ConfigLintResult (PreflightCheck (CheckId Value 10)) Must LintFail
            ("evalAssuranceLevel out of range: " <> T.pack (show level))
            (Just (ValueSuggestion "evalAssuranceLevel" ("must be in range 1..7. Current value: " <> T.pack (show level))))
        ]

checkSofRange :: SecurityAssertionsConfig -> [ConfigLintResult]
checkSofRange sa = case sacStrengthOfFunction sa of
  Nothing -> [mkPass' (CheckId Value 17) May "strengthOfFunction not present (optional)"]
  Just sof
    | sof `elem` ["basic", "medium", "high"] ->
        [mkPass' (CheckId Value 17) May "strengthOfFunction in valid range"]
    | otherwise ->
        [ ConfigLintResult (PreflightCheck (CheckId Value 17)) Must LintFail
            ("strengthOfFunction invalid: " <> T.pack sof)
            (Just (ValueSuggestion "strengthOfFunction" "must be one of \"basic\", \"medium\", \"high\""))
        ]

checkRtmType :: SecurityAssertionsConfig -> [ConfigLintResult]
checkRtmType sa = case sacRTMType sa of
  Nothing -> [mkPass' (CheckId Security 3) May "rtmType not present (optional)"]
  Just rt
    | rt `elem` ["static", "dynamic", "nonHosted", "hybrid", "physical", "virtual"] ->
        [mkPass' (CheckId Security 3) May "rtmType in valid range"]
    | otherwise ->
        [ ConfigLintResult (PreflightCheck (CheckId Security 3)) Must LintFail
            ("rtmType invalid: " <> T.pack rt)
            (Just (ValueSuggestion "rtmType" "must be one of \"static\", \"dynamic\", \"nonHosted\", \"hybrid\", \"physical\", \"virtual\""))
        ]

-- ============================================================
-- Component checks (VAL-011~013, REG-001~002)
-- ============================================================

checkComponents :: [ComponentConfig] -> [ConfigLintResult]
checkComponents [] = [ConfigLintResult (PreflightCheck (CheckId Value 11)) Must LintPass "No components to check" Nothing]
checkComponents comps = concatMap checkSingleComponent comps

checkSingleComponent :: ComponentConfig -> [ConfigLintResult]
checkSingleComponent comp = concat
  [ -- VAL-011: manufacturer and model required
    if null (ccManufacturer comp)
      then [ConfigLintResult (PreflightCheck (CheckId Value 11)) Must LintFail
              "Component manufacturer must not be empty"
              (Just (ValueSuggestion "manufacturer" "must be a non-empty string"))]
      else [mkPass' (CheckId Value 11) Must "Component manufacturer present"]
  , if null (ccModel comp)
      then [ConfigLintResult (PreflightCheck (CheckId Value 11)) Must LintFail
              "Component model must not be empty"
              (Just (ValueSuggestion "model" "must be a non-empty string"))]
      else []
  , -- VAL-013 / REG-002: componentClassValue must be 4-byte hex (8 hex chars)
    let classVal = ccClass comp
    in if length classVal /= 8 || not (all isHexChar classVal)
      then [ConfigLintResult (PreflightCheck (CheckId Value 13)) Must LintFail
              ("componentClassValue must be 8 hex digits. Current: \"" <> T.pack classVal <> "\"")
              (Just (FixFormat "componentClassValue" "8-digit hexadecimal (4 bytes)" (Just "00030003")))]
      else [mkPass' (CheckId Value 13) Must "componentClassValue is valid 4-byte hex"]
  , -- VAL-012 / REG-001: componentClassRegistry must be a known OID
    case ccComponentClass comp of
      Nothing -> []
      Just cc ->
        let reg = cccRegistry cc
        in if reg `elem` ["2.23.133.18.3.1", "2.23.133.18.3.3", "1.3.6.1.4.1"]
          then [mkPass' (CheckId Value 12) Must "componentClassRegistry is a known OID"]
          else [ConfigLintResult (PreflightCheck (CheckId Value 12)) Must LintFail
                  ("Unknown componentClassRegistry OID: " <> T.pack reg)
                  (Just (ValueSuggestion "componentClassRegistry"
                    "must be a known OID: 2.23.133.18.3.1 (TCG), 2.23.133.18.3.3 (DMTF), 1.3.6.1.4.1 (IETF PEN)"))]
  ]

isHexChar :: Char -> Bool
isHexChar c = c `elem` ("0123456789abcdefABCDEF" :: String)

-- ============================================================
-- URI reference checks (G-002/SEC-005, G-003)
-- ============================================================

checkUriReferences :: PlatformCertConfig -> [ConfigLintResult]
checkUriReferences config = concat
  [ maybe [] (checkSingleUri "platformConfigUri") (pccPlatformConfigUri config)
  , maybe [] (checkSingleUri "componentsUri") (pccComponentsUri config)
  , maybe [] (checkSingleUri "propertiesUri") (pccPropertiesUri config)
  ]

checkSingleUri :: Text -> URIReferenceConfig -> [ConfigLintResult]
checkSingleUri field uri = concat
  [ -- G-002 / SEC-005: hash pair co-existence
    case (uriHashAlgorithm uri, uriHashValue uri) of
      (Just _, Just _) -> [mkPass' (CheckId Security 5) Must "URI hash pair both present"]
      (Nothing, Nothing) -> [mkPass' (CheckId Security 5) Must "URI hash pair both absent"]
      _ -> [ConfigLintResult (PreflightCheck (CheckId Security 5)) Must LintFail
              (field <> ": hashAlgorithm and hashValue must both exist or both be absent")
              (Just (ValueSuggestion field "hashAlgorithm and hashValue must co-exist per G-002"))]
  , -- G-003: URI length
    if length (uriUri uri) > urimax
      then [ConfigLintResult (ConfigOnly "G-003") Should LintWarn
              (field <> " URI exceeds URIMAX(" <> T.pack (show urimax) <> ")")
              (Just (ValueSuggestion field ("URI should not exceed " <> T.pack (show urimax) <> " characters")))]
      else []
  ]

-- ============================================================
-- Credential field checks (STR-011~013)
-- ============================================================

checkCredentialFields :: PlatformCertConfig -> [ConfigLintResult]
checkCredentialFields config = concat
  [ -- STR-011: Platform Spec recommended for Base
    case (pccPlatformSpecMajor config, pccPlatformSpecMinor config) of
      (Just _, Just _) -> [mkPass' (CheckId Structural 11) Should "TCG Platform Specification present"]
      _ -> [ConfigLintResult (PreflightCheck (CheckId Structural 11)) Should LintWarn
              "TCG Platform Specification not set (recommended for Base)"
              (Just (AddField "platformSpecMajor/Minor/Revision" (Just "platformSpecMajor: 2\nplatformSpecMinor: 0\nplatformSpecRevision: 164")))]
  , -- STR-012: Credential Type (implicitly determined by config type for Base)
    [mkPass' (CheckId Structural 12) Should "Credential type is Base (determined by config type)"]
  , -- STR-013: Credential Spec recommended for Base
    case (pccCredentialSpecMajor config, pccCredentialSpecMinor config) of
      (Just _, Just _) -> [mkPass' (CheckId Structural 13) Should "TCG Credential Specification present"]
      _ -> [ConfigLintResult (PreflightCheck (CheckId Structural 13)) Should LintWarn
              "TCG Credential Specification not set (recommended for Base)"
              (Just (AddField "credentialSpecMajor/Minor/Revision" (Just "credentialSpecMajor: 1\ncredentialSpecMinor: 1\ncredentialSpecRevision: 13")))]
  ]

-- ============================================================
-- ManufacturerId check (VAL-005 / ERR-003)
-- ============================================================

-- | VAL-005 / ERR-003: manufacturerId is valid OID format (optional).
checkManufacturerId :: PlatformCertConfig -> [ConfigLintResult]
checkManufacturerId config = case pccManufacturerId config of
  Nothing -> [mkPass' (CheckId Value 5) May "manufacturerId not present (optional)"]
  Just oid
    | isValidOidFormat oid ->
        [mkPass' (CheckId Value 5) May "manufacturerId is valid OID format"]
    | otherwise ->
        [ ConfigLintResult (PreflightCheck (CheckId Value 5)) May LintWarn
            ("manufacturerId is not valid OID format: " <> T.pack oid)
            (Just (ValueSuggestion "manufacturerId" "should be dot-notation OID (e.g., \"1.3.6.1.4.1.99999\")"))
        ]

isValidOidFormat :: String -> Bool
isValidOidFormat s =
  not (null s) && all (\c -> c == '.' || (c >= '0' && c <= '9')) s
    && not ('.' == head s) && not ('.' == last s)
    && ".." `notSubstringOf` s
  where
    notSubstringOf sub str = not $ any (isPrefixOf sub) (tails str)
    isPrefixOf [] _ = True
    isPrefixOf _ [] = False
    isPrefixOf (x:xs) (y:ys) = x == y && isPrefixOf xs ys
    tails [] = [[]]
    tails xs@(_:xs') = xs : tails xs'

-- ============================================================
-- Config-only checks (CFG-001~003)
-- ============================================================

checkConfigOnlyBase :: PlatformCertConfig -> [ConfigLintResult]
checkConfigOnlyBase config = concat
  [ checkDuplicateSerials (pccComponents config)
  , checkUtf8Encodability config
  , checkRegistryRange (pccComponents config)
  ]

-- | CFG-002: All string fields are UTF8-encodable.
checkUtf8Encodability :: PlatformCertConfig -> [ConfigLintResult]
checkUtf8Encodability config =
  let fields = [ ("manufacturer", pccManufacturer config)
               , ("model", pccModel config)
               , ("version", pccVersion config)
               , ("serial", pccSerial config)
               ]
      checkField (name, val) =
        if all isValidUtf8Char val
          then Nothing
          else Just $ ConfigLintResult (ConfigOnly "CFG-002") Must LintFail
                 (T.pack name <> " contains non-UTF8-encodable characters")
                 (Just (ValueSuggestion (T.pack name) "must contain only valid UTF-8 characters"))
      failures = mapMaybe checkField fields
  in if null failures
    then [ConfigLintResult (ConfigOnly "CFG-002") Must LintPass "All string fields are UTF8-encodable" Nothing]
    else failures

isValidUtf8Char :: Char -> Bool
isValidUtf8Char c = c /= '\xFFFD' && c /= '\xFFFE' && c /= '\xFFFF'

-- | CFG-003: componentClassValue within registry-defined range.
checkRegistryRange :: [ComponentConfig] -> [ConfigLintResult]
checkRegistryRange [] = []
checkRegistryRange comps =
  let checks = concatMap checkOneRegistry comps
  in if null checks
    then [ConfigLintResult (ConfigOnly "CFG-003") Should LintPass "All component class values within known ranges" Nothing]
    else checks
  where
    checkOneRegistry comp = case ccComponentClass comp of
      Nothing -> []
      Just cc ->
        let reg = cccRegistry cc
        in if isKnownRegistry reg
          then []
          else [ConfigLintResult (ConfigOnly "CFG-003") Should LintWarn
                  ("Unknown component class registry OID: " <> T.pack reg)
                  (Just (ValueSuggestion "componentClassRegistry"
                    "should be a known registry: 2.23.133.18.3.1 (TCG), 2.23.133.18.3.3 (DMTF), 1.3.6.1.4.1 (IETF PEN)"))]
    isKnownRegistry r = r `elem`
      [ "2.23.133.18.3.1"  -- TCG
      , "2.23.133.18.3.3"  -- DMTF
      , "1.3.6.1.4.1"      -- IETF Private Enterprise Numbers
      ]

checkDuplicateSerials :: [ComponentConfig] -> [ConfigLintResult]
checkDuplicateSerials comps =
  let serials = mapMaybe ccSerial comps
      duplicates = serials List.\\ List.nub serials
  in if null duplicates
    then [ConfigLintResult (ConfigOnly "CFG-001") Should LintPass "No duplicate component serials" Nothing]
    else [ConfigLintResult (ConfigOnly "CFG-001") Should LintWarn
            ("Duplicate component serial numbers found: " <> T.pack (show (List.nub duplicates)))
            (Just (ValueSuggestion "component serial" "should be unique across all components"))]

-- ============================================================
-- Delta-specific checks
-- ============================================================

checkDeltaPlatformStrings :: DeltaCertConfig -> [ConfigLintResult]
checkDeltaPlatformStrings config = concat
  [ checkNonEmptyStr (CheckId Value 1) Must "platformManufacturerStr" (dccManufacturer config)
  , checkNonEmptyStr (CheckId Value 2) Must "platformModel" (dccModel config)
  , checkNonEmptyStr (CheckId Value 3) Must "platformVersion" (dccVersion config)
  ]

-- | Check that Delta config does not contain prohibited fields.
-- Note: DeltaCertConfig structurally lacks securityAssertions and platformSpec fields,
-- so these checks always pass. If DeltaCertConfig is ever extended with these fields,
-- this function MUST be updated to inspect them.
checkDeltaProhibited :: DeltaCertConfig -> [ConfigLintResult]
checkDeltaProhibited _config =
  [ mkPass' (CheckId Security 1) MustNot "Delta config does not include tBBSecurityAssertions"
  , mkPass' (CheckId Security 2) MustNot "Delta config does not include TCGPlatformSpecification"
  ]

-- | DLT-009~012: Delta manufacturer/model/version must match Base.
-- When no Base certificate is available, these checks are skipped.
checkDeltaIdentityMatch :: DeltaCertConfig -> Maybe SignedPlatformCertificate -> [ConfigLintResult]
checkDeltaIdentityMatch _config Nothing =
  [ ConfigLintResult (ConfigOnly "DLT-009") Must LintPass
      "Delta identity match skipped (no Base certificate provided)" Nothing
  ]
checkDeltaIdentityMatch config (Just baseCert) =
  case getPlatformInfo baseCert of
    Nothing ->
      [ ConfigLintResult (ConfigOnly "DLT-009") Must LintPass
          "Delta identity match skipped (cannot extract Base platform info)" Nothing
      ]
    Just pi' ->
      let baseMfr = BC.unpack (piManufacturer pi')
          baseMod = BC.unpack (piModel pi')
          baseVer = BC.unpack (piVersion pi')
      in concat
        [ if dccManufacturer config == baseMfr
            then [ConfigLintResult (ConfigOnly "DLT-009") Must LintPass "Delta manufacturer matches Base" Nothing]
            else [ConfigLintResult (ConfigOnly "DLT-009") Must LintFail
                    ("Delta manufacturer \"" <> T.pack (dccManufacturer config) <> "\" does not match Base \"" <> T.pack baseMfr <> "\"")
                    (Just (ValueSuggestion "manufacturer" ("must match Base: \"" <> T.pack baseMfr <> "\"")))]
        , if dccModel config == baseMod
            then [ConfigLintResult (ConfigOnly "DLT-010") Must LintPass "Delta model matches Base" Nothing]
            else [ConfigLintResult (ConfigOnly "DLT-010") Must LintFail
                    ("Delta model \"" <> T.pack (dccModel config) <> "\" does not match Base \"" <> T.pack baseMod <> "\"")
                    (Just (ValueSuggestion "model" ("must match Base: \"" <> T.pack baseMod <> "\"")))]
        , if dccVersion config == baseVer
            then [ConfigLintResult (ConfigOnly "DLT-011") Must LintPass "Delta version matches Base" Nothing]
            else [ConfigLintResult (ConfigOnly "DLT-011") Must LintFail
                    ("Delta version \"" <> T.pack (dccVersion config) <> "\" does not match Base \"" <> T.pack baseVer <> "\"")
                    (Just (ValueSuggestion "version" ("must match Base: \"" <> T.pack baseVer <> "\"")))]
        ]

checkDeltaComponents :: [ComponentConfig] -> [ConfigLintResult]
checkDeltaComponents comps = concatMap checkDeltaComponentStatus comps

checkDeltaComponentStatus :: ComponentConfig -> [ConfigLintResult]
checkDeltaComponentStatus comp = case ccStatus comp of
  Nothing ->
    [ ConfigLintResult (PreflightCheck (CheckId Delta 8)) Must LintFail
        ("Component \"" <> T.pack (ccModel comp) <> "\" missing status field (required in Delta)")
        (Just (AddField "status" (Just "status: \"ADDED\"")))
    ]
  Just status
    | status `elem` ["ADDED", "MODIFIED", "REMOVED"] ->
        [mkPass' (CheckId Delta 6) Must "Component status is valid"]
    | otherwise ->
        [ ConfigLintResult (PreflightCheck (CheckId Delta 6)) Must LintFail
            ("Invalid status: \"" <> T.pack status <> "\"")
            (Just (ValueSuggestion "status" ("must be one of \"ADDED\", \"MODIFIED\", \"REMOVED\". Current value: \"" <> T.pack status <> "\"")))
        ]

-- ============================================================
-- Display
-- ============================================================

displayLintResults :: [ConfigLintResult] -> IO ()
displayLintResults results = mapM_ displayOne results
  where
    displayOne r = do
      let tag = case clrStatus r of
            LintPass -> "[PASS]"
            LintFail -> "[FAIL]"
            LintWarn -> "[WARN]"
          checkStr = case clrCheckId r of
            PreflightCheck cid -> T.pack (show cid)
            ConfigOnly t -> t
      putStrLn $ "  " ++ T.unpack tag ++ " " ++ T.unpack checkStr ++ "  " ++ T.unpack (clrMessage r)
      case clrSuggestion r of
        Nothing -> return ()
        Just sug -> putStrLn $ "    -> " ++ T.unpack (formatSuggestion sug)

-- ============================================================
-- Helpers
-- ============================================================

mkPass' :: CheckId -> RequirementLevel -> Text -> ConfigLintResult
mkPass' cid level msg = ConfigLintResult (PreflightCheck cid) level LintPass msg Nothing
