{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.ChainCompliance
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Certificate chain compliance checks (CHAIN-001 to CHAIN-005).
--
-- These checks validate integrity across a chain of certificates
-- (one Base + N Delta certificates), separate from the per-certificate
-- CHN-001~005 checks in "Data.X509.TCG.Compliance.Chain".

module Data.X509.TCG.Compliance.ChainCompliance
  ( -- * Result Types
    ChainCheckResult (..)
  , PlatformState (..)
  , ComponentEntry (..)
  , CompId
    -- * Individual Checks
  , checkChainIdentity       -- ^ CHAIN-001
  , checkChainOrdering       -- ^ CHAIN-002
  , checkStateTransitions    -- ^ CHAIN-003
  , checkHolderChain         -- ^ CHAIN-004
  , computeFinalState        -- ^ CHAIN-005
  ) where

#if !MIN_VERSION_base(4,20,0)
import Data.List (foldl')
#endif
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Data.X509.TCG.Compliance.Types (ComplianceMode(..), RequirementLevel(..))
import Data.X509.TCG.Compliance.Result (CheckStatus(..))
import Data.X509.TCG.Platform (ComponentStatus(..))

-- | Result of a single chain-level check.
data ChainCheckResult = ChainCheckResult
  { ccrCheckId  :: !Text             -- ^ "CHAIN-001" etc.
  , ccrLevel    :: !RequirementLevel
  , ccrStatus   :: !CheckStatus      -- ^ Pass / Fail / Skip / Error
  , ccrMessage  :: !Text
  } deriving (Show, Eq)

-- | Final platform state after applying all Deltas.
data PlatformState = PlatformState
  { psComponents :: ![ComponentEntry]
  , psDeltaCount :: !Int
  } deriving (Show, Eq)

-- | A component in the final platform state.
data ComponentEntry = ComponentEntry
  { ceManufacturer :: !B.ByteString
  , ceModel        :: !B.ByteString
  , ceSerial       :: !(Maybe B.ByteString)
  } deriving (Show, Eq)

-- | Component identity for matching: (manufacturer, model, serial)
type CompId = (B.ByteString, B.ByteString, Maybe B.ByteString)

-- ============================================================
-- CHAIN-001: Platform identity consistency
-- ============================================================

-- | Check that all Delta certificates share the same manufacturer/model/version as the Base.
-- Input: Base identity (manufacturer, model, version) and list of Delta identities.
checkChainIdentity :: (B.ByteString, B.ByteString, B.ByteString)
                   -> [(B.ByteString, B.ByteString, B.ByteString)]
                   -> ChainCheckResult
checkChainIdentity (baseMfr, baseMod, baseVer) deltaIdentities =
  let mismatches = filter (not . matches) (zip [1..] deltaIdentities)
      matches (_, (mfr, model, ver)) = mfr == baseMfr && model == baseMod && ver == baseVer
  in case mismatches of
    [] -> ChainCheckResult "CHAIN-001" Must Pass
            "Platform identity consistent across chain"
    ((idx, (mfr, model, ver)):_) -> ChainCheckResult "CHAIN-001" Must
            (Fail $ "Delta " <> T.pack (show (idx :: Int)) <> " identity mismatch: "
              <> "manufacturer=" <> T.pack (BC.unpack mfr)
              <> " model=" <> T.pack (BC.unpack model)
              <> " version=" <> T.pack (BC.unpack ver))
            ("Delta certificates must match Base identity per DLT-009~011")

-- ============================================================
-- CHAIN-002: Serial number ordering
-- ============================================================

-- | Check that Delta serial numbers are strictly ascending (no duplicates).
checkChainOrdering :: [Integer] -> ChainCheckResult
checkChainOrdering serials =
  let pairs = zip serials (drop 1 serials)
      violations = filter (\(a, b) -> a >= b) pairs
  in case violations of
    [] -> ChainCheckResult "CHAIN-002" Should Pass
            "Delta serial numbers are strictly ascending"
    ((a, b):_) -> ChainCheckResult "CHAIN-002" Should
            (Fail $ "Non-ascending serial numbers: " <> T.pack (show a) <> " >= " <> T.pack (show b))
            "Delta certificates should have ascending serial numbers for deterministic ordering"

-- ============================================================
-- CHAIN-003: State transitions
-- ============================================================

-- | Tracked component state during chain traversal.
data TrackedComponent = TrackedComponent
  { tcId     :: !CompId
  , tcState  :: !TrackState
  } deriving (Show, Eq)

data TrackState
  = Present       -- ^ In Base or re-added
  | Added         -- ^ Added by a Delta
  | Removed       -- ^ Removed by a Delta
  deriving (Show, Eq)

-- | Check that all component state transitions in the chain are valid.
-- Input: Base components and list of Delta component changes per Delta.
checkStateTransitions :: [CompId]
                      -> [[(CompId, ComponentStatus)]]
                      -> ComplianceMode
                      -> ChainCheckResult
-- Note: _mode is accepted for future use. Currently REMOVED->ADDED re-add
-- is allowed in both modes; StrictV11 behavior is TBD.
checkStateTransitions baseComps deltaChains _mode =
  let initialState = map (\cid -> TrackedComponent cid Present) baseComps
      result = foldl' applyDelta (Right initialState) deltaChains
  in case result of
    Right _ -> ChainCheckResult "CHAIN-003" Must Pass
                 "Component state transitions are valid"
    Left err -> ChainCheckResult "CHAIN-003" Must
                 (Fail err)
                 "Invalid component state transition detected"

-- | Apply one Delta's component changes to the tracked state.
applyDelta :: Either Text [TrackedComponent]
           -> [(CompId, ComponentStatus)]
           -> Either Text [TrackedComponent]
applyDelta (Left err) _ = Left err
applyDelta (Right tracked) changes = foldl' applySingle (Right tracked) changes

-- | Apply a single component change.
applySingle :: Either Text [TrackedComponent]
            -> (CompId, ComponentStatus)
            -> Either Text [TrackedComponent]
applySingle (Left err) _ = Left err
applySingle (Right tracked) (cid, status) =
  let existing = lookup' cid tracked
  in case (existing, status) of
    -- Valid: ADDED for non-existent component
    (Nothing, ComponentAdded) ->
      Right (tracked ++ [TrackedComponent cid Added])

    -- Invalid: MODIFIED for non-existent component
    (Nothing, ComponentModified) ->
      Left $ "Cannot MODIFY non-existent component: " <> compIdText cid

    -- Invalid: REMOVED for non-existent component
    (Nothing, ComponentRemoved) ->
      Left $ "Cannot REMOVE non-existent component: " <> compIdText cid

    -- Valid: MODIFIED for present or added component
    (Just tc, ComponentModified)
      | tcState tc `elem` [Present, Added] ->
          Right (updateState cid Present tracked)
      | otherwise ->
          Left $ "Cannot MODIFY component in state " <> T.pack (show (tcState tc)) <> ": " <> compIdText cid

    -- Valid: REMOVED for present or added component
    (Just tc, ComponentRemoved)
      | tcState tc `elem` [Present, Added] ->
          Right (updateState cid Removed tracked)
      | otherwise ->
          Left $ "Cannot REMOVE component in state " <> T.pack (show (tcState tc)) <> ": " <> compIdText cid

    -- Valid: ADDED for removed component (re-add, OperationalCompatibility)
    (Just tc, ComponentAdded)
      | tcState tc == Removed ->
          Right (updateState cid Added tracked)
      -- Invalid: duplicate ADDED
      | otherwise ->
          Left $ "Cannot ADD already-present component: " <> compIdText cid

    -- ComponentUnchanged: no state change needed
    (Nothing, ComponentUnchanged) -> Right tracked
    (Just _, ComponentUnchanged) -> Right tracked

lookup' :: CompId -> [TrackedComponent] -> Maybe TrackedComponent
lookup' cid = foldr (\tc acc -> if tcId tc == cid then Just tc else acc) Nothing

updateState :: CompId -> TrackState -> [TrackedComponent] -> [TrackedComponent]
updateState cid newState = map (\tc -> if tcId tc == cid then tc { tcState = newState } else tc)

compIdText :: CompId -> Text
compIdText (mfr, model, mSerial) =
  T.pack (BC.unpack mfr) <> "/" <> T.pack (BC.unpack model)
    <> maybe "" (\s -> "/" <> T.pack (BC.unpack s)) mSerial

-- ============================================================
-- CHAIN-004: Holder reference chain validation
-- ============================================================

-- | Check that each Delta certificate's holder references a valid
-- certificate in the chain (Base or a preceding Delta).
-- Input: Base serial number and list of (Delta serial, Delta holder serial) pairs.
checkHolderChain :: Integer -> [(Integer, Integer)] -> ChainCheckResult
checkHolderChain baseSerial deltaHolders =
  let check' _ [] = Nothing
      check' validSerials ((deltaSerial, holderSerial):rest)
        | holderSerial `elem` validSerials =
            check' (deltaSerial : validSerials) rest
        | otherwise =
            Just $ "Delta (serial=" <> T.pack (show deltaSerial)
              <> ") references unknown holder serial " <> T.pack (show holderSerial)
      result = check' [baseSerial] deltaHolders
  in case result of
    Nothing -> ChainCheckResult "CHAIN-004" Must Pass
                "All Delta holder references are valid"
    Just err -> ChainCheckResult "CHAIN-004" Must
                (Fail err)
                "Each Delta must reference Base or a preceding Delta as holder"

-- ============================================================
-- CHAIN-005: Final platform state
-- ============================================================

-- | Compute the final platform state after applying all Deltas.
computeFinalState :: [CompId]
                  -> [[(CompId, ComponentStatus)]]
                  -> PlatformState
computeFinalState baseComps deltaChains =
  let initialState = map (\cid -> TrackedComponent cid Present) baseComps
      finalTracked = foldl' applyDeltaIgnoreErrors initialState deltaChains
      activeComps = [ ComponentEntry mfr model serial
                    | TrackedComponent (mfr, model, serial) st <- finalTracked
                    , st /= Removed
                    ]
  in PlatformState
    { psComponents = activeComps
    , psDeltaCount = length deltaChains
    }

-- | Apply delta changes, skipping only invalid transitions (best-effort for CHAIN-005).
applyDeltaIgnoreErrors :: [TrackedComponent] -> [(CompId, ComponentStatus)] -> [TrackedComponent]
applyDeltaIgnoreErrors tracked changes = foldl' applyOneIgnoreError tracked changes
  where
    applyOneIgnoreError t change =
      case applySingle (Right t) change of
        Right t' -> t'
        Left _   -> t  -- skip only THIS change
