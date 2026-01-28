-- |
-- Module      : Data.X509.TCG.Validation.Cache
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Validation Library
-- Stability   : experimental
-- Portability : unknown
--
-- Caching mechanism for TCG Platform Certificate validation results.
-- This module provides caching functionality similar to crypton-x509-validation
-- but specialized for Platform Certificates.
module Data.X509.TCG.Validation.Cache
  ( -- * Cache Types
    TCGValidationCache (..),
    TCGValidationCacheResult (..),
    
    -- * Cache Callbacks  
    TCGValidationCacheQueryCallback,
    TCGValidationCacheAddCallback,
    
    -- * Cache Implementations
    defaultTCGValidationCache,
    exceptionTCGValidationCache,
    tofuTCGValidationCache,
    
    -- * Fingerprint Support
    TCGFingerprint (..),
    getTCGFingerprint,
  )
where

import Control.Concurrent (newMVar, readMVar, modifyMVar_)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Default (Default(..))
import Data.X509.TCG.Validation.Types
import Data.X509.TCG (SignedPlatformCertificate, SignedDeltaPlatformCertificate)
import Crypto.Hash (SHA256(..), hashWith)
import Data.ByteArray (convert)

-- | TCG Platform Certificate fingerprint for cache identification
newtype TCGFingerprint = TCGFingerprint ByteString
  deriving (Show, Eq, Ord)

-- | Result of a TCG validation cache query
data TCGValidationCacheResult
  = -- | Cache allows this certificate to pass validation
    TCGValidationCachePass
  | -- | Cache denies this certificate for further validation
    TCGValidationCacheDenied String
  | -- | Unknown certificate in cache
    TCGValidationCacheUnknown
  deriving (Show, Eq)

-- | TCG validation cache query callback type
type TCGValidationCacheQueryCallback =
     TCGServiceID
  -- ^ Platform/service identification
  -> TCGFingerprint  
  -- ^ Fingerprint of the certificate
  -> Either SignedPlatformCertificate SignedDeltaPlatformCertificate
  -- ^ The certificate being validated
  -> IO TCGValidationCacheResult
  -- ^ Validation cache result

-- | TCG validation cache add callback type  
type TCGValidationCacheAddCallback =
     TCGServiceID
  -- ^ Platform/service identification
  -> TCGFingerprint
  -- ^ Fingerprint of the certificate
  -> Either SignedPlatformCertificate SignedDeltaPlatformCertificate  
  -- ^ The certificate to add to cache
  -> IO ()

-- | TCG validation cache with query and add callbacks
data TCGValidationCache = TCGValidationCache
  { tcgCacheQuery :: TCGValidationCacheQueryCallback
  -- ^ Cache querying callback
  , tcgCacheAdd :: TCGValidationCacheAddCallback  
  -- ^ Cache adding callback
  }

-- | Default TCG validation cache (no caching)
defaultTCGValidationCache :: TCGValidationCache
defaultTCGValidationCache = exceptionTCGValidationCache []

instance Default TCGValidationCache where
  def = defaultTCGValidationCache

-- | Create a TCG validation cache with specific exceptions
--
-- This creates a cache that allows specific certificates based on
-- their fingerprints and service IDs. No new certificates will be
-- added to the cache after creation.
--
-- This is useful for allowing known self-signed certificates or
-- certificates that would otherwise fail validation but are
-- explicitly trusted in specific contexts.
exceptionTCGValidationCache :: [(TCGServiceID, TCGFingerprint)] -> TCGValidationCache
exceptionTCGValidationCache exceptions =
  TCGValidationCache
    { tcgCacheQuery = queryExceptionList exceptions
    , tcgCacheAdd = \_ _ _ -> return ()  -- No additions allowed
    }

-- | Trust-on-first-use (TOFU) TCG validation cache
--
-- This cache starts with an optional list of exceptions and then
-- adds any successfully validated certificate to the cache. This
-- prevents future changes to certificate fingerprints for the same
-- service ID.
--
-- This is useful for environments where certificate changes should
-- be detected and flagged.
tofuTCGValidationCache 
  :: [(TCGServiceID, TCGFingerprint)]  -- ^ Initial exceptions
  -> IO TCGValidationCache
tofuTCGValidationCache initialExceptions = do
  cacheVar <- newMVar initialExceptions
  return $ TCGValidationCache
    { tcgCacheQuery = \serviceId fingerprint _cert -> do
        cache <- readMVar cacheVar
        queryExceptionList cache serviceId fingerprint _cert
    , tcgCacheAdd = \serviceId fingerprint _cert -> do
        modifyMVar_ cacheVar $ \cache -> 
          return ((serviceId, fingerprint) : cache)
    }

-- | Query function for exception-based caches
queryExceptionList 
  :: [(TCGServiceID, TCGFingerprint)] 
  -> TCGValidationCacheQueryCallback
queryExceptionList exceptions serviceId fingerprint _cert = return $
  case lookup serviceId exceptions of
    Nothing -> TCGValidationCacheUnknown
    Just expectedFingerprint
      | fingerprint == expectedFingerprint -> TCGValidationCachePass
      | otherwise -> TCGValidationCacheDenied $
          "Expected fingerprint " ++ show expectedFingerprint ++ 
          " but got " ++ show fingerprint ++ 
          " for service " ++ show serviceId

-- | Generate SHA256 fingerprint for a TCG certificate
getTCGFingerprint :: Either SignedPlatformCertificate SignedDeltaPlatformCertificate -> TCGFingerprint
getTCGFingerprint cert = TCGFingerprint $ convert $ hashWith SHA256 certBytes
  where
    certBytes = case cert of
      Left platformCert -> encodeTCGCertificate platformCert
      Right deltaCert -> encodeTCGCertificate deltaCert

-- | Encode TCG certificate to bytes for fingerprinting
-- Note: This is a placeholder - actual implementation would use
-- the ASN.1 encoding functions from the main tcg-platform-cert library
encodeTCGCertificate :: (Show a) => a -> ByteString
encodeTCGCertificate cert = 
  -- Temporary implementation using show - should be replaced with proper ASN.1 encoding
  B.pack $ map (fromIntegral . fromEnum) $ take 256 $ show cert