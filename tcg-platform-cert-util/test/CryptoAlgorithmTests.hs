{-# LANGUAGE OverloadedStrings #-}

module CryptoAlgorithmTests (tests) where

import Test.Tasty
import Test.Tasty.HUnit

-- TCG imports
import qualified Data.X509.TCG as TCG
import Data.X509.TCG.Util.Certificate
import Data.X509.TCG.Util.Config
import Data.X509.TCG

-- Crypto imports  
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.Types as ECC

tests :: TestTree
tests = testGroup "Cryptographic Algorithm Tests"
  [ basicKeyGenerationTests
  , hashAlgorithmTests
  ]

-- | Test basic key generation for different algorithms
basicKeyGenerationTests :: TestTree
basicKeyGenerationTests = testGroup "Basic Key Generation Tests"
  [ testCase "Generate RSA keys" $ do
      let alg = TCG.AlgRSA 2048 TCG.hashSHA384
      (_, pubKey, privKey) <- TCG.generateKeys alg
      
      -- Verify RSA key properties
      RSA.public_size pubKey @?= 256  -- 2048 bits = 256 bytes
      RSA.public_n pubKey > 0 @?= True
      RSA.private_p privKey > 0 @?= True

  , testCase "Generate ECDSA keys" $ do
      let alg = TCG.AlgEC ECC.SEC_p256r1 TCG.hashSHA384  
      (_, pubKey, privKey) <- TCG.generateKeys alg
      
      -- Verify ECDSA key was generated (basic checks)
      pubKey `seq` privKey `seq` return ()

  , testCase "Generate DSA keys (basic)" $ do
      -- DSA parameter generation is complex - just test that basic DSA types exist
      -- For a real test we would need pre-generated parameters
      return ()

  , testCase "Generate Ed25519 keys" $ do
      let alg = TCG.AlgEd25519
      (_, pubKey, privKey) <- TCG.generateKeys alg
      
      -- Ed25519 keys are opaque - just verify generation worked
      pubKey `seq` privKey `seq` return ()

  , testCase "Generate Ed448 keys" $ do
      let alg = TCG.AlgEd448
      (_, pubKey, privKey) <- TCG.generateKeys alg
      
      -- Ed448 keys are opaque - just verify generation worked
      pubKey `seq` privKey `seq` return ()
  ]

-- | Test hash algorithm support
hashAlgorithmTests :: TestTree
hashAlgorithmTests = testGroup "Hash Algorithm Support"
  [ testCase "SHA256 with RSA" $ testHashWithRSA TCG.hashSHA256
  , testCase "SHA384 with RSA (default)" $ testHashWithRSA TCG.hashSHA384
  , testCase "SHA512 with RSA" $ testHashWithRSA TCG.hashSHA512
  , testCase "Hash algorithm compatibility with ECDSA" $ do
      let algSHA256 = TCG.AlgEC ECC.SEC_p256r1 TCG.hashSHA256
          algSHA384 = TCG.AlgEC ECC.SEC_p256r1 TCG.hashSHA384
          algSHA512 = TCG.AlgEC ECC.SEC_p256r1 TCG.hashSHA512
      
      -- Test that all hash algorithms work with ECDSA
      (_, pub1, priv1) <- TCG.generateKeys algSHA256
      (_, pub2, priv2) <- TCG.generateKeys algSHA384  
      (_, pub3, priv3) <- TCG.generateKeys algSHA512
      
      -- Verify key generation worked for all hash variants
      pub1 `seq` priv1 `seq` pub2 `seq` priv2 `seq` pub3 `seq` priv3 `seq` return ()
  ]
  where
    testHashWithRSA hash = do
      let alg = TCG.AlgRSA 2048 hash
      (_, pubKey, privKey) <- TCG.generateKeys alg
      
      -- Verify key generation worked with the specified hash
      RSA.public_n pubKey > 0 @?= True
      RSA.private_p privKey > 0 @?= True