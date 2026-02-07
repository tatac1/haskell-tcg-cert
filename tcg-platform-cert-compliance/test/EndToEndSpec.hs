{-# LANGUAGE OverloadedStrings #-}

-- | End-to-end compliance tests using real certificates.
module EndToEndSpec (tests) where

import Control.Monad (filterM)
import qualified Data.ByteString as B
import Data.PEM (pemParseBS, pemContent)
import System.Directory (doesFileExist)
import Test.Tasty
import Test.Tasty.HUnit

import Data.X509.TCG.Platform (SignedPlatformCertificate, decodeSignedPlatformCertificate)
import Data.X509.TCG.Compliance.Check (runComplianceTest, defaultComplianceOptions)
import Data.X509.TCG.Compliance.Result (ComplianceResult(..))

tests :: TestTree
tests = testGroup "End-to-end compliance"
  [ testCase "tcg-example1.pem compliance run (no errors)" $ do
      cert <- loadPemCert "tcg-example1.pem"
      result <- runComplianceTest cert defaultComplianceOptions
      resTotalErrors result @?= 0

  , testCase "tcg-example2.pem compliance run (no errors)" $ do
      cert <- loadPemCert "tcg-example2.pem"
      result <- runComplianceTest cert defaultComplianceOptions
      resTotalErrors result @?= 0
  ]

loadPemCert :: FilePath -> IO SignedPlatformCertificate
loadPemCert name = do
  path <- locateCert name
  bs <- B.readFile path
  case pemParseBS bs of
    Left err -> assertFailure ("PEM parse failed for " <> path <> ": " <> err)
    Right [] -> assertFailure ("No PEM blocks found in " <> path)
    Right (pem:_) ->
      case decodeSignedPlatformCertificate (pemContent pem) of
        Left err -> assertFailure ("Decode platform certificate failed for " <> path <> ": " <> err)
        Right cert -> pure cert

locateCert :: FilePath -> IO FilePath
locateCert name = do
  let candidates = ["test-certs/" <> name, "../test-certs/" <> name]
  found <- filterM doesFileExist candidates
  case found of
    (p:_) -> pure p
    [] -> assertFailure ("Certificate not found: " <> name)
