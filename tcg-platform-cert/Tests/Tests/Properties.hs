{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module      : Tests.Properties
-- License     : BSD-style
-- Maintainer  : TCG Platform Certificate Library
-- Stability   : experimental
-- Portability : unknown
--
-- Common property-based testing functions for TCG Platform Certificates.
-- These functions are modeled after the x509 library's property tests.

module Tests.Properties (
  tests,
  property_unmarshall_marshall_id,
  property_encode_decode_id,
  property_marshall_idempotent,
  property_marshall_deterministic
) where

import Test.Tasty
import Test.Tasty.QuickCheck
import Data.ASN1.Types (ASN1Object(..), ASN1(..))
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.BinaryEncoding (DER(..))
import Control.Exception (SomeException, evaluate, try)
import qualified Data.ByteString as B
import Data.Either (isLeft)
import Data.Word (Word8)
import Data.X509.TCG.Platform
import Data.X509.TCG.Delta
import Data.X509.TCG.Component
import Data.X509.TCG (TBBSecurityAssertions(..), buildTBBSecurityAssertionsAttr, oidToContentBytes)
import Data.X509.Attribute (Attribute(..))
import Tests.Arbitrary(genIA5String)

-- | Property test for ASN.1 marshalling/unmarshalling roundtrip
--
-- This test verifies that for any object of type 'o' that implements ASN1Object:
-- 1. The object can be marshalled to ASN.1 using toASN1
-- 2. The resulting ASN.1 can be unmarshalled using fromASN1  
-- 3. The unmarshalled object equals the original object
-- 4. No ASN.1 data remains after parsing (complete consumption)
--
-- This property is essential for ensuring data integrity when storing
-- and retrieving TCG certificates in ASN.1 DER format.
property_unmarshall_marshall_id :: (Show o, Arbitrary o, ASN1Object o, Eq o) => o -> Bool
property_unmarshall_marshall_id o =
  case got of
    Right (gotObject, [])
      | gotObject == o -> True
      | otherwise ->
        error ("object is different: " ++ show gotObject ++ " expecting " ++ show o)
    Right (gotObject, l) ->
      error
        ( "state remaining: "
            ++ show l
            ++ " marshalled: "
            ++ show oMarshalled
            ++ " parsed: "
            ++ show gotObject
        )
    Left e ->
      error
        ( "parsing failed: "
            ++ show e
            ++ " object: "
            ++ show o
            ++ " marshalled as: "
            ++ show oMarshalled
        )
  where
    got = fromASN1 oMarshalled
    oMarshalled = toASN1 o []

-- | Property test for ASN.1 marshalling/unmarshalling with custom parser
--
-- This variant allows testing with custom encode/decode functions
-- instead of the standard ASN1Object instance.
property_encode_decode_id :: (Show o, Eq o) 
                         => (o -> [ASN1])           -- ^ Encoder function
                         -> ([ASN1] -> Either String (o, [ASN1]))  -- ^ Decoder function
                         -> o                       -- ^ Test object
                         -> Bool
property_encode_decode_id encoder decoder o =
  case decoder encoded of
    Right (decoded, [])
      | decoded == o -> True
      | otherwise ->
        error ("decoded object differs: " ++ show decoded ++ " expecting " ++ show o)
    Right (decoded, remaining) ->
      error ("leftover data: " ++ show remaining ++ " decoded: " ++ show decoded)
    Left e ->
      error ("decode failed: " ++ show e ++ " encoded: " ++ show encoded)
  where
    encoded = encoder o

-- | Property test for idempotent marshalling
--
-- This test verifies that marshalling an object multiple times
-- produces the same ASN.1 representation.
property_marshall_idempotent :: (ASN1Object o) => o -> Bool
property_marshall_idempotent o = 
  toASN1 o [] == toASN1 o []

-- | Property test for marshalling determinism
--
-- This test verifies that the same object always produces
-- the same ASN.1 representation (deterministic encoding).
property_marshall_deterministic :: (ASN1Object o, Eq o) => o -> o -> Bool
property_marshall_deterministic o1 o2
  | o1 == o2  = toASN1 o1 [] == toASN1 o2 []
  | otherwise = True  -- Different objects may have different encodings

-- | Test suite for ASN.1 marshalling/unmarshalling properties
tests :: TestTree
tests = testGroup "ASN.1 Marshalling Properties"
  [ testGroup "Platform Certificate Types"
    [ -- Note: These tests require complete ASN1Object implementations
      -- Currently most ASN1Object instances have placeholder fromASN1 implementations
      
      -- Example test structure (commented out until ASN1Object instances are fully implemented):
      -- testProperty "PlatformCertificateInfo roundtrip" $
      --   property_unmarshall_marshall_id @PlatformCertificateInfo
      
      testGroup "Basic Data Types"
        [ testProperty "TPMVersion marshalling idempotent" $
            property_marshall_idempotent @TPMVersion
        , testProperty "TPMVersion roundtrip" $
            property_unmarshall_marshall_id @TPMVersion
        , testProperty "TPMSpecification marshalling idempotent" $ 
            property_marshall_idempotent @TPMSpecification
        , testProperty "TPMSpecification roundtrip" $
            property_unmarshall_marshall_id @TPMSpecification
        , testProperty "ComponentStatus marshalling idempotent" $
            property_marshall_idempotent @ComponentStatus
        , testProperty "ComponentStatus roundtrip" $
            property_unmarshall_marshall_id @ComponentStatus
        , testProperty "ComponentAddress marshalling idempotent" $
            property_marshall_idempotent @ComponentAddress
        , testProperty "ComponentAddress roundtrip" $
            property_unmarshall_marshall_id @ComponentAddress
        , testProperty "ComponentAddressType marshalling idempotent" $
            property_marshall_idempotent @ComponentAddressType
        , testProperty "ComponentAddressType roundtrip" $
            property_unmarshall_marshall_id @ComponentAddressType
        , testProperty "ComponentIdentifierV2 marshalling idempotent" $
            property_marshall_idempotent @ComponentIdentifierV2
        , testProperty "ComponentIdentifierV2 roundtrip" $
            property_unmarshall_marshall_id @ComponentIdentifierV2
        ]
    ]
  , testGroup "Delta Certificate Types" 
    [ testGroup "Basic Data Types"
        [ testProperty "DeltaOperation marshalling idempotent" $
            property_marshall_idempotent @DeltaOperation
        , testProperty "DeltaOperation roundtrip" $
            property_unmarshall_marshall_id @DeltaOperation
        , testProperty "ChangeType marshalling idempotent" $
            property_marshall_idempotent @ChangeType
        , testProperty "ChangeType roundtrip" $
            property_unmarshall_marshall_id @ChangeType
        ]
    ]
  , testGroup "Decode Size Limit Properties"
    [ testProperty "Platform decodeWithLimit rejects when limit too small" $
        \(bytes :: [Word8]) ->
          let bs = B.pack bytes
              len = B.length bs
          in if len == 0
               then True
               else isLeft (decodeSignedPlatformCertificateWithLimit (len - 1) bs)

    , testProperty "Platform decodeWithLimit matches decode when limit >= length" $
        \(bytes :: [Word8]) (NonNegative extra) -> ioProperty $ do
          let bs = B.pack bytes
              limit = B.length bs + extra
          res <- try (evaluate (decodeSignedPlatformCertificate bs))
            :: IO (Either SomeException (Either String SignedPlatformCertificate))
          case res of
            Left _ -> pure True -- ignore ill-formed inputs that throw
            Right decoded ->
              pure (decodeSignedPlatformCertificateWithLimit limit bs == decoded)

    , testProperty "Delta decodeWithLimit rejects when limit too small" $
        \(bytes :: [Word8]) ->
          let bs = B.pack bytes
              len = B.length bs
          in if len == 0
               then True
               else isLeft (decodeSignedDeltaPlatformCertificateWithLimit (len - 1) bs)

    , testProperty "Delta decodeWithLimit matches decode when limit >= length" $
        \(bytes :: [Word8]) (NonNegative extra) -> ioProperty $ do
          let bs = B.pack bytes
              limit = B.length bs + extra
          res <- try (evaluate (decodeSignedDeltaPlatformCertificate bs))
            :: IO (Either SomeException (Either String SignedDeltaPlatformCertificate))
          case res of
            Left _ -> pure True -- ignore ill-formed inputs that throw
            Right decoded ->
              pure (decodeSignedDeltaPlatformCertificateWithLimit limit bs == decoded)
    ]
  , testGroup "ASN.1 Structure Properties (IWG v1.1)"
    [ testProperty "OID VLQ cross-validation with standard library" $
        forAll genValidOID $ \arcs ->
          let contentBytes = oidToContentBytes arcs
              fullStandard = encodeASN1' DER [OID arcs]
              contentLen = B.length contentBytes
          in contentLen > 0
             && contentLen <= 127
             && B.length fullStandard == contentLen + 2
             && B.index fullStandard 0 == 0x06
             && B.index fullStandard 1 == fromIntegral contentLen
             && B.drop 2 fullStandard == contentBytes

    , testProperty "TBB version=0 omitted (DER DEFAULT)" $
        \tbb -> tbbVersion tbb == 0 ==>
          let Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
              flatVals = concat vals
          in IntVal 0 `notElem` flatVals

    , testProperty "TBB iso9000Certified=False omitted (DER DEFAULT)" $
        \tbb -> (tbbISO9000Certified tbb == Just False
              || tbbISO9000Certified tbb == Nothing) ==>
          let Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
              flatVals = concat vals
          in Boolean False `notElem` flatVals

    , testProperty "TBB iso9000Certified=True present" $
        \tbb -> tbbISO9000Certified tbb == Just True ==>
          let Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
              flatVals = concat vals
          in Boolean True `elem` flatVals

    , testProperty "TBB plus=False omitted (DER DEFAULT)" $
        \tbb -> (tbbPlus tbb == Just False || tbbPlus tbb == Nothing) ==>
          let Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
              flatVals = concat vals
          in Boolean False `notElem` flatVals

    , testProperty "TBB plus=True present (CC block active)" $
        forAll (do tbb <- arbitrary
                   ccVer <- genIA5String
                   eal <- choose (1, 7)
                   return tbb { tbbPlus = Just True
                              , tbbCCVersion = Just ccVer
                              , tbbEvalAssuranceLevel = Just eal
                              , tbbISO9000Certified = Nothing
                              , tbbFIPSPlus = Nothing }) $ \tbb ->
          let Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
              flatVals = concat vals
          in Boolean True `elem` flatVals

    , testProperty "TBB fipsPlus=False omitted (DER DEFAULT)" $
        \tbb -> (tbbFIPSPlus tbb == Just False || tbbFIPSPlus tbb == Nothing) ==>
          let Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
              flatVals = concat vals
          in Boolean False `notElem` flatVals

    , testProperty "TBB fipsPlus=True present (FIPS block active)" $
        forAll (do tbb <- arbitrary
                   fipsVer <- genIA5String
                   fipsLvl <- choose (1, 4)
                   return tbb { tbbFIPSPlus = Just True
                              , tbbFIPSVersion = Just fipsVer
                              , tbbFIPSSecurityLevel = Just fipsLvl
                              , tbbISO9000Certified = Nothing
                              , tbbPlus = Nothing }) $ \tbb ->
          let Attribute _ vals = buildTBBSecurityAssertionsAttr tbb
              flatVals = concat vals
          in Boolean True `elem` flatVals

    , testProperty "TBB encoding deterministic" $
        \(tbb :: TBBSecurityAssertions) ->
          buildTBBSecurityAssertionsAttr tbb == buildTBBSecurityAssertionsAttr tbb
    ]
  ]

-- * Valid OID generator for property tests

-- | Generate a valid OID with 2+ arcs suitable for VLQ testing
genValidOID :: Gen [Integer]
genValidOID = do
  a <- choose (0, 2 :: Integer)
  b <- if a < 2 then choose (0, 39) else choose (0, 115)  -- 40*2+115=195 < 256
  n <- choose (0, 10)  -- limit arc count for manageable DER size
  rest <- vectorOf n (choose (0, 16383 :: Integer))  -- up to 2-byte VLQ
  return (a : b : rest)
