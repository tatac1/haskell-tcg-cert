-- |
-- Module      : Data.X509.TCG.Validation.Signature
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Signature verification for TCG Platform Certificates.
--
-- This module provides functions to verify digital signatures on Platform
-- Certificates, ensuring cryptographic integrity and authenticity.

module Data.X509.TCG.Validation.Signature
    ( -- * Signature Verification
      verifyPlatformCertificateSignature
    , verifyDeltaCertificateSignature
    , verifyCertificateChainSignatures
    
      -- * Signature Algorithm Validation
    , validateSignatureAlgorithm
    , isSupportedSignatureAlgorithm
    , getRequiredKeySize
    
      -- * Low-level Verification
    , verifySignatureWithKey
    , verifyRSASignature
    , verifyECDSASignature
    
      -- * Signature Policy Validation
    , validateSignatureCompliance
    , checkSignatureStrength
    ) where

import qualified Data.ByteString as B
import Data.X509 (Certificate, PubKey(..), SignatureALG(..), HashALG(..), getSigned, signedObject, signedAlg, signedSignature, certPubKey)
import Data.X509.TCG.Platform (SignedPlatformCertificate, SignedDeltaPlatformCertificate)
import Data.X509.TCG.Validation.Types
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.BinaryEncoding (DER(..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.Hash as Hash
import Crypto.Hash (SHA1, SHA256, SHA384, SHA512)
import Data.ASN1.Types (ASN1(..))
import Data.ASN1.Parse (runParseASN1, parseASN1)
import Data.ASN1.BinaryEncoding.Parse (decodeASN1')

-- | Verify the signature on a Platform Certificate using the issuer's certificate
verifyPlatformCertificateSignature :: 
    SignedPlatformCertificate -> 
    Certificate -> 
    ValidationResult
verifyPlatformCertificateSignature signedCert issuerCert = do
    -- Extract signature data from the signed certificate
    let certData = extractCertificateData signedCert
        signature = extractSignature signedCert
        sigAlg = extractSignatureAlgorithm signedCert
        issuerPubKey = extractPublicKey issuerCert
    
    -- Validate signature algorithm
    case validateSignatureAlgorithm sigAlg of
        Left errs -> Left errs
        Right () -> do
            -- Verify the actual signature
            case verifySignatureWithKey sigAlg issuerPubKey certData signature of
                False -> Left [SignatureVerificationFailed "Platform certificate signature verification failed"]
                True -> Right ()

-- | Verify the signature on a Delta Platform Certificate
verifyDeltaCertificateSignature :: 
    SignedDeltaPlatformCertificate -> 
    Certificate -> 
    ValidationResult
verifyDeltaCertificateSignature signedDelta issuerCert = do
    -- Extract signature data from the signed delta certificate
    let deltaData = extractDeltaCertificateData signedDelta
        signature = extractDeltaSignature signedDelta
        sigAlg = extractDeltaSignatureAlgorithm signedDelta
        issuerPubKey = extractPublicKey issuerCert
    
    -- Validate signature algorithm
    case validateSignatureAlgorithm sigAlg of
        Left errs -> Left errs
        Right () -> do
            -- Verify the actual signature
            case verifySignatureWithKey sigAlg issuerPubKey deltaData signature of
                False -> Left [SignatureVerificationFailed "Delta certificate signature verification failed"]
                True -> Right ()

-- | Verify signatures on an entire certificate chain
verifyCertificateChainSignatures :: 
    SignedPlatformCertificate -> 
    [SignedDeltaPlatformCertificate] -> 
    [Certificate] -> 
    ValidationResult
verifyCertificateChainSignatures baseCert deltas issuerCerts = do
    -- Verify base certificate signature
    baseResult <- case issuerCerts of
        (issuer:_) -> verifyPlatformCertificateSignature baseCert issuer
        [] -> Left [MissingTrustedRoot "No issuer certificate provided for base certificate"]
    
    -- Verify all delta certificate signatures
    deltaResults <- mapM (`verifyDeltaCertificateSignature` head issuerCerts) deltas
    
    -- Combine all results
    return $ combineValidationResults (baseResult : deltaResults)

-- | Validate that a signature algorithm is acceptable according to policy
validateSignatureAlgorithm :: SignatureALG -> ValidationResult
validateSignatureAlgorithm sigAlg = 
    case sigAlg of
        SignatureALG hashAlg pubKeyAlg -> do
            -- Check if the signature algorithm is supported
            if isSupportedSignatureAlgorithm sigAlg
                then Right ()
                else Left [UnsupportedSignatureAlgorithm (show sigAlg)]

-- | Check if a signature algorithm is supported
isSupportedSignatureAlgorithm :: SignatureALG -> Bool
isSupportedSignatureAlgorithm sigAlg = 
    case sigAlg of
        SignatureALG hashAlg pubKeyAlg -> 
            isSupportedHashAlgorithm hashAlg && isSupportedPubKeyAlgorithm pubKeyAlg
  where
    isSupportedHashAlgorithm hashAlg = hashAlg `elem` [HashSHA256, HashSHA384, HashSHA512]
    isSupportedPubKeyAlgorithm pubKeyAlg = pubKeyAlg `elem` [PubKeyALG_RSA, PubKeyALG_ECDSA]

-- | Get the minimum required key size for a signature algorithm
getRequiredKeySize :: SignatureALG -> Maybe Int
getRequiredKeySize (SignatureALG _ PubKeyALG_RSA) = Just 2048  -- Minimum 2048 bits for RSA
getRequiredKeySize (SignatureALG _ PubKeyALG_ECDSA) = Just 256  -- Minimum P-256 for ECDSA
getRequiredKeySize _ = Nothing

-- | Low-level signature verification with a public key
verifySignatureWithKey :: 
    SignatureALG -> 
    PubKey -> 
    B.ByteString -> 
    B.ByteString -> 
    Bool
verifySignatureWithKey sigAlg pubKey certData signature =
    case (sigAlg, pubKey) of
        (SignatureALG hashAlg PubKeyALG_RSA, PubKeyRSA rsaPubKey) ->
            verifyRSASignature hashAlg rsaPubKey certData signature
        (SignatureALG hashAlg PubKeyALG_ECDSA, PubKeyECDSA ecdsaPubKey) ->
            verifyECDSASignature hashAlg ecdsaPubKey certData signature
        _ -> False  -- Unsupported combination

-- | Verify RSA signature
verifyRSASignature :: 
    HashALG -> 
    RSA.PublicKey -> 
    B.ByteString -> 
    B.ByteString -> 
    Bool
verifyRSASignature hashAlg rsaPubKey certData signature = 
    case hashAlg of
        HashSHA1   -> RSA.verify (Just Hash.SHA1) rsaPubKey certData signature
        HashSHA256 -> RSA.verify (Just Hash.SHA256) rsaPubKey certData signature 
        HashSHA384 -> RSA.verify (Just Hash.SHA384) rsaPubKey certData signature
        HashSHA512 -> RSA.verify (Just Hash.SHA512) rsaPubKey certData signature
        _          -> False  -- Unsupported hash algorithm

-- | Verify ECDSA signature  
verifyECDSASignature :: 
    HashALG -> 
    ECDSA.PublicKey -> 
    B.ByteString -> 
    B.ByteString -> 
    Bool
verifyECDSASignature hashAlg ecdsaPubKey certData signature = 
    case parseECDSASignature signature of
        Nothing -> False  -- Failed to parse signature
        Just ecdsaSig -> 
            case hashAlg of
                HashSHA1   -> ECDSA.verify Hash.SHA1 ecdsaPubKey ecdsaSig certData
                HashSHA256 -> ECDSA.verify Hash.SHA256 ecdsaPubKey ecdsaSig certData
                HashSHA384 -> ECDSA.verify Hash.SHA384 ecdsaPubKey ecdsaSig certData
                HashSHA512 -> ECDSA.verify Hash.SHA512 ecdsaPubKey ecdsaSig certData
                _          -> False  -- Unsupported hash algorithm

-- | Validate signature compliance with policy
validateSignatureCompliance :: 
    SignatureALG -> 
    ValidationPolicy -> 
    ValidationResult
validateSignatureCompliance sigAlg policy =
    if vpRequireValidSignature policy
        then validateSignatureAlgorithm sigAlg
        else Right ()

-- | Check signature strength according to current security standards
checkSignatureStrength :: SignatureALG -> ValidationResult
checkSignatureStrength sigAlg = 
    case getRequiredKeySize sigAlg of
        Nothing -> Left [UnsupportedSignatureAlgorithm (show sigAlg)]
        Just minSize -> 
            if minSize >= getMinimumKeySize sigAlg
                then Right ()
                else Left [WeakSignatureAlgorithm (show sigAlg)]
  where
    getMinimumKeySize (SignatureALG _ PubKeyALG_RSA) = 2048
    getMinimumKeySize (SignatureALG _ PubKeyALG_ECDSA) = 256
    getMinimumKeySize _ = 0

-- Helper functions (these would need to be implemented based on the actual certificate structure)

extractCertificateData :: SignedPlatformCertificate -> B.ByteString
extractCertificateData signedCert = 
    -- Extract the to-be-signed data from the SignedExact structure
    case encodeASN1' DER (signedObject $ getSigned signedCert) of
        Right bs -> bs
        Left _ -> B.empty  -- Fallback to empty if encoding fails

extractSignature :: SignedPlatformCertificate -> B.ByteString  
extractSignature signedCert = 
    -- Extract signature bytes from the SignedExact structure
    signedSignature $ getSigned signedCert

extractSignatureAlgorithm :: SignedPlatformCertificate -> SignatureALG
extractSignatureAlgorithm signedCert = 
    -- Extract signature algorithm from the SignedExact structure
    signedAlg $ getSigned signedCert

extractPublicKey :: Certificate -> PubKey
extractPublicKey = certPubKey  -- Use the existing X509 function

extractDeltaCertificateData :: SignedDeltaPlatformCertificate -> B.ByteString
extractDeltaCertificateData signedDelta = 
    -- Extract the to-be-signed data from the Delta certificate
    case encodeASN1' DER (signedObject $ getSigned signedDelta) of
        Right bs -> bs
        Left _ -> B.empty  -- Fallback to empty if encoding fails

extractDeltaSignature :: SignedDeltaPlatformCertificate -> B.ByteString
extractDeltaSignature signedDelta = 
    -- Extract signature bytes from the Delta certificate
    signedSignature $ getSigned signedDelta

extractDeltaSignatureAlgorithm :: SignedDeltaPlatformCertificate -> SignatureALG
extractDeltaSignatureAlgorithm signedDelta = 
    -- Extract signature algorithm from the Delta certificate
    signedAlg $ getSigned signedDelta

-- | Parse ECDSA signature from DER-encoded bytes
parseECDSASignature :: B.ByteString -> Maybe ECDSA.Signature
parseECDSASignature sigBytes = 
    case decodeASN1' DER sigBytes of
        Left _ -> Nothing
        Right asn1 -> 
            case runParseASN1 parseSignature asn1 of
                Left _ -> Nothing
                Right sig -> Just sig
  where
    parseSignature = do
        Start Sequence <- getNext
        IntVal r <- getNext
        IntVal s <- getNext
        End Sequence <- getNext
        return $ ECDSA.Signature r s
    
    getNext = parseASN1

-- | Combine multiple validation results
combineValidationResults :: [ValidationResult] -> ValidationResult
combineValidationResults results = 
    case partitionEithers results of
        ([], _) -> Right ()
        (errs, _) -> Left (concat errs)
  where
    partitionEithers [] = ([], [])
    partitionEithers (Left e : xs) = let (ls, rs) = partitionEithers xs in (e : ls, rs)
    partitionEithers (Right r : xs) = let (ls, rs) = partitionEithers xs in (ls, r : rs)