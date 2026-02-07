{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Data.X509.TCG.Compliance.ASN1
-- License     : BSD-style
-- Maintainer  : Toru Tomita <toru.tomita@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- ASN.1 helpers for compliance checks (SAN parsing, size limits, value helpers).

module Data.X509.TCG.Compliance.ASN1
  ( decodeASN1WithLimit
  , decodeAttributeASN1
  , formatOID
  , lookupExtensionRaw
  , extractSANAttributes
  , asn1StringValue
  , asn1OIDValue
  , stripSequence
  , stripSequenceOrContent
  , extractContextContainer
  , findContextPrimitive
  , skipContainer
  , ParsedAlgorithmIdentifier(..)
  , ParsedURIReference(..)
  , ParsedAttributeCertificateIdentifier(..)
  , ParsedIssuerSerial(..)
  , ParsedCertificateIdentifier(..)
  , ParsedAddress(..)
  , ParsedProperty(..)
  , ParsedComponent(..)
  , ParsedPlatformConfiguration(..)
  , ParsedCommonCriteriaMeasures(..)
  , ParsedFipsLevel(..)
  , ParsedTbbSecurityAssertions(..)
  , ParsedCertificatePolicies(..)
  , ParsedTargetingInfo(..)
  , parseURIReferenceContent
  , parsePlatformConfiguration
  , parsePlatformComponents
  , parseTBBSecurityAssertions
  , parseCertificatePolicies
  , parseTargetingInformation
  ) where

import qualified Data.ByteString as B
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.List (foldl')
import Data.Bits ((.&.), (.|.), shiftL)

import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.Types
import Data.ASN1.BitArray (BitArray)
import Data.X509 (Extensions(..), ExtensionRaw(..))

-- | Maximum ASN.1 payload size to parse for platformConfiguration (bytes).
maxPlatformConfigBytes :: Int
maxPlatformConfigBytes = 1024 * 1024

-- | Parsed AlgorithmIdentifier (RFC 5280).
data ParsedAlgorithmIdentifier = ParsedAlgorithmIdentifier
  { paiOid :: OID
  , paiParams :: [ASN1]
  } deriving (Show, Eq)

-- | Parsed URIReference (IWG §3.1.1).
data ParsedURIReference = ParsedURIReference
  { puriUri :: B.ByteString
  , puriHashAlg :: Maybe ParsedAlgorithmIdentifier
  , puriHashValue :: Maybe BitArray
  } deriving (Show, Eq)

-- | Parsed AttributeCertificateIdentifier.
data ParsedAttributeCertificateIdentifier = ParsedAttributeCertificateIdentifier
  { paciHashAlg :: ParsedAlgorithmIdentifier
  , paciHashValue :: B.ByteString
  } deriving (Show, Eq)

-- | Parsed IssuerSerial.
data ParsedIssuerSerial = ParsedIssuerSerial
  { pisIssuer :: [ASN1]
  , pisSerial :: Integer
  } deriving (Show, Eq)

-- | Parsed CertificateIdentifier.
data ParsedCertificateIdentifier = ParsedCertificateIdentifier
  { pciAttrCertId :: Maybe ParsedAttributeCertificateIdentifier
  , pciIssuerSerial :: Maybe ParsedIssuerSerial
  } deriving (Show, Eq)

-- | Parsed ComponentAddress.
data ParsedAddress = ParsedAddress
  { paType :: OID
  , paValue :: B.ByteString
  } deriving (Show, Eq)

-- | Parsed Property.
data ParsedProperty = ParsedProperty
  { ppName :: B.ByteString
  , ppValue :: B.ByteString
  , ppStatus :: Maybe Integer
  } deriving (Show, Eq)

-- | Parsed component info from PlatformConfiguration.
data ParsedComponent = ParsedComponent
  { pcClassRegistry :: Maybe OID
  , pcClassValue :: Maybe B.ByteString
  , pcManufacturer :: Maybe B.ByteString
  , pcModel :: Maybe B.ByteString
  , pcSerial :: Maybe B.ByteString
  , pcRevision :: Maybe B.ByteString
  , pcManufacturerId :: Maybe OID
  , pcFieldReplaceable :: Maybe Bool
  , pcAddresses :: [ParsedAddress]
  , pcPlatformCert :: Maybe ParsedCertificateIdentifier
  , pcPlatformCertUri :: Maybe ParsedURIReference
  , pcStatus :: Maybe Integer
  } deriving (Show, Eq)

-- | Parsed PlatformConfiguration (v2).
data ParsedPlatformConfiguration = ParsedPlatformConfiguration
  { ppcComponents :: [ParsedComponent]
  , ppcComponentsUri :: Maybe ParsedURIReference
  , ppcProperties :: [ParsedProperty]
  , ppcPropertiesUri :: Maybe ParsedURIReference
  , ppcIsLegacy :: Bool
  } deriving (Show, Eq)

-- | Parsed CommonCriteriaMeasures.
data ParsedCommonCriteriaMeasures = ParsedCommonCriteriaMeasures
  { pccVersion :: B.ByteString
  , pccAssurance :: Integer
  , pccEvalStatus :: Integer
  , pccPlus :: Bool
  , pccStrength :: Maybe Integer
  , pccProfileOid :: Maybe OID
  , pccProfileUri :: Maybe ParsedURIReference
  , pccTargetOid :: Maybe OID
  , pccTargetUri :: Maybe ParsedURIReference
  } deriving (Show, Eq)

-- | Parsed FIPSLevel.
data ParsedFipsLevel = ParsedFipsLevel
  { pfVersion :: B.ByteString
  , pfLevel :: Integer
  , pfPlus :: Bool
  } deriving (Show, Eq)

-- | Parsed TBBSecurityAssertions.
data ParsedTbbSecurityAssertions = ParsedTbbSecurityAssertions
  { ptbbVersion :: Maybe Integer
  , ptbbCcInfo :: Maybe ParsedCommonCriteriaMeasures
  , ptbbFipsLevel :: Maybe ParsedFipsLevel
  , ptbbRtmType :: Maybe Integer
  , ptbbIso9000Certified :: Maybe Bool
  , ptbbIso9000Uri :: Maybe B.ByteString
  } deriving (Show, Eq)

-- | Parsed CertificatePolicies extension.
data ParsedCertificatePolicies = ParsedCertificatePolicies
  { pcpPolicyIds :: [OID]
  , pcpCpsUris :: [B.ByteString]
  , pcpUserNotices :: [B.ByteString]
  } deriving (Show, Eq)

-- | Parsed TargetingInformation extension.
data ParsedTargetingInfo = ParsedTargetingInfo
  { ptiHasTargetName :: Bool
  , ptiHasSerialNumberRdn :: Bool
  , ptiHasNonTargetName :: Bool
  } deriving (Show, Eq)

-- | Decode ASN.1 with a size limit to avoid DoS.
decodeASN1WithLimit :: Int -> B.ByteString -> Either Text [ASN1]
decodeASN1WithLimit maxBytes bs
  | B.length bs > maxBytes =
      Left $ "ASN.1 content too large (" <> T.pack (show (B.length bs)) <> " bytes)"
  | otherwise =
      case decodeASN1' DER bs of
        Left err -> Left $ "ASN.1 decode failed: " <> T.pack (show err)
        Right asn1 -> Right asn1

-- | Decode an AttributeValue list into ASN.1.
-- Some attributes carry a DER blob inside an OctetString; others are already decoded.
decodeAttributeASN1 :: Int -> [ASN1] -> Either Text [ASN1]
decodeAttributeASN1 maxBytes values = case values of
  (OctetString bs : _) -> decodeASN1WithLimit maxBytes bs
  _ -> Right values

-- | Format OID as dotted text.
formatOID :: OID -> Text
formatOID oid = T.intercalate "." (map (T.pack . show) oid)

-- | Lookup raw extension by OID.
lookupExtensionRaw :: OID -> Extensions -> Maybe ExtensionRaw
lookupExtensionRaw oid (Extensions mexts) = do
  exts <- mexts
  let matches ext = extRawOID ext == oid
  case filter matches exts of
    (ext:_) -> Just ext
    [] -> Nothing

-- | Extract DirectoryName attributes from SubjectAltName extension.
-- Returns a map from OID to a list of ASN1 value lists (in order encountered).
extractSANAttributes :: Extensions -> Either Text (Maybe (Map OID [[ASN1]]))
extractSANAttributes exts = case lookupExtensionRaw [2,5,29,17] exts of
  Nothing -> Right Nothing
  Just ext -> do
    let ExtensionRaw _ _ raw = ext
    asn1 <- decodeASN1WithLimit (256 * 1024) raw
    attrs <- parseGeneralNames asn1
    Right (Just attrs)

asn1StringValue :: ASN1 -> Maybe (ASN1StringEncoding, B.ByteString)
asn1StringValue (ASN1String (ASN1CharacterString enc bs)) = Just (enc, bs)
asn1StringValue _ = Nothing

asn1OIDValue :: ASN1 -> Maybe OID
asn1OIDValue (OID oid) = Just oid
asn1OIDValue _ = Nothing

decodeUtf8Bytes :: Text -> B.ByteString -> Either Text B.ByteString
decodeUtf8Bytes label bs =
  case TE.decodeUtf8' bs of
    Left _ -> Left $ label <> ": invalid UTF8String"
    Right _ -> Right bs

decodeIa5Bytes :: Text -> B.ByteString -> Either Text B.ByteString
decodeIa5Bytes label bs =
  if B.all (< 0x80) bs
    then Right bs
    else Left $ label <> ": invalid IA5String"

decodeIntegerContent :: B.ByteString -> Either Text Integer
decodeIntegerContent bs
  | B.null bs = Left "INTEGER: empty content"
  | otherwise =
      let unsigned = foldl' (\acc w -> acc * 256 + fromIntegral w) 0 (B.unpack bs)
          signBitSet = (B.head bs .&. 0x80) /= 0
          modulus = (1 :: Integer) `shiftL` (8 * B.length bs)
      in Right $
           if signBitSet
             then unsigned - modulus
             else unsigned

decodeEnumContent :: B.ByteString -> Either Text Integer
decodeEnumContent = decodeIntegerContent

decodeOIDContent :: B.ByteString -> Either Text OID
decodeOIDContent bs = do
  first <- case B.uncons bs of
    Nothing -> Left "OID: empty content"
    Just (b0, rest) -> Right (b0, rest)
  let (b0, rest) = first
      b0i = fromIntegral b0 :: Integer
      firstArc = if b0i >= 80 then 2 else b0i `div` 40
      secondArc = if b0i >= 80 then b0i - 80 else b0i `mod` 40
  arcs <- decodeBase128Arcs rest
  return (fromIntegral firstArc : fromIntegral secondArc : arcs)
  where
    decodeBase128Arcs :: B.ByteString -> Either Text [Integer]
    decodeBase128Arcs input
      | B.null input = Right []
      | otherwise = go input []
      where
        go bs acc =
          case B.uncons bs of
            Nothing -> Right (reverse acc)
            Just _ -> do
              (arc, rest) <- decodeArc bs
              go rest (arc : acc)

        decodeArc bs =
          let step current remaining =
                case B.uncons remaining of
                  Nothing -> Left "OID: truncated base128 encoding"
                  Just (b, rest) ->
                    let value = (current `shiftL` 7) .|. fromIntegral (b .&. 0x7f)
                        continue = b .&. 0x80 /= 0
                    in if continue
                         then step value rest
                         else Right (value, rest)
          in step 0 bs

parseSequenceContent :: [ASN1] -> Either Text ([ASN1], [ASN1])
parseSequenceContent (Start Sequence : rest) = collectContainer Sequence rest
parseSequenceContent _ = Left "ASN.1: expected SEQUENCE"

parseSetContent :: [ASN1] -> Either Text ([ASN1], [ASN1])
parseSetContent (Start Set : rest) = collectContainer Set rest
parseSetContent _ = Left "ASN.1: expected SET"

-- | Strip the outer SEQUENCE and return its contents.
stripSequence :: [ASN1] -> Either Text [ASN1]
stripSequence (Start Sequence : rest) = go 1 [] rest
  where
    go :: Int -> [ASN1] -> [ASN1] -> Either Text [ASN1]
    go _ _ [] = Left "ASN.1: unterminated SEQUENCE"
    go depth acc (x:xs)
      | x == Start Sequence = go (depth + 1) (x:acc) xs
      | x == End Sequence =
          if depth == 1
            then Right (reverse acc)
            else go (depth - 1) (x:acc) xs
      | otherwise = go depth (x:acc) xs
stripSequence _ = Left "ASN.1: expected SEQUENCE"

-- | Strip outer SEQUENCE if present; otherwise treat input as already content.
stripSequenceOrContent :: [ASN1] -> Either Text [ASN1]
stripSequenceOrContent xs = case xs of
  (Start Sequence : _) -> stripSequence xs
  _ -> Right xs

-- | Extract a constructed context-specific container.
extractContextContainer :: Int -> [ASN1] -> Either Text (Maybe [ASN1])
extractContextContainer tag xs = go xs
  where
    container = Container Context tag
    go [] = Right Nothing
    go (Start c : rest)
      | c == container = do
          (content, _remaining) <- collectContainer c rest
          return (Just content)
      | otherwise = skipContainer c rest >>= go
    go (_:rest) = go rest

-- | Find an IMPLICIT context-specific primitive value (e.g., ENUMERATED).
findContextPrimitive :: Int -> [ASN1] -> Maybe B.ByteString
findContextPrimitive _ [] = Nothing
findContextPrimitive tag (Other Context t bs : _)
  | t == tag = Just bs
findContextPrimitive tag (_:rest) = findContextPrimitive tag rest

parseAlgorithmIdentifier :: [ASN1] -> Either Text (ParsedAlgorithmIdentifier, [ASN1])
parseAlgorithmIdentifier (Start Sequence : rest) = do
  (content, remaining) <- collectContainer Sequence rest
  case content of
    (OID oid : params) -> Right (ParsedAlgorithmIdentifier oid params, remaining)
    _ -> Left "AlgorithmIdentifier: expected OBJECT IDENTIFIER"
parseAlgorithmIdentifier _ = Left "AlgorithmIdentifier: expected SEQUENCE"

parseURIReferenceContent :: [ASN1] -> Either Text ParsedURIReference
parseURIReferenceContent content = do
  case content of
    (ASN1String (ASN1CharacterString IA5 bs) : rest) -> do
      _ <- decodeIa5Bytes "URIReference.uniformResourceIdentifier" bs
      (hashAlg, hashVal, leftover) <- parseUriRefTail rest
      if null leftover
        then Right $ ParsedURIReference bs hashAlg hashVal
        else Left "URIReference: trailing data"
    _ -> Left "URIReference: expected IA5String URI"
  where
    parseUriRefTail :: [ASN1] -> Either Text (Maybe ParsedAlgorithmIdentifier, Maybe BitArray, [ASN1])
    parseUriRefTail xs = do
      let (algPart, rest1) =
            case xs of
              (Start Sequence : _) ->
                case parseAlgorithmIdentifier xs of
                  Right (alg, remaining) -> (Just alg, remaining)
                  Left _ -> (Nothing, xs)
              _ -> (Nothing, xs)
      let (hashPart, rest2) =
            case rest1 of
              (BitString bits : remaining) -> (Just bits, remaining)
              _ -> (Nothing, rest1)
      return (algPart, hashPart, rest2)

parseURIReference :: [ASN1] -> Either Text ParsedURIReference
parseURIReference xs = do
  content <- stripSequenceOrContent xs
  parseURIReferenceContent content

parseAttributeCertificateIdentifier :: [ASN1] -> Either Text (ParsedAttributeCertificateIdentifier, [ASN1])
parseAttributeCertificateIdentifier xs = do
  (content, remaining) <- parseSequenceContent xs
  case content of
    (Start Sequence : _) -> do
      (alg, rest1) <- parseAlgorithmIdentifier content
      case rest1 of
        (OctetString h : rest2) ->
          if null rest2
            then Right (ParsedAttributeCertificateIdentifier alg h, remaining)
            else Left "AttributeCertificateIdentifier: trailing data"
        _ -> Left "AttributeCertificateIdentifier: expected OCTET STRING hashOverSignatureValue"
    _ -> Left "AttributeCertificateIdentifier: invalid SEQUENCE"

parseIssuerSerial :: [ASN1] -> Either Text (ParsedIssuerSerial, [ASN1])
parseIssuerSerial xs = do
  (content, remaining) <- parseSequenceContent xs
  case content of
    (Start Sequence : rest) -> do
      (gns, rest1) <- collectContainer Sequence rest
      case rest1 of
        (IntVal serial : rest2) ->
          if null rest2
            then Right (ParsedIssuerSerial (Start Sequence : gns ++ [End Sequence]) serial, remaining)
            else Left "IssuerSerial: trailing data"
        _ -> Left "IssuerSerial: expected serial INTEGER"
    _ -> Left "IssuerSerial: expected GeneralNames SEQUENCE"

parseCertificateIdentifierContent :: [ASN1] -> Either Text ParsedCertificateIdentifier
parseCertificateIdentifierContent content = go content (ParsedCertificateIdentifier Nothing Nothing)
  where
    go [] acc = Right acc
    go (Start (Container Context 0) : rest) acc = do
      (ctx, remaining) <- collectContainer (Container Context 0) rest
      (aci, leftover) <- parseAttributeCertificateIdentifier (Start Sequence : ctx ++ [End Sequence])
      if not (null leftover)
        then Left "CertificateIdentifier: trailing data in attributeCertIdentifier"
        else go remaining acc { pciAttrCertId = Just aci }
    go (Start (Container Context 1) : rest) acc = do
      (ctx, remaining) <- collectContainer (Container Context 1) rest
      (isr, leftover) <- parseIssuerSerial (Start Sequence : ctx ++ [End Sequence])
      if not (null leftover)
        then Left "CertificateIdentifier: trailing data in genericCertIdentifier"
        else go remaining acc { pciIssuerSerial = Just isr }
    go (_:_) _ = Left "CertificateIdentifier: unexpected token"

parseCertificateIdentifier :: [ASN1] -> Either Text ParsedCertificateIdentifier
parseCertificateIdentifier xs = do
  content <- stripSequenceOrContent xs
  parseCertificateIdentifierContent content

-- | STRMAX per IWG Profile §2.2: UTF8String (SIZE (1..255))
strMax :: Int
strMax = 255

parseComponentAddresses :: [ASN1] -> Either Text [ParsedAddress]
parseComponentAddresses content = do
  seqs <- splitSequences content
  mapM parseComponentAddress seqs
  where
    parseComponentAddress seqAsn1 = do
      fields <- stripSequence seqAsn1
      case fields of
        (OID oid : ASN1String (ASN1CharacterString UTF8 bs) : []) -> do
          _ <- decodeUtf8Bytes "ComponentAddress.addressValue" bs
          -- Validate STRMAX constraint per IWG §3.1.6 line 604
          let len = B.length bs
          if len < 1 || len > strMax
            then Left $ "ComponentAddress.addressValue length " <> T.pack (show len) <> " out of range (1.." <> T.pack (show strMax) <> ")"
            else return (ParsedAddress oid bs)
        _ -> Left "ComponentAddress: expected { OID, UTF8String }"

parseProperty :: [ASN1] -> Either Text ParsedProperty
parseProperty seqAsn1 = do
  fields <- stripSequence seqAsn1
  case fields of
    (ASN1String (ASN1CharacterString UTF8 name) : ASN1String (ASN1CharacterString UTF8 val) : rest) -> do
      _ <- decodeUtf8Bytes "Property.propertyName" name
      _ <- decodeUtf8Bytes "Property.propertyValue" val
      -- Validate STRMAX constraint per IWG §3.1.6 lines 610-611
      let nameLen = B.length name
          valLen = B.length val
      if nameLen < 1 || nameLen > strMax
        then Left $ "Property.propertyName length " <> T.pack (show nameLen) <> " out of range (1.." <> T.pack (show strMax) <> ")"
        else if valLen < 1 || valLen > strMax
          then Left $ "Property.propertyValue length " <> T.pack (show valLen) <> " out of range (1.." <> T.pack (show strMax) <> ")"
          else case rest of
            [] -> return (ParsedProperty name val Nothing)
            (Other Context 0 bs : []) -> do
              v <- decodeEnumContent bs
              return (ParsedProperty name val (Just v))
            _ -> Left "Property: unexpected trailing data"
    _ -> Left "Property: expected UTF8String name and value"

-- | Parse full PlatformConfiguration (v2 or legacy v1).
parsePlatformConfiguration :: [ASN1] -> Either Text ParsedPlatformConfiguration
parsePlatformConfiguration values = do
  asn1 <- decodeAttributeASN1 maxPlatformConfigBytes values
  content <- stripSequenceOrContent asn1
  if hasAnyContextTag content
    then parsePlatformConfigurationV2 content
    else do
      comps <- parseLegacyComponents content
      Right $ ParsedPlatformConfiguration
        { ppcComponents = comps
        , ppcComponentsUri = Nothing
        , ppcProperties = []
        , ppcPropertiesUri = Nothing
        , ppcIsLegacy = True
        }

-- | Parse PlatformConfiguration components (spec v1.1 or legacy encoding).
parsePlatformComponents :: [ASN1] -> Either Text [ParsedComponent]
parsePlatformComponents values = ppcComponents <$> parsePlatformConfiguration values

parsePlatformConfigurationV2 :: [ASN1] -> Either Text ParsedPlatformConfiguration
parsePlatformConfigurationV2 content = go content emptyCfg
  where
    emptyCfg = ParsedPlatformConfiguration [] Nothing [] Nothing False

    go [] acc = Right acc
    go (Start (Container Context tag) : rest) acc = do
      (ctxContent, remaining) <- collectContainer (Container Context tag) rest
      acc' <- case tag of
        0 -> do
          seqs <- splitSequences ctxContent
          comps <- mapM parseComponentSequence seqs
          return acc { ppcComponents = comps }
        1 -> do
          uri <- parseURIReferenceContent ctxContent
          return acc { ppcComponentsUri = Just uri }
        2 -> do
          seqs <- splitSequences ctxContent
          props <- mapM parseProperty seqs
          return acc { ppcProperties = props }
        3 -> do
          uri <- parseURIReferenceContent ctxContent
          return acc { ppcPropertiesUri = Just uri }
        _ -> Left "PlatformConfiguration: unknown context-specific tag"
      go remaining acc'
    go (_:_) _ = Left "PlatformConfiguration: unexpected token"

-- ============================================================================
-- Internal parsing helpers (shared)
-- ============================================================================

hasAnyContextTag :: [ASN1] -> Bool
hasAnyContextTag [] = False
hasAnyContextTag (Start (Container Context _) : _) = True
hasAnyContextTag (Other Context _ _ : _) = True
hasAnyContextTag (_:rest) = hasAnyContextTag rest

splitSequences :: [ASN1] -> Either Text [[ASN1]]
splitSequences [] = Right []
splitSequences (Start Sequence : rest) = do
  (content, remaining) <- collectContainer Sequence rest
  others <- splitSequences remaining
  let seqAsn1 = Start Sequence : content ++ [End Sequence]
  return (seqAsn1 : others)
splitSequences (_:_) = Left "ASN.1: expected SEQUENCE OF ComponentIdentifier"

parseComponentSequence :: [ASN1] -> Either Text ParsedComponent
parseComponentSequence seqAsn1 = do
  content <- stripSequence seqAsn1
  (registryOid, classValue, afterClass) <- parseComponentClass content
  (manufacturer, afterMfg) <- parseRequiredUtf8 "componentManufacturer" afterClass
  (model, afterModel) <- parseRequiredUtf8 "componentModel" afterMfg
  (serial, rest1) <- parseOptionalContextUtf8 0 afterModel
  (revision, rest2) <- parseOptionalContextUtf8 1 rest1
  (manufacturerId, rest3) <- parseOptionalContextOid 2 rest2
  (fieldReplaceable, rest4) <- parseOptionalContextBool 3 rest3
  (addresses, rest5) <- parseOptionalContextAddresses 4 rest4
  (platformCert, rest6) <- parseOptionalContextCertId 5 rest5
  (platformCertUri, rest7) <- parseOptionalContextUri 6 rest6
  (status, rest8) <- parseOptionalContextEnum 7 rest7
  if not (null rest8)
    then Left "ComponentIdentifier: trailing data"
    else return ParsedComponent
      { pcClassRegistry = Just registryOid
      , pcClassValue = Just classValue
      , pcManufacturer = Just manufacturer
      , pcModel = Just model
      , pcSerial = serial
      , pcRevision = revision
      , pcManufacturerId = manufacturerId
      , pcFieldReplaceable = fieldReplaceable
      , pcAddresses = addresses
      , pcPlatformCert = platformCert
      , pcPlatformCertUri = platformCertUri
      , pcStatus = status
      }

parseComponentClass :: [ASN1] -> Either Text (OID, B.ByteString, [ASN1])
parseComponentClass (Start Sequence : OID oid : OctetString val : End Sequence : rest) =
  Right (oid, val, rest)
parseComponentClass _ =
  Left "ComponentClass: expected SEQUENCE { OID, OCTET STRING }"

parseRequiredUtf8 :: Text -> [ASN1] -> Either Text (B.ByteString, [ASN1])
parseRequiredUtf8 _ [] = Left "ASN.1: missing UTF8String"
parseRequiredUtf8 label (val : rest) =
  case asn1StringValue val of
    Just (UTF8, bs) -> do
      _ <- decodeUtf8Bytes label bs
      -- Validate STRMAX constraint per IWG §3.1.6
      let len = B.length bs
      if len < 1 || len > strMax
        then Left $ label <> " length " <> T.pack (show len) <> " out of range (1.." <> T.pack (show strMax) <> ")"
        else Right (bs, rest)
    Just (enc, _) -> Left $ label <> ": expected UTF8String, got " <> T.pack (show enc)
    Nothing -> Left $ label <> ": expected UTF8String"

parseOptionalContextUtf8 :: Int -> [ASN1] -> Either Text (Maybe B.ByteString, [ASN1])
parseOptionalContextUtf8 tag (Other Context t bs : rest)
  | t == tag = do
      _ <- decodeUtf8Bytes "UTF8String" bs
      -- Validate STRMAX constraint per IWG §3.1.6
      let len = B.length bs
      if len < 1 || len > strMax
        then Left $ "UTF8String length " <> T.pack (show len) <> " out of range (1.." <> T.pack (show strMax) <> ")"
        else Right (Just bs, rest)
parseOptionalContextUtf8 _ xs = Right (Nothing, xs)

parseOptionalContextOid :: Int -> [ASN1] -> Either Text (Maybe OID, [ASN1])
parseOptionalContextOid tag (Other Context t bs : rest)
  | t == tag = do
      oid <- decodeOIDContent bs
      Right (Just oid, rest)
parseOptionalContextOid _ xs = Right (Nothing, xs)

parseOptionalContextBool :: Int -> [ASN1] -> Either Text (Maybe Bool, [ASN1])
parseOptionalContextBool tag (Other Context t bs : rest)
  | t == tag =
      case B.uncons bs of
        Just (v, _) -> Right (Just (v /= 0), rest)
        Nothing -> Left "BOOLEAN: empty content"
parseOptionalContextBool _ xs = Right (Nothing, xs)

parseOptionalContextAddresses :: Int -> [ASN1] -> Either Text ([ParsedAddress], [ASN1])
parseOptionalContextAddresses tag (Start (Container Context t) : rest)
  | t == tag = do
      (ctx, remaining) <- collectContainer (Container Context t) rest
      addrs <- parseComponentAddresses ctx
      Right (addrs, remaining)
parseOptionalContextAddresses _ xs = Right ([], xs)

parseOptionalContextCertId :: Int -> [ASN1] -> Either Text (Maybe ParsedCertificateIdentifier, [ASN1])
parseOptionalContextCertId tag (Start (Container Context t) : rest)
  | t == tag = do
      (ctx, remaining) <- collectContainer (Container Context t) rest
      certId <- parseCertificateIdentifierContent ctx
      Right (Just certId, remaining)
parseOptionalContextCertId _ xs = Right (Nothing, xs)

parseOptionalContextUri :: Int -> [ASN1] -> Either Text (Maybe ParsedURIReference, [ASN1])
parseOptionalContextUri tag (Start (Container Context t) : rest)
  | t == tag = do
      (ctx, remaining) <- collectContainer (Container Context t) rest
      uri <- parseURIReferenceContent ctx
      Right (Just uri, remaining)
parseOptionalContextUri _ xs = Right (Nothing, xs)

parseOptionalContextEnum :: Int -> [ASN1] -> Either Text (Maybe Integer, [ASN1])
parseOptionalContextEnum tag (Other Context t bs : rest)
  | t == tag = do
      v <- decodeEnumContent bs
      Right (Just v, rest)
parseOptionalContextEnum _ xs = Right (Nothing, xs)

decodeStatus :: Maybe B.ByteString -> Maybe Integer
decodeStatus Nothing = Nothing
decodeStatus (Just bs) =
  case decodeEnumContent bs of
    Right v -> Just v
    Left _ -> Nothing

-- Legacy encoding: PlatformConfiguration ::= SEQUENCE { mfg, model, version, serial, components SEQUENCE }
parseLegacyComponents :: [ASN1] -> Either Text [ParsedComponent]
parseLegacyComponents (mfg : mdl : _ver : _ser : Start Sequence : rest)
  | isStringLike mfg && isStringLike mdl = do
      (content, remaining) <- collectContainer Sequence rest
      if not (null remaining)
        then Left "Legacy PlatformConfiguration: trailing data after component list"
        else do
          seqs <- splitSequences content
          mapM parseLegacyComponentSequence seqs
parseLegacyComponents _ = Right []

parseLegacyComponentSequence :: [ASN1] -> Either Text ParsedComponent
parseLegacyComponentSequence seqAsn1 = do
  content <- stripSequence seqAsn1
  case content of
    (mfg : mdl : _) | isStringLike mfg && isStringLike mdl -> do
      manufacturer <- parseLegacyString "componentManufacturer" mfg
      model <- parseLegacyString "componentModel" mdl
      return ParsedComponent
        { pcClassRegistry = Nothing
        , pcClassValue = Nothing
        , pcManufacturer = Just manufacturer
        , pcModel = Just model
        , pcSerial = Nothing
        , pcRevision = Nothing
        , pcManufacturerId = Nothing
        , pcFieldReplaceable = Nothing
        , pcAddresses = []
        , pcPlatformCert = Nothing
        , pcPlatformCertUri = Nothing
        , pcStatus = Nothing
        }
    _ -> Left "Legacy ComponentIdentifier: expected manufacturer/model strings"

isStringLike :: ASN1 -> Bool
isStringLike (OctetString _) = True
isStringLike (ASN1String _) = True
isStringLike _ = False

parseLegacyString :: Text -> ASN1 -> Either Text B.ByteString
parseLegacyString _ (OctetString bs) = Right bs
parseLegacyString _ (ASN1String (ASN1CharacterString _ bs)) = Right bs
parseLegacyString label _ = Left $ label <> ": expected string"

-- ============================================================================
-- TBBSecurityAssertions parsing
-- ============================================================================

parseTBBSecurityAssertions :: [ASN1] -> Either Text ParsedTbbSecurityAssertions
parseTBBSecurityAssertions values = do
  asn1 <- decodeAttributeASN1 (256 * 1024) values
  content <- stripSequenceOrContent asn1
  let (ver, rest1) = case content of
        (IntVal v : rest) -> (Just v, rest)
        _ -> (Nothing, content)
  (ccInfo, rest2) <- parseOptionalContextCC 0 rest1
  (fipsLevel, rest3) <- parseOptionalContextFips 1 rest2
  (rtmType, rest4) <- parseOptionalContextEnumTag 2 rest3
  (isoCert, rest5) <- parseOptionalBoolean rest4
  (isoUri, rest6) <- parseOptionalIA5 rest5
  if not (null rest6)
    then Left "TBBSecurityAssertions: trailing data"
    else Right $ ParsedTbbSecurityAssertions
      { ptbbVersion = ver
      , ptbbCcInfo = ccInfo
      , ptbbFipsLevel = fipsLevel
      , ptbbRtmType = rtmType
      , ptbbIso9000Certified = isoCert
      , ptbbIso9000Uri = isoUri
      }
  where
    parseOptionalContextCC :: Int -> [ASN1] -> Either Text (Maybe ParsedCommonCriteriaMeasures, [ASN1])
    parseOptionalContextCC tag (Start (Container Context t) : rest) | t == tag = do
      (ctx, remaining) <- collectContainer (Container Context t) rest
      cc <- parseCommonCriteriaMeasuresContent ctx
      return (Just cc, remaining)
    parseOptionalContextCC _ xs = Right (Nothing, xs)

    parseOptionalContextFips :: Int -> [ASN1] -> Either Text (Maybe ParsedFipsLevel, [ASN1])
    parseOptionalContextFips tag (Start (Container Context t) : rest) | t == tag = do
      (ctx, remaining) <- collectContainer (Container Context t) rest
      fips <- parseFipsLevelContent ctx
      return (Just fips, remaining)
    parseOptionalContextFips _ xs = Right (Nothing, xs)

    parseOptionalContextEnumTag :: Int -> [ASN1] -> Either Text (Maybe Integer, [ASN1])
    parseOptionalContextEnumTag tag (Other Context t bs : rest) | t == tag = do
      v <- decodeEnumContent bs
      return (Just v, rest)
    parseOptionalContextEnumTag _ xs = Right (Nothing, xs)

    parseOptionalBoolean :: [ASN1] -> Either Text (Maybe Bool, [ASN1])
    parseOptionalBoolean (Boolean b : rest) = Right (Just b, rest)
    parseOptionalBoolean xs = Right (Nothing, xs)

    parseOptionalIA5 :: [ASN1] -> Either Text (Maybe B.ByteString, [ASN1])
    parseOptionalIA5 (ASN1String (ASN1CharacterString IA5 bs) : rest) = do
      _ <- decodeIa5Bytes "iso9000Uri" bs
      return (Just bs, rest)
    parseOptionalIA5 xs = Right (Nothing, xs)

parseCommonCriteriaMeasuresContent :: [ASN1] -> Either Text ParsedCommonCriteriaMeasures
parseCommonCriteriaMeasuresContent content = do
  (version, rest1) <- parseRequiredIA5 "CommonCriteriaMeasures.version" content
  (assurance, rest2) <- parseEnumerated "CommonCriteriaMeasures.assuranceLevel" rest1
  (evalStatus, rest3) <- parseEnumerated "CommonCriteriaMeasures.evaluationStatus" rest2
  (plus, rest4) <- parseOptionalBool "CommonCriteriaMeasures.plus" rest3
  (strength, rest5) <- parseOptionalContextEnum 0 rest4
  (profileOid, rest6) <- parseOptionalContextOidTag 1 rest5
  (profileUri, rest7) <- parseOptionalContextUriTag 2 rest6
  (targetOid, rest8) <- parseOptionalContextOidTag 3 rest7
  (targetUri, rest9) <- parseOptionalContextUriTag 4 rest8
  if not (null rest9)
    then Left "CommonCriteriaMeasures: trailing data"
    else Right $ ParsedCommonCriteriaMeasures
      { pccVersion = version
      , pccAssurance = assurance
      , pccEvalStatus = evalStatus
      , pccPlus = plus
      , pccStrength = strength
      , pccProfileOid = profileOid
      , pccProfileUri = profileUri
      , pccTargetOid = targetOid
      , pccTargetUri = targetUri
      }
  where
    parseRequiredIA5 :: Text -> [ASN1] -> Either Text (B.ByteString, [ASN1])
    parseRequiredIA5 label (ASN1String (ASN1CharacterString IA5 bs) : rest) = do
      _ <- decodeIa5Bytes label bs
      Right (bs, rest)
    parseRequiredIA5 label _ = Left $ label <> ": expected IA5String"

    parseEnumerated :: Text -> [ASN1] -> Either Text (Integer, [ASN1])
    parseEnumerated _ (Enumerated v : rest) = Right (v, rest)
    parseEnumerated _ (IntVal v : rest) = Right (v, rest)
    parseEnumerated label _ = Left $ label <> ": expected ENUMERATED"

    parseOptionalBool :: Text -> [ASN1] -> Either Text (Bool, [ASN1])
    parseOptionalBool _ (Boolean b : rest) = Right (b, rest)
    parseOptionalBool _ xs = Right (False, xs)

    parseOptionalContextEnum :: Int -> [ASN1] -> Either Text (Maybe Integer, [ASN1])
    parseOptionalContextEnum tag (Other Context t bs : rest) | t == tag = do
      v <- decodeEnumContent bs
      Right (Just v, rest)
    parseOptionalContextEnum _ xs = Right (Nothing, xs)

    parseOptionalContextOidTag :: Int -> [ASN1] -> Either Text (Maybe OID, [ASN1])
    parseOptionalContextOidTag tag (Other Context t bs : rest) | t == tag = do
      oid <- decodeOIDContent bs
      Right (Just oid, rest)
    parseOptionalContextOidTag _ xs = Right (Nothing, xs)

    parseOptionalContextUriTag :: Int -> [ASN1] -> Either Text (Maybe ParsedURIReference, [ASN1])
    parseOptionalContextUriTag tag (Start (Container Context t) : rest) | t == tag = do
      (ctx, remaining) <- collectContainer (Container Context t) rest
      uri <- parseURIReferenceContent ctx
      Right (Just uri, remaining)
    parseOptionalContextUriTag _ xs = Right (Nothing, xs)

parseFipsLevelContent :: [ASN1] -> Either Text ParsedFipsLevel
parseFipsLevelContent content = do
  (version, rest1) <- parseRequiredIA5 "FIPSLevel.version" content
  (level, rest2) <- parseEnumerated "FIPSLevel.level" rest1
  (plus, rest3) <- parseOptionalBool rest2
  if not (null rest3)
    then Left "FIPSLevel: trailing data"
    else Right $ ParsedFipsLevel version level plus
  where
    parseRequiredIA5 :: Text -> [ASN1] -> Either Text (B.ByteString, [ASN1])
    parseRequiredIA5 label (ASN1String (ASN1CharacterString IA5 bs) : rest) = do
      _ <- decodeIa5Bytes label bs
      Right (bs, rest)
    parseRequiredIA5 label _ = Left $ label <> ": expected IA5String"

    parseEnumerated :: Text -> [ASN1] -> Either Text (Integer, [ASN1])
    parseEnumerated _ (Enumerated v : rest) = Right (v, rest)
    parseEnumerated _ (IntVal v : rest) = Right (v, rest)
    parseEnumerated label _ = Left $ label <> ": expected ENUMERATED"

    parseOptionalBool :: [ASN1] -> Either Text (Bool, [ASN1])
    parseOptionalBool (Boolean b : rest) = Right (b, rest)
    parseOptionalBool xs = Right (False, xs)

-- ============================================================================
-- CertificatePolicies parsing
-- ============================================================================

parseCertificatePolicies :: [ASN1] -> Either Text ParsedCertificatePolicies
parseCertificatePolicies asn1 = do
  content <- stripSequenceOrContent asn1
  seqs <- splitSequences content
  foldl' parsePolicy (Right (ParsedCertificatePolicies [] [] [])) seqs
  where
    parsePolicy acc seqAsn1 = do
      state <- acc
      fields <- stripSequence seqAsn1
      case fields of
        (OID pid : rest) -> do
          (cps, unotice) <- parsePolicyQualifiers rest
          Right state
            { pcpPolicyIds = pid : pcpPolicyIds state
            , pcpCpsUris = cps ++ pcpCpsUris state
            , pcpUserNotices = unotice ++ pcpUserNotices state
            }
        _ -> Left "CertificatePolicies: expected policyIdentifier OID"

    parsePolicyQualifiers [] = Right ([], [])
    parsePolicyQualifiers (Start Sequence : rest) = do
      (qualContent, remaining) <- collectContainer Sequence rest
      if not (null remaining)
        then Left "CertificatePolicies: trailing data after policyQualifiers"
        else do
          qualifiers <- splitSequences qualContent
          foldl' parseQualifier (Right ([], [])) qualifiers
    parsePolicyQualifiers _ = Left "CertificatePolicies: invalid policyQualifiers"

    parseQualifier acc seqAsn1 = do
      (cpsAcc, unoticeAcc) <- acc
      fields <- stripSequence seqAsn1
      case fields of
        (OID qid : qrest) ->
          case qid of
            [1,3,6,1,5,5,7,2,1] -> do -- id-qt-cps
              cps <- parseCpsUri qrest
              return (cps : cpsAcc, unoticeAcc)
            [1,3,6,1,5,5,7,2,2] -> do -- id-qt-unotice
              notices <- parseUserNotice qrest
              return (cpsAcc, notices ++ unoticeAcc)
            _ -> return (cpsAcc, unoticeAcc)
        _ -> Left "PolicyQualifierInfo: expected policyQualifierId OID"

    parseCpsUri :: [ASN1] -> Either Text B.ByteString
    parseCpsUri (ASN1String (ASN1CharacterString IA5 bs) : []) = do
      _ <- decodeIa5Bytes "cPSuri" bs
      return bs
    parseCpsUri _ = Left "PolicyQualifierInfo(cPSuri): expected IA5String"

    parseUserNotice :: [ASN1] -> Either Text [B.ByteString]
    parseUserNotice (Start Sequence : rest) = do
      (content, remaining) <- collectContainer Sequence rest
      if not (null remaining)
        then Left "UserNotice: trailing data"
        else do
          afterNoticeRef <- case content of
            (Start Sequence : rest1) -> do
              (_noticeRef, remaining1) <- collectContainer Sequence rest1
              Right remaining1
            _ -> Right content
          Right (extractDisplayTexts afterNoticeRef)
    parseUserNotice _ = Left "UserNotice: expected SEQUENCE"

    extractDisplayTexts :: [ASN1] -> [B.ByteString]
    extractDisplayTexts [] = []
    extractDisplayTexts (ASN1String (ASN1CharacterString _ bs) : rest) =
      bs : extractDisplayTexts rest
    extractDisplayTexts (Start (Container Context 1) : rest) =
      case collectContainer (Container Context 1) rest of
        Right (ctx, remaining) ->
          let texts = [bs | ASN1String (ASN1CharacterString _ bs) <- ctx]
          in texts ++ extractDisplayTexts remaining
        Left _ -> extractDisplayTexts rest
    extractDisplayTexts (_:xs) = extractDisplayTexts xs

-- ============================================================================
-- TargetingInformation parsing
-- ============================================================================

parseTargetingInformation :: [ASN1] -> Either Text ParsedTargetingInfo
parseTargetingInformation asn1 = do
  content <- stripSequenceOrContent asn1
  targetsSeqs <- splitSequences content
  foldl' parseTargets (Right (ParsedTargetingInfo False False False)) targetsSeqs
  where
    parseTargets acc seqAsn1 = do
      state <- acc
      targetsContent <- stripSequence seqAsn1
      parseTargetEntries targetsContent state

    parseTargetEntries [] state = Right state
    parseTargetEntries (Start (Container Context tag) : rest) state = do
      (ctx, remaining) <- collectContainer (Container Context tag) rest
      case tag of
        0 -> do
          hasSerial <- generalNameHasSerialNumberRdn ctx
          parseTargetEntries remaining state
            { ptiHasTargetName = True
            , ptiHasSerialNumberRdn = ptiHasSerialNumberRdn state || hasSerial
            }
        _ -> parseTargetEntries remaining state { ptiHasNonTargetName = True }
    parseTargetEntries (_:_) _ = Left "TargetingInformation: unexpected token"

    generalNameHasSerialNumberRdn :: [ASN1] -> Either Text Bool
    generalNameHasSerialNumberRdn (Start (Container Context 4) : rest) = do
      (dnContent, remaining) <- collectContainer (Container Context 4) rest
      if not (null remaining)
        then Left "GeneralName: trailing data"
        else do
          attrs <- parseDirectoryName dnContent
          return (Map.member [2,5,4,5] attrs)
    generalNameHasSerialNumberRdn _ = Right False

-- ============================================================================
-- Internal parsing helpers
-- ============================================================================

parseGeneralNames :: [ASN1] -> Either Text (Map OID [[ASN1]])
parseGeneralNames (Start Sequence : rest) = go rest Map.empty
  where
    go (End Sequence : _) acc = Right acc
    go xs acc = do
      (attrs, rest') <- parseGeneralName xs
      let acc' = Map.unionWith (++) acc attrs
      go rest' acc'
parseGeneralNames _ = Left "SubjectAltName: expected SEQUENCE"

parseGeneralName :: [ASN1] -> Either Text (Map OID [[ASN1]], [ASN1])
parseGeneralName [] = Left "SubjectAltName: unexpected end of data"
parseGeneralName (Start (Container Context 4) : rest) = do
  (content, remaining) <- collectContainer (Container Context 4) rest
  attrs <- parseDirectoryName content
  Right (attrs, remaining)
parseGeneralName (Start container : rest) = do
  remaining <- skipContainer container rest
  Right (Map.empty, remaining)
parseGeneralName (_ : rest) = Right (Map.empty, rest)

collectContainer :: ASN1ConstructionType -> [ASN1] -> Either Text ([ASN1], [ASN1])
collectContainer container = go 1 []
  where
    go :: Int -> [ASN1] -> [ASN1] -> Either Text ([ASN1], [ASN1])
    go _ _ [] = Left "SubjectAltName: unterminated container"
    go depth acc (x:xs)
      | x == Start container = go (depth + 1) (x:acc) xs
      | x == End container =
          if depth == 1
            then Right (reverse acc, xs)
            else go (depth - 1) (x:acc) xs
      | otherwise = go depth (x:acc) xs

skipContainer :: ASN1ConstructionType -> [ASN1] -> Either Text [ASN1]
skipContainer container = go 1
  where
    go :: Int -> [ASN1] -> Either Text [ASN1]
    go _ [] = Left "SubjectAltName: unterminated container"
    go depth (x:xs)
      | x == Start container = go (depth + 1) xs
      | x == End container =
          if depth == 1 then Right xs else go (depth - 1) xs
      | otherwise = go depth xs

parseDirectoryName :: [ASN1] -> Either Text (Map OID [[ASN1]])
parseDirectoryName (Start Sequence : rest) = go rest Map.empty
  where
    go (End Sequence : _) acc = Right acc
    go (Start Set : xs) acc = do
      (setAttrs, rest') <- parseRDNSet xs []
      let acc' = foldr (\(oid, vals) m -> Map.insertWith (++) oid [vals] m) acc setAttrs
      go rest' acc'
    go _ _ = Left "SubjectAltName: invalid DirectoryName structure"
parseDirectoryName _ = Left "SubjectAltName: expected DirectoryName SEQUENCE"

parseRDNSet :: [ASN1] -> [(OID, [ASN1])] -> Either Text ([(OID, [ASN1])], [ASN1])
parseRDNSet [] _ = Left "SubjectAltName: unterminated RDN SET"
parseRDNSet (End Set : rest) acc = Right (reverse acc, rest)
parseRDNSet xs acc = do
  (pair, rest') <- parseATV xs
  parseRDNSet rest' (pair:acc)

parseATV :: [ASN1] -> Either Text ((OID, [ASN1]), [ASN1])
parseATV (Start Sequence : rest) = do
  (content, remaining) <- collectContainer Sequence rest
  case content of
    (OID oid : valTokens) | not (null valTokens) -> Right ((oid, valTokens), remaining)
    _ -> Left "SubjectAltName: invalid AttributeTypeAndValue"
parseATV _ = Left "SubjectAltName: invalid AttributeTypeAndValue"
