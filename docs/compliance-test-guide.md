# TCG Platform Certificate Compliance Specification

## 1. Scope

This document specifies the compliance verification requirements for TCG Platform Certificates, based on the following primary sources:

- `docs/IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.pdf`
- `docs/TCG_PlatformCertificateProfilev1p1_r19_Errata_v3_pub.pdf`
- `docs/TCG_Component_Class_Registry_v1.0_rev14_pub.pdf`
- `docs/SMBIOS-Component-Class-Registry_v1.01_finalpublication.pdf`
- `docs/TCG_PCIe_Component_Class_Registry_v1_r18_pub10272021.pdf`
- `docs/Storage-Component-Class-Registry-Version-1.0-Revision-22_pub.pdf`

This specification covers 66 implementation checks (STR/VAL/DLT/CHN/REG/EXT/SEC/ERR).
Note that `REG-*` checks have external specification dependencies per registry type; therefore, the applicable normative basis must be explicitly stated according to the registry in use.
The default profile is **Operational Compatibility (v1.1 + subsequent registries)**, which includes PCIe/Storage registries as conformance assessment targets.

## 2. Normative Interpretation

- RFC 2119 terminology (MUST/SHOULD/MAY, etc.) follows the definitions in the IWG body text (L41-L42).
- ASN.1 structures require DER encoding (L317).
- Errata v3 Clarifications/Errata take precedence over and are applied as corrections to the IWG R19 body text.
- Per Errata v3 Clarification 2, certificate sample values in the Appendix are treated as informative.
- The corresponding Registry specification (TCG/SMBIOS/PCIe/Storage) is applied normatively based on the `componentClassRegistry` value.
- The default assessment profile in this document is `OperationalCompatibility` (v1.1 + PCIe/Storage).
- `StrictV11` (tcg/ietf/dmtf only) assessment is treated as an optional additional profile.
- When requirements conflict within the IWG body text, the following explicit rules apply:
- `DLT-005` cites both conflicting clauses and defines the default assessment (see Section 8 of this document).
- Assessment levels:
- `Required`: MUST / MUST NOT
- `Recommended`: SHOULD / SHOULD NOT
- `Optional`: MAY

## 3. Conformance Decision

- If there is one or more `Required` failure, or one or more execution errors, the certificate is **Non-compliant**.
- If only `Recommended` failures exist, the certificate is **Compliant with recommendations** (improvement advised).
- `Optional` omissions do not constitute non-compliance, but if present, structural and value validity must be verified.
- The assessment profile used (`OperationalCompatibility`/`StrictV11`) must always be recorded in the assessment result.

## 4. Global ASN.1/DER Constraints

| ID | Rule | Level | Source |
|---|---|---|---|
| G-001 | ASN.1 must be DER encoded | MUST | §3 (L315-L317) |
| G-002 | In `URIReference`, `hashAlgorithm` and `hashValue` must not exist independently (one without the other) | MUST | §3.1.1 (L402-L407) |
| G-003 | `URIMAX` should not exceed a recommended upper limit of 1024 | SHOULD NOT exceed | §3.1.1 (L336-L341) |
| G-004 | `STRMAX` should not exceed a recommended upper limit of 256 | SHOULD NOT exceed | §3.1.1 (L342-L345) |
| G-005 | `AlgorithmIdentifier.parameters` for hashing should generally not be used | SHOULD NOT use | §3.1.6 (L650-L652) |
| G-006 | The `platformConfiguration` parser should be version-aware, recognizing both current and prior OIDs | SHOULD | §3.1.6 NOTE (L655-L661) |

## 5. Compliance Check Catalog (66 checks)

### 5.1 STR (STR-001 through STR-013)

| ID | Requirement | Level | Applies | Source |
|---|---|---|---|---|
| STR-001 | AC version must be v2 (ASN.1 value is `1`) | MUST | Base/Delta | §3.2.1 (L686-L687), §3.3.1 (L800-L801) |
| STR-002 | Holder must use the `BaseCertificateID` choice and include the referenced certificate's issuer/serial (for Base, the TPM EK certificate) | MUST | Base/Delta | §3.2.4 (L698-L700), §3.3.4 (L812-L813), Errata Clarification 1 (L91-L94) |
| STR-003 | Issuer must represent the issuer's DN | MUST | Base/Delta | §3.2.5 (L705-L707), §3.3.5 (L815-L818) |
| STR-004 | Signature algorithm must correspond to the TCG Algorithm Registry | MUST | Base/Delta | §3.2.3 (L694-L696), §3.3.3 (L808-L810) |
| STR-005 | Serial Number must be a positive integer and unique within the issuer | MUST | Base/Delta | §3.2.2 (L689-L691), §3.3.2 (L803-L805) |
| STR-006 | `notBefore/notAfter` must conform to RFC 5755 format, with `notBefore <= notAfter` | MUST | Base/Delta | §3.2.6 (L711-L714), §3.3.6 (L821-L825) |
| STR-007 | Attributes are recommended to be included | SHOULD | Base/Delta | §3.2.10 (L739-L748), §3.3.10 (L847-L856) |
| STR-008 | Duplicate extension OIDs are prohibited | MUST | Base/Delta | RFC 5755 compliance requirement (§3.2/§3.3 preamble L678-L679, L793-L794) |
| STR-009 | Unknown critical extensions must be rejected | MUST | Base/Delta | RFC 5755 compliance requirement (§3.2/§3.3 preamble L678-L679, L793-L794) |
| STR-010 | If `platformConfigUri` is present, it must conform to the `URIReference` structure | MAY + valid if present | Base/Delta | §3.1.7 (L662-L673), §3.1.1 (L402-L407) |
| STR-011 | `TCG Platform Specification` is recommended for Base, prohibited for Delta | SHOULD (Base) / MUST NOT (Delta) | Base/Delta | §3.2.10 (L740-L742), §3.1.3 (L481-L482) |
| STR-012 | `TCG Credential Type` is recommended for Base, required for Delta | SHOULD (Base) / MUST (Delta) | Base/Delta | §3.2.10 (L743), §3.1.4 (L500-L501), §3.3.10 (L847-L849) |
| STR-013 | `TCG Credential Specification` is recommended for Base, conditionally optional for Delta | SHOULD (Base) / MAY (Delta) | Base/Delta | §3.2.10 (L744-L745), §3.1.5 (L516-L517), Table 4 (L1298-L1301) |

### 5.2 VAL (VAL-001 through VAL-017)

| ID | Requirement | Level | Applies | Source |
|---|---|---|---|---|
| VAL-001 | `platformManufacturerStr` must be `UTF8String (1..STRMAX)` | MUST | Base/Delta | §3.1.2 (L430-L444) |
| VAL-002 | `platformModel` must be `UTF8String (1..STRMAX)` | MUST | Base/Delta | §3.1.2 (L432-L448) |
| VAL-003 | `platformVersion` must be `UTF8String (1..STRMAX)` | MUST | Base/Delta | §3.1.2 (L433-L452) |
| VAL-004 | `platformSerial` is `UTF8String (1..STRMAX)` (optional) | MAY | Base/Delta | §3.1.2 (L435-L456), §3.2.8 (L726-L727), §3.3.8 (L838-L839) |
| VAL-005 | `platformManufacturerId` is `ManufacturerId ::= SEQUENCE { manufacturerIdentifier PrivateEnterpriseNumber }` | MAY | Base/Delta | §3.1.2 (L437-L465), Errata 9 (L291-L305) |
| VAL-006 | `tBBSecurityAssertions` structure must match the ASN.1 definition | SHOULD (Base) / MUST NOT (Delta) | Base/Delta | §3.2.10 (L746-L748), §3.1.1 (L333-L334) |
| VAL-007 | `TBBSecurityAssertions.version` must be `v1(0)` (DEFAULT) | MUST (if present) | Base | §3.1.1 (L346, L352-L354) |
| VAL-008 | `FIPSLevel.level` must be in the range `1..4` | MAY + valid if present | Base | §3.1.1 (L416-L425) |
| VAL-009 | `iso9000Certified` must be BOOLEAN, `iso9000Uri` must be IA5String(1..URIMAX) | MAY + valid if present | Base | §3.1.1 (L357-L358) |
| VAL-010 | `EvaluationAssuranceLevel` must be in `1..7`, `StrengthOfFunction` must be in `0..2` | MAY + valid if present | Base | §3.1.1 (L376-L399) |
| VAL-011 | `ComponentIdentifier` requires class/manufacturer/model; status is Delta-only | MUST | Base/Delta | §3.1.6 (L531-L535, L582-L594, L554-L555) |
| VAL-012 | `componentClassRegistry` must conform to the ASN.1-defined OID | MUST | Base/Delta | §3.1.6 (L595-L600) |
| VAL-013 | `componentClassValue` must be `OCTET STRING SIZE(4)` | MUST | Base/Delta | §3.1.6 (L595-L598) |
| VAL-014 | When using `componentPlatformCert`, either `attributeCertIdentifier` or `genericCertIdentifier` is required | MUST (conditional) | Base/Delta | §3.1.6 (L541-L548), (L614-L621) |
| VAL-015 | The current attribute OID is `tcg-at-platformConfiguration-v2`, but the parser should support prior versions | SHOULD (emit v2) + SHOULD (accept prior) | Base/Delta | §3.1.6 (L570-L573), NOTE (L655-L661), OID definition (L928-L930) |
| VAL-016 | `CertificateIdentifier` structure (`attributeCertIdentifier` / `genericCertIdentifier`) validity | MUST | Base/Delta | §3.1.6 (L614-L626) |
| VAL-017 | `StrengthOfFunction` must be `basic/medium/high` (`0..2`) | MAY + valid if present | Base | §3.1.1 (L396-L399) |

### 5.3 DLT (DLT-001 through DLT-012)

| ID | Requirement | Level | Applies | Source |
|---|---|---|---|---|
| DLT-001 | Delta `platformConfiguration` is optional, but if present it must contain only the differences from the base | MAY (if present MUST be delta-only changes) | Delta | §2.2.6.13 (L300-L303), Table 4 (L1303-L1308) |
| DLT-002 | Delta must include `tcgCredentialType` (Delta OID) | MUST | Delta | §3.1.4 (L500-L501), §3.3.10 (L847-L849), Table 4 (L1296-L1297) |
| DLT-003 | Delta Serial Number must be a positive integer and unique within the issuer | MUST | Delta | §3.3.2 (L803-L805) |
| DLT-004 | Delta Holder must reference a base Platform/Delta certificate | MUST | Delta | §3.3.4 (L812-L813) |
| DLT-005 | Delta `notAfter` must satisfy the relationship constraint with the base (see Section 8 for conflict interpretation) | SHOULD NOT precede / (competing MUST match) | Delta | §3.3.6 (L823), §2.2.6.10 (L291) |
| DLT-006 | `AttributeStatus` must be one of `added(0)/modified(1)/removed(2)` only | MUST | Delta | §3.1.6 (L628-L631) |
| DLT-007 | The `status` field may only be used in Delta certificates | MUST | Delta | §3.1.6 (L554-L555, L562-L563) |
| DLT-008 | When indicating a change in Delta, a status enumerator must be assigned | MUST (conditional) | Delta | §3.1.6 (L564-L568) |
| DLT-009 | `platformManufacturerStr` must be identical to the base | MUST | Delta | §2.2.6.4 (L266-L267), §3.3.8 (L835-L836) |
| DLT-010 | `platformModel` must be identical to the base | MUST | Delta | §2.2.6.6 (L276-L277), §3.3.8 (L835-L836) |
| DLT-011 | `platformVersion` must be identical to the base | MUST | Delta | §2.2.6.7 (L280-L282), §3.3.8 (L835-L836) |
| DLT-012 | `platformSerial`/`platformManufacturerId`, if present, must be identical to the base | MUST (if present) | Delta | §2.2.6.5 (L271-L272), §2.2.6.12 (L297-L298), §3.3.8 (L838-L840) |

### 5.4 CHN (CHN-001 through CHN-005)

| ID | Requirement | Level | Applies | Source |
|---|---|---|---|---|
| CHN-001 | AKI must be non-critical. If the issuer's SKI is available, it must be set in the keyIdentifier; if unavailable, it may be omitted | MUST (non-critical) + conditional omit | Base/Delta | §3.2.11 (L771-L773), §3.3.11 (L858-L860), Table 3/4 (L1136-L1139, L1337-L1340) |
| CHN-002 | AIA must be non-critical; if present, `id-ad-ocsp` and an OCSP URI are recommended | SHOULD (if present) | Base/Delta | §3.2.12 (L775-L778), §3.3.12 (L863-L865) |
| CHN-003 | CRL DP must be non-critical. Presence is optional. When both AIA/OCSP are provided, preferring OCSP is recommended | MAY (Base/Delta) + SHOULD (prefer OCSP when both present) | Base/Delta | §3.2.13 (L783-L787), §3.3.13 (L870-L874), Table 3/4 |
| CHN-004 | Base must satisfy the EK certificate reference requirement via Holder + TargetingInformation | MUST (Base) / MAY (Delta) | Base/Delta | §3.2.4 (L698-L701), §3.2.9 (L732-L736), §3.3.9 (L844-L845) |
| CHN-005 | If TargetingInformation is present, it must have `critical=TRUE` and `targetName` containing the EK serial RDN | MUST (if present) | Base/Delta | §3.2.9 (L734-L736), §3.3.9 (L844-L845) |

### 5.5 REG (REG-001 through REG-004)

> Note: `REG-*` checks are composite requirements derived from the IWG and each Component Class Registry. The default profile is `OperationalCompatibility`. Value definitions for `tcg-registry-componentClass-ietf` are outside the scope of this document.

| ID | Requirement | Level | Applies | Source |
|---|---|---|---|---|
| REG-001 | `componentClassRegistry` must match the selected registry OID. Under `OperationalCompatibility`, `tcg/ietf/dmtf/pcie/storage` are permitted; under `StrictV11`, only `tcg/ietf/dmtf` are permitted | MUST | Base/Delta | IWG §3.1.6 (L599-L600, L633-L637), TCG Registry §2.1.1 (L194-L199), SMBIOS Registry §2.1.1.1 (L176-L179), PCIe Registry §2.1.1.1 (L174-L178), Storage Registry §2.1.1 (L237-L241) |
| REG-002 | `componentClassValue` must be `OCTET STRING SIZE(4)`. The value and byte representation must be encoded according to the normative tables of the selected registry (registry definition takes precedence over uniform rules) | MUST | Base/Delta | IWG §3.1.6 (L597), TCG Registry §2.2.1 (L211-L217), SMBIOS Table 1 (L281-L284), PCIe Table 1 (L287-L292), Storage Table 1/2/3 (L488-L490, L536-L538, L610-L612) |
| REG-003 | When `componentClassRegistry = tcg-registry-componentClass-tcg`, `componentClassValue` must conform to TCG Registry Table 1 (normative) | MUST | Base/Delta | TCG Registry §2.1.1 (L194-L199), §3 (L233-L235) |
| REG-004 | When `componentClassRegistry = dmtf/pcie/storage`, only the target fields defined by each registry's Translation Table (normative) shall be generated/verified (N/A/no recommendation fields are not binding). For PCIe network controller `addressValue`, the issuer must use uppercase hex without delimiters; verifiers should accept Errata-compatible representations | MUST (issuer) + SHOULD (verifier compatibility) | Base/Delta | SMBIOS §3 Table 1 (L274-L284), PCIe §3 Table 1 (L287-L299), Storage §3/4/5 Table 1/2/3 (L486-L490, L534-L538, L608-L612), Errata Clarification 4 (L106-L123) |

### 5.6 EXT (EXT-001 through EXT-005)

| ID | Requirement | Level | Applies | Source |
|---|---|---|---|---|
| EXT-001 | CertificatePolicies must be non-critical, with `policyIdentifier>=1`, `cPSuri` as an HTTP URL, and `userNotice` as a fixed string | MUST | Base/Delta | §3.2.7 (L716-L721), §3.3.7 (L827-L833) |
| EXT-002 | SAN must be non-critical. The directoryName must contain platform* attributes, and in Delta must be identical to the base (RDN attribute ordering is not significant) | MUST | Base/Delta | §3.2.8 (L723-L730), §3.3.8 (L835-L842), Errata Clarification 7 (L149-L152) |
| EXT-003 | The `userNotice` explicit text must be `TCG Trusted Platform Endorsement` (a separate concept from the Certificate Type OID) | MUST | Base/Delta | §3.2.7 (L720), §3.3.7 (L831), Errata Clarification 5/6 (L123-L148), Errata 7 (L230-L237) |
| EXT-004 | Issuer Unique ID must be omitted | MUST NOT | Base/Delta | §3.2.14 (L788-L790), §3.3.14 (L875-L877) |
| EXT-005 | If TargetingInformation is present, critical must be TRUE | MUST (if present) | Base/Delta | §3.2.9 (L734), §3.3.9 (L844-L845) |

### 5.7 SEC (SEC-001 through SEC-005)

| ID | Requirement | Level | Applies | Source |
|---|---|---|---|---|
| SEC-001 | Delta must not include `tBBSecurityAssertions` | MUST NOT | Delta | §3.1.1 (L333-L334) |
| SEC-002 | Delta must not include `TCGPlatformSpecification` | MUST NOT | Delta | §3.1.3 (L481-L482) |
| SEC-003 | `MeasurementRootType` must be within the enumeration range `0..5` | MUST (if present) | Base | §3.1.1 (L365-L371) |
| SEC-004 | When both `profileOid/profileUri` and `targetOid/targetUri` pairs are present, they must be semantically consistent | MUST (if both present) | Base | §3.1.1 (L328-L330) |
| SEC-005 | All `URIReference` instances must satisfy the hash pair co-existence constraint | MUST | Base/Delta | §3.1.1 (L402-L407) |

### 5.8 ERR (ERR-001 through ERR-005)

> Note: `ERR-*` checks codify the correction requirements from Errata v3.

| ID | Requirement | Level | Applies | Source |
|---|---|---|---|---|
| ERR-001 | Verification of `componentIdentifiers` must be order-independent (fixed ordering must not be required) | MUST | Base/Delta | Errata 1 (L159-L168) |
| ERR-002 | `ComponentAddress.addressValue` should accept the multiple MAC string representations listed in the Errata | SHOULD (verifier capability) | Base/Delta | Errata Clarification 4 (L106-L123) |
| ERR-003 | `PrivateEnterpriseNumber` must be interpreted and validated as an `OBJECT IDENTIFIER` | MUST | Base/Delta | Errata 9 (L291-L305) |
| ERR-004 | `baseCertificateID` must include the TPM EK issuer/serial; when referencing component certificates, `attributeCertificateIdentifier` or `genericCertIdentifier` must be included | MUST | Base/Delta | Errata Clarification 1 (L91-L94), Errata 4 (L191-L206) |
| ERR-005 | `tcg-address-ethernetmac` / `tcg-address-wlanmac` / `tcg-address-bluetoothmac` permit only 48-bit MACs | MUST | Base/Delta | Errata 6 (L225-L229) |

## 6. Requirements That Need Manual Evidence

The following cannot be fully verified through static ASN.1 validation alone and require manual evidence or operational data:

1. Serial Number uniqueness within the issuer (requires multiple issuance history records)
2. `policyIdentifier` "acceptable" determination (depends on Relying Party policy, L721/L833)
3. Semantic consistency of `CommonCriteriaMeasures` OID and URI (L328-L330)
4. Availability and response validity of OCSP/CRL endpoints (L779-L787, L866-L874)
5. Authenticity of the base certificate referenced by a Delta (chain validation and revocation checking through operational coordination)
6. Conversion validity from SMBIOS/PCIe/ATA/SCSI/NVMe raw data (REG-004) cannot be fully verified from the certificate alone; raw data evidence is required

## 6.1 Normative Clauses Not Yet Mapped to Dedicated Check IDs

The following have normative provisions in the primary sources but are not separated into dedicated IDs within the 66 checks of this document:

1. In Base certificates, legacy compatibility attributes (TCPA spec version, TPM/TBB protection profile, etc.) SHOULD NOT be included (§3.2.10, L754-L769)
2. Value definitions for `tcg-registry-componentClass-ietf` are outside the scope of this document (to be separately defined by the IETF-side registry specification)

## 7. Test Data Obligations

Test sets based on this specification must include at minimum the following:

- Base positive cases (containing all required attributes/extensions)
- Delta positive cases (with base comparison, change differences + status present)
- Delta negative cases (base comparison mismatch, invalid status, prohibited attribute inclusion)
- ASN.1 boundary values (`STRMAX/URIMAX`, out-of-range ENUM, empty values, missing one side of a hash pair)
- DER negative cases (invalid length, invalid tag, invalid character type, oversized input)

## 8. Mandatory Ambiguity Handling

### 8.1 Delta `notAfter` requirement conflict (DLT-005)

IWG R19 contains the following conflict:

- §2.2.6.10: `notAfter` **MUST match** the base (L291)
- §3.3.6: `notAfter` **SHOULD NOT precede** the base (L823)

Rules applied in this specification:

1. The default compliance assessment adopts §3.3.6, treating `SHOULD NOT precede` as `Recommended`.
2. As an optional additional strict assessment profile, §2.2.6.10's `MUST match` may be applied.
3. The audit output must always state which assessment criterion was used.

### 8.2 Delta Name Attributes optionality conflict

- §3.1.2 states "These attributes MUST be included in the Delta Platform Certificate" (L439)
- However, the same section describes `platformSerial` and `platformManufacturerId` as OPTIONAL (L435-L438)
- SAN definitions also treat serial/manufacturerId as optional (L726-L728, L838-L840)

Rules applied in this specification:

1. For Delta, `manufacturer/model/version` are required.
2. `serial/manufacturerId`, if present, must be syntactically valid and match the base.
3. When absent, they are treated as `Optional`, but operational requirements may override this to mandatory via profile configuration.

### 8.3 `platformConfiguration` OID version handling

- The current ASN.1 attribute ID is `tcg-at-platformConfiguration-v2` (L570-L573, L928-L930)
- However, a NOTE advises the parser to consider prior version support (L655-L661)

Rules applied in this specification:

1. For issuer conformance, emitting v2 is recommended (`SHOULD emit v2`).
2. For verifier conformance, the ability to accept v1/v2 is recommended (`SHOULD parse prior versions`).
3. The detected OID must be recorded in the inspection results upon acceptance.

### 8.4 Authority Key Identifier interpretation

- Tables 3/4 indicate AKI as `MUST` (L1136-L1139, L1337-L1340)
- §3.2.11/§3.3.11 state "set keyIdentifier if the issuer certificate's SKI is available; if unavailable, omission is permitted" (L771-L773, L858-L860)

Rules applied in this specification:

1. AKI criticality must be `FALSE`.
2. `keyIdentifier` is required when the issuer's SKI can be obtained.
3. Omission of `keyIdentifier` is permitted only when the issuer's SKI cannot be obtained.

### 8.5 Issuer Unique ID conflict

- Table 3 can be read as `SHOULD NOT` for Issuer Unique ID (L1147-L1152)
- §3.2.14/§3.3.14 specify that Issuer Unique ID `MUST be omitted` (L788-L790, L875-L877)

Rules applied in this specification:

1. The body text sections (§3.2.14/§3.3.14) take precedence, and the assessment is `MUST NOT include`.

### 8.6 Errata v3 integration rules

- Clarification 2: Appendix sample certificate values are informative and must not be used as a conformance basis (L95-L100).
- Clarification 3: Extension of profile-defined sequences/attributes is not intended; therefore, proprietary extensions cannot serve as a conformance basis (L101-L105).
- Errata 8/11/12/13: ASN.1 name/OID typographical errors are corrected by the post-Errata definitions, which are treated as authoritative (L237-L286, L468-L520).

### 8.7 Registry MAC format policy

- The PCIe Registry specifies that the network controller's `componentAddresses.addressValue` uses uppercase hexadecimal without delimiters (L296-L299).
- Errata Clarification 4 requires verifiers to be capable of accepting multiple MAC string representations (L106-L123).

Rules applied in this specification:

1. For issuer conformance assessment, the canonical format defined in the PCIe registry specification is required.
2. For verifier interoperability assessment, the ability to accept the MAC representations listed in the Errata is recommended.
3. This acceptance capability check (`ERR-002`) is treated as `SHOULD` (Recommended) and does not independently result in a Non-compliant determination.

### 8.8 Registry OID compatibility profile

- The IWG v1.1 body text defines `ComponentClassRegistry` as `tcg/ietf/dmtf`.
- Subsequent registries (PCIe/Storage) are used in implementation and verification practice as operational extensions after v1.1.

Rules applied in this specification:

1. The default assessment is `OperationalCompatibility`, which permits `tcg/ietf/dmtf/pcie/storage`.
2. As an optional additional assessment, `StrictV11` may be applied, permitting only `tcg/ietf/dmtf`.
3. The audit output must always state which profile was used for the pass/fail determination.

## 9. Coverage Summary

- STR: 13
- VAL: 17
- DLT: 12
- CHN: 5
- REG: 4
- EXT: 5
- SEC: 5
- ERR: 5
- **Total: 66 checks**

This specification is defined in a clause-traceable manner using IWG R19 + Errata v3 + Component Class Registries (TCG/SMBIOS/PCIe/Storage) as primary normative sources.
`REG-*` checks are explicitly marked as registry-specific specification dependencies, and `ERR-*` checks are explicitly marked as Errata v3 dependencies; normative basis must be provided at the time of application.
