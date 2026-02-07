# TCG Platform Certificate Utility -- User Guide

This guide covers the full capabilities of `tcg-platform-cert-util`, a command-line tool for generating, validating, and testing TCG Platform Certificates per the IWG Platform Certificate Profile v1.1.

## Table of Contents

- [Overview](#overview)
- [YAML Configuration Reference](#yaml-configuration-reference)
  - [Base Certificate Config](#base-certificate-config)
  - [Delta Certificate Config](#delta-certificate-config)
  - [Component Class Reference](#component-class-reference)
- [Commands in Detail](#commands-in-detail)
  - [generate](#generate)
  - [lint](#lint)
  - [compliance](#compliance)
  - [show](#show)
  - [validate](#validate)
  - [components](#components)
  - [generate-delta](#generate-delta)
  - [create-config](#create-config)
  - [convert](#convert)
- [Compliance Modes](#compliance-modes)
- [Pre-Issuance Compliance](#pre-issuance-compliance)
- [Lint Check Reference](#lint-check-reference)
- [Chain Compliance](#chain-compliance)
- [JSON Output](#json-output)
- [Exit Codes](#exit-codes)
- [Troubleshooting](#troubleshooting)

---

## Overview

`tcg-platform-cert-util` provides an end-to-end workflow for TCG Platform Certificates:

1. **Create** a YAML configuration describing the platform
2. **Lint** the configuration to catch errors before generation
3. **Generate** a signed Base or Delta Platform Certificate
4. **Inspect** the certificate with `show` or `components`
5. **Validate** the structure and cryptographic signature
6. **Test compliance** against 66 IWG v1.1 checks
7. **Verify chain integrity** across Base + Delta certificates

---

## YAML Configuration Reference

### Base Certificate Config

```yaml
# ============================================================
# Required Platform Identity
# ============================================================
manufacturer: "Dell Technologies Inc."       # platformManufacturerStr (VAL-001)
model: "PowerEdge R750"                      # platformModel (VAL-002)
version: "2.1.3"                             # platformVersion (VAL-003)
serial: "PE750-ENT-2024-001"                 # platformSerial (VAL-004)

# ============================================================
# Certificate Properties
# ============================================================
validityDays: 1095                           # Validity period (default: 365)
keySize: 3072                                # RSA key size (default: 2048)

# ============================================================
# Extended Platform Information (IWG v1.1)
# ============================================================
manufacturerId: "1.3.6.1.4.1.99999"         # Private Enterprise Number OID (VAL-005)
platformClass: "00000001"                    # Platform class identifier (hex)
specificationVersion: "1.1"
majorVersion: 2
minorVersion: 1
patchVersion: 3
platformQualifier: "Enterprise"

# ============================================================
# Credential / Platform Specification (STR-011~013)
# ============================================================
credentialSpecMajor: 1                       # TCG Credential Specification version
credentialSpecMinor: 1
credentialSpecRevision: 13
platformSpecMajor: 2                         # TPM 2.0
platformSpecMinor: 0
platformSpecRevision: 164

# ============================================================
# Platform URIs (with optional hash integrity)
# ============================================================
platformConfigUri:
  uri: "https://example.com/platform-config/pcr-values"
  hashAlgorithm: "sha256"                    # SEC-005 / G-002: hash pair must co-exist
  hashValue: "YWJjZGVm..."                   # Base64-encoded hash

platformConfigLocalUri:
  uri: "file:///etc/tcg/platform-config.json"

# ============================================================
# Security Assertions (VAL-006~010, VAL-017, SEC-003)
# ============================================================
securityAssertions:
  version: 0
  ccVersion: "3.1"                           # Common Criteria version
  evalAssuranceLevel: 4                      # EAL 1-7 (VAL-006)
  strengthOfFunction: "medium"               # basic | medium | high (VAL-007)
  fipsVersion: "140-3"
  fipsSecurityLevel: 2                       # Level 1-4 (VAL-008)
  rtmType: "hybrid"                          # static | dynamic | nonHosted | hybrid (VAL-017)
  iso9000Certified: false

# ============================================================
# Platform Properties
# ============================================================
properties:
  - name: "firmware.version"
    value: "1.2.3"

# ============================================================
# Components (VAL-011~013, REG-001~002)
# ============================================================
components:
  - class: "00030003"                        # 8 hex digits = 4 bytes (REG-002)
    manufacturer: "Dell Technologies Inc."   # Required (VAL-011)
    model: "PowerEdge R750 Motherboard"      # Required (VAL-011)
    serial: "MB-PE750-001"                   # Optional but recommended
    revision: "A02"
    fieldReplaceable: true
    componentClass:                          # Optional structured class info
      registry: "2.23.133.18.3.1"            # TCG registry OID (REG-001)
      value: "00030003"
    addresses:
      - ethernetMac: "00:11:22:33:44:55"

  - class: "00010002"                        # CPU
    manufacturer: "Intel Corporation"
    model: "Xeon Gold 6348"
    serial: "CPU-PE750-001"
    revision: "Stepping 6"

  - class: "00040009"                        # TPM
    manufacturer: "Nuvoton Technology Corp."
    model: "NPCT750"
    serial: "TPM-PE750-001"
    revision: "TPM 2.0"
```

### Delta Certificate Config

Delta certificates track hardware changes relative to a Base certificate. Only include components that have changed. Each component must have a `status` field.

```yaml
manufacturer: "Dell Technologies Inc."       # Must match Base (DLT-009)
model: "PowerEdge R750"                      # Must match Base (DLT-010)
version: "2.1.4"                             # Must match Base (DLT-011)
serial: "PE750-ENT-2024-001"

baseCertificateSerial: "PE750-ENT-2024-001"
deltaSequenceNumber: 1
changeDescription: "Firmware update and memory expansion"

components:
  - class: "00130003"                        # System firmware (UEFI)
    manufacturer: "Dell Technologies Inc."
    model: "PowerEdge UEFI BIOS"
    serial: "BIOS-PE750-001"
    revision: "2.17.0"
    status: "MODIFIED"                       # ADDED | MODIFIED | REMOVED (DLT-008)

  - class: "00060004"                        # DRAM Memory
    manufacturer: "Samsung Electronics"
    model: "M393A4K40DB3-CWE"
    serial: "MEM-PE750-003"
    revision: "32GB DDR4-3200"
    status: "ADDED"
```

**Delta-specific rules:**

- `securityAssertions` and `platformSpec` fields are prohibited (SEC-001, SEC-002)
- Every component must have a `status` field (DLT-008)
- Valid status values: `ADDED`, `MODIFIED`, `REMOVED`
- `manufacturer`, `model`, `version` must match the Base certificate (DLT-009~011)

### Component Class Reference

Component class values from the TCG Component Class Registry v1.0 rev14. The `componentClassValue` is a 4-byte OCTET STRING where the upper 2 bytes identify the category and the lower 2 bytes the sub-category.

**Microprocessor Components** (`0x0001xxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `00010000` | General Processor | Processor, type unspecified |
| `00010002` | CPU | Central Processing Unit |
| `00010004` | DSP Processor | Digital Signal Processing unit |
| `00010005` | Video Processor | Video signal processing unit |
| `00010006` | GPU | Graphics Processing Unit |
| `00010007` | DPU | Data Processing Unit |
| `00010008` | Embedded processor | Embedded controller |
| `00010009` | SoC | System-on-a-Chip |

**Container Components** (`0x0002xxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `00020002` | Desktop | Desktop computer chassis |
| `00020010` | Main Server Chassis | Rack-mounted server chassis |
| `00020020` | IoT | Internet-of-Things device container |

**IC Board Components** (`0x0003xxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `00030002` | Daughter board | Board extending another board |
| `00030003` | Motherboard | Board with principal components (processor, memory, I/O) |
| `00030004` | Riser Card | Board providing additional slots |

**Module Components** (`0x0004xxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `00040009` | TPM | Discrete Trusted Platform Module |

**Controller Components** (`0x0005xxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `00050004` | Ethernet Controller | Manages Ethernet communications |
| `00050008` | SATA Controller | Serial ATA controller |
| `0005000B` | RAID Controller | Controller of hard disk drives |
| `0005000D` | USB Controller | Universal Serial Bus port controller |
| `00050012` | BMC | Baseboard Management Controller |

**Memory Components** (`0x0006xxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `00060004` | DRAM Memory | Dynamic Random-Access Memory |
| `0006000A` | FLASH Memory | Solid-state non-volatile memory |
| `0006001D` | DDR5 Memory | Double Data Rate 5 RAM |
| `0006001E` | LPDDR5 Memory | Low Power DDR5 |

**Storage Components** (`0x0007xxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `00070003` | SSD Drive | Solid-State Drive |
| `00070004` | M.2 Drive | M.2 SSD drive |
| `00070005` | HDD Drive | Hard Disk Drive |
| `00070006` | NVMe | NVMe subsystem |

**Network Adapter Components** (`0x0009xxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `00090002` | Ethernet Adapter | Ethernet LAN adapter |
| `00090003` | Wi-Fi Adapter | Wi-Fi network adapter |
| `00090004` | Bluetooth Adapter | Bluetooth adapter |
| `00090009` | 5G Cellular Adapter | 5G cellular network adapter |

**Energy Object Components** (`0x000Axxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `000A0002` | Power Supply | Power supplying component |
| `000A0003` | Battery | Battery component |

**Cooling Components** (`0x000Dxxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `000D0004` | Chassis Fan | Cooling fan attached to chassis |
| `000D0005` | Socket Fan | CPU fan |

**Firmware Components** (`0x0013xxxx`):

| Class | Mnemonic | Description |
| --- | --- | --- |
| `00130003` | System firmware | Platform firmware (e.g., UEFI) |
| `00130004` | Drive firmware | Storage device firmware |
| `00130005` | Bootloader | Boot process software |
| `00130007` | NIC firmware | Network Interface Card firmware |

For the full list of all component class values, see [TCG Component Class Registry v1.0 rev14](TCG_Component_Class_Registry_v1.0_rev14_pub.pdf).

**Registry OIDs** (for `componentClass.registry`):

| OID | Name | Registry | Compliance Mode |
| --- | --- | --- | --- |
| `2.23.133.18.3.1` | tcg | TCG Component Class Registry v1.0 | All |
| `2.23.133.18.3.2` | ietf | IETF RFC 8348 IANA Hardware Class | All |
| `2.23.133.18.3.3` | dmtf | DMTF SMBIOS Component Class Registry | All |
| `2.23.133.18.3.4` | pcie | PCIe Component Class Registry | OperationalCompatibility only |
| `2.23.133.18.3.5` | storage | Storage Component Class Registry | OperationalCompatibility only |

In **StrictV11** mode, only `tcg`, `ietf`, and `dmtf` registries are permitted per the original IWG v1.1 specification text. The `pcie` and `storage` registries were published separately and are accepted in **OperationalCompatibility** mode.

---

## Commands in Detail

### generate

Generates a Base Platform Certificate with automatic pre-issuance compliance checking.

```bash
tcg-platform-cert-util generate \
  --config platform-config.yaml \
  --ca-key ca-key.pem \
  --ca-cert ca-cert.pem \
  --ek-cert ek-cert.pem \
  --output platform-cert.pem

# Generate from paccor JSON files via paccor signer
tcg-platform-cert-util generate \
  --use-paccor-signer \
  --config ComponentList_PCUseCase1.json \
  --ca-key TCG_OEM_ecc_p256_TestCA_Leaf.key \
  --ca-cert TCG_OEM_ecc_p256_TestCA_Leaf.pem \
  --ek-cert TCG_EK_ecc_p256_Test.pem \
  --paccor-signer /opt/paccor/bin/signer \
  --paccor-validator /opt/paccor/bin/validator \
  --paccor-cert-serial 23 \
  --paccor-not-before 20180101 \
  --paccor-not-after 20680101 \
  --output TCG_PlatCert_v1.1_PCUseCase1_ecc_p256_Test.pem
```

**Full option list:**

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--ca-key FILE` | `-k` | | CA private key (PEM) **[REQUIRED]** |
| `--ca-cert FILE` | `-c` | | CA certificate (PEM) **[REQUIRED]** |
| `--ek-cert FILE` | `-e` | | TPM EK certificate (PEM) **[REQUIRED]** |
| `--config FILE` | `-f` | | YAML configuration file |
| `--manufacturer NAME` | `-m` | `"Unknown"` | Platform manufacturer |
| `--model NAME` | | `"Unknown"` | Platform model |
| `--version VER` | | `"1.0"` | Platform version |
| `--serial NUM` | `-s` | `"0001"` | Platform serial number |
| `--output FILE` | `-o` | `platform-cert.pem` | Output file |
| `--hash ALG` | | `sha384` | Hash algorithm (`sha256`/`sha384`/`sha512`) |
| `--key-size BITS` | | `2048` | RSA key size |
| `--validity DAYS` | | `365` | Certificate validity period |
| `--skip-compliance` | | | Skip pre-issuance compliance checks |
| `--compat` | | (default) | OperationalCompatibility mode |
| `--strict-v11` | | | Strict IWG v1.1 mode |
| `--use-paccor-signer` | | | Use paccor signer with paccor JSON files |
| `--paccor-extensions FILE` | | `<config-dir>/Extensions.json` | paccor `Extensions.json` path |
| `--paccor-policy FILE` | | `<config-dir>/PolicyReference.json` | paccor `PolicyReference.json` path |
| `--paccor-signer FILE` | | `$PACCOR_SIGNER_PATH` or `/opt/paccor/bin/signer` | paccor signer binary path |
| `--paccor-validator FILE` | | `$PACCOR_VALIDATOR_PATH` or `/opt/paccor/bin/validator` | paccor validator binary path |
| `--paccor-cert-serial NUM` | | `1` | Certificate serial for paccor signer (`-N`) |
| `--paccor-not-before YYYYMMDD` | | `20180101` | `notBefore` for paccor signer (`-b`) |
| `--paccor-not-after YYYYMMDD` | | `20680101` | `notAfter` for paccor signer (`-a`) |
| `--paccor-holder FILE` | | `--ek-cert` | Holder certificate passed to paccor signer (`-e`) |
| `--json` | | | Machine-readable JSON output |

**What happens during generation:**

1. Load and parse configuration (YAML or CLI options)
2. **Layer 1**: Config lint (if `--config` used and `--skip-compliance` not set)
3. Validate hash algorithm and key compatibility
4. Generate the signed certificate
5. Verify the generated certificate internally
6. **Layer 2**: Post-generation compliance check (66 checks)
7. Write the PEM file

### lint

Validates a YAML configuration file without generating a certificate. This is useful for catching configuration errors early.

```bash
# Base config
tcg-platform-cert-util lint platform-config.yaml

# Delta config against Base certificate
tcg-platform-cert-util lint --base base-cert.pem delta-config.yaml

# JSON output for CI
tcg-platform-cert-util lint --json platform-config.yaml

# Show all checks (including passes)
tcg-platform-cert-util lint --verbose platform-config.yaml

# Strict mode (warnings also fail)
tcg-platform-cert-util lint --strict-v11 platform-config.yaml
```

| Option | Short | Description |
| --- | --- | --- |
| `--base FILE` | `-b` | Base certificate for Delta config validation |
| `--compat` | | OperationalCompatibility mode (default) |
| `--strict-v11` | | Strict v1.1 mode |
| `--json` | | JSON output |
| `--verbose` | `-v` | Show all checks including passes |

Without `--verbose`, only warnings and failures are displayed.

### compliance

Runs IWG v1.1 compliance checks on existing PEM certificates.

```bash
# Single certificate
tcg-platform-cert-util compliance platform-cert.pem

# Delta against Base
tcg-platform-cert-util compliance --base base-cert.pem delta-cert.pem

# Chain compliance (Base + Deltas)
tcg-platform-cert-util compliance --chain base.pem delta1.pem delta2.pem

# Verbose with strict mode
tcg-platform-cert-util compliance --verbose --strict-v11 platform-cert.pem

# JSON output for CI
tcg-platform-cert-util compliance --json platform-cert.pem
```

| Option | Short | Description |
| --- | --- | --- |
| `--verbose` | `-v` | Per-check details with spec references |
| `--base FILE` | `-b` | Base certificate for Delta comparison |
| `--chain` | | Chain compliance mode |
| `--compat` | | OperationalCompatibility profile (default) |
| `--strict-v11` | | Strict v1.1 profile |
| `--json` | | JSON output |

### show

Displays certificate details: serial number, version, validity period, platform information, TCG attributes, component details, and ASN.1 structure.

```bash
tcg-platform-cert-util show platform-cert.pem
tcg-platform-cert-util show --verbose platform-cert.pem
```

### validate

Validates certificate structure, checks validity period, and optionally verifies the cryptographic signature.

```bash
tcg-platform-cert-util validate platform-cert.pem
tcg-platform-cert-util validate --ca-cert ca-cert.pem platform-cert.pem
```

Supports RSA, ECDSA, DSA, Ed25519, and Ed448 signatures.

### components

Lists all platform components with manufacturer, model, serial, revision, component class, and addresses.

```bash
tcg-platform-cert-util components platform-cert.pem
tcg-platform-cert-util components --verbose platform-cert.pem
```

### generate-delta

Generates a Delta Platform Certificate tracking hardware changes.

```bash
tcg-platform-cert-util generate-delta \
  --base-cert base-cert.pem \
  --config delta-config.yaml \
  --ca-key ca-key.pem \
  --ca-cert ca-cert.pem \
  --output delta-cert.pem
```

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--base-cert FILE` | `-b` | | Base platform certificate **[REQUIRED]** |
| `--ca-key FILE` | `-k` | | CA private key **[REQUIRED]** |
| `--ca-cert FILE` | `-c` | | CA certificate **[REQUIRED]** |
| `--config FILE` | `-f` | | Delta YAML configuration |
| `--output FILE` | `-o` | `delta-cert.pem` | Output file |
| `--hash ALG` | | `sha384` | Hash algorithm |

### create-config

Generates a template YAML file with all available configuration fields.

```bash
tcg-platform-cert-util create-config my-platform.yaml
```

If no filename is given, defaults to `platform-config.yaml`.

### convert

Converts [paccor](https://github.com/nsacyber/paccor) (NSA Platform Attribute Certificate Creator) JSON format to the YAML format used by this tool.

```bash
tcg-platform-cert-util convert paccor-output.json --output platform.yaml
tcg-platform-cert-util convert --from-paccor device.json
```

---

## Compliance Modes

Two compliance assessment profiles are available:

### OperationalCompatibility (default)

Relaxed mode for real-world interoperability:

- Permits all 5 registry OIDs: `tcg`, `ietf`, `dmtf`, `pcie`, `storage`
- Warnings do not block certificate generation
- Lint exit code 2 for warnings-only (no failures)

### StrictV11

Strict interpretation of the IWG v1.1 specification text:

- Permits only 3 registry OIDs: `tcg`, `ietf`, `dmtf`
- Warnings are treated as failures
- Lint exit code 1 for any warnings or failures

Select with `--compat` (default) or `--strict-v11`. These flags are mutually exclusive.

---

## Pre-Issuance Compliance

The `generate` command runs a two-layer compliance check before writing the certificate:

### Layer 1: Config Lint

Validates the YAML configuration before certificate generation. This catches errors that would inevitably fail in Layer 2, saving time.

- Runs automatically when `--config` is provided
- Skipped with `--skip-compliance`
- Blocking: Must-level failures stop generation immediately

### Layer 2: Post-Generation Compliance

Runs the full 66-check compliance suite on the generated certificate (before writing to disk).

- Catches issues that can only be detected on the encoded certificate
- Non-compliant certificates are not written to disk

### Standalone Lint

Use the `lint` command for standalone config validation:

```bash
tcg-platform-cert-util lint platform-config.yaml
tcg-platform-cert-util lint --base base-cert.pem delta-config.yaml
```

---

## Lint Check Reference

### Preflight Checks

These map to the 66 compliance checks but run on the YAML config:

| Check ID | Level | Description |
| --- | --- | --- |
| VAL-001 | Must | `manufacturer` is non-empty |
| VAL-002 | Must | `model` is non-empty |
| VAL-003 | Must | `version` is non-empty |
| VAL-004 | Must | `serial` is non-empty |
| VAL-005 | May | `manufacturerId` is valid OID format |
| VAL-006 | Must | `evalAssuranceLevel` in range 1~7 |
| VAL-007 | Must | `strengthOfFunction` is valid enum |
| VAL-008 | Must | `fipsSecurityLevel` in range 1~4 |
| VAL-009 | Must | `fipsVersion` is non-empty (if fipsSecurityLevel set) |
| VAL-010 | Must | `iso9000Certified` is boolean |
| VAL-011 | Must | Component `manufacturer` and `model` are non-empty |
| VAL-012 | Must | `componentClassRegistry` is a known OID |
| VAL-013 | Must | `componentClassValue` is 8 hex digits (4 bytes) |
| VAL-017 | Must | `rtmType` is valid enum |
| STR-011 | Should | Platform Specification version is present |
| STR-012 | Should | Credential type is correct for config type |
| STR-013 | Should | Credential Specification version is present |
| SEC-001 | MustNot | Delta config lacks `securityAssertions` |
| SEC-002 | MustNot | Delta config lacks `platformSpec` |
| SEC-005 | Must | URI hash pair co-existence (G-002) |
| DLT-008 | Must | Delta component has `status` field |
| DLT-009 | Must | Delta `manufacturer` matches Base |
| DLT-010 | Must | Delta `model` matches Base |
| DLT-011 | Must | Delta `version` matches Base |

### Config-Only Checks

These are unique to lint and have no corresponding compliance check:

| Check ID | Level | Description |
| --- | --- | --- |
| CFG-001 | Should | No duplicate component serial numbers |
| CFG-002 | Must | All string fields are UTF-8 encodable |
| CFG-003 | Should | Component class values within known registry ranges |

### General Guards

| Check ID | Level | Description |
| --- | --- | --- |
| G-002 | Must | URI `hashAlgorithm` and `hashValue` must both exist or both be absent |
| G-003 | Should | URI length does not exceed URIMAX (2048 characters) |
| G-004 | Should | String length does not exceed STRMAX (256 characters) |

---

## Chain Compliance

Chain compliance validates integrity across a certificate chain (one Base + N Delta certificates).

```bash
tcg-platform-cert-util compliance --chain base.pem delta1.pem delta2.pem
```

Five cross-certificate checks are performed:

| Check | Level | Description |
| --- | --- | --- |
| CHAIN-001 | Must | Platform identity (manufacturer/model/version) is consistent across all certificates |
| CHAIN-002 | Should | Delta serial numbers are strictly ascending |
| CHAIN-003 | Must | Component state transitions are valid (no MODIFY on non-existent, no duplicate ADD, etc.) |
| CHAIN-004 | Must | Each Delta's holder references the Base or a preceding Delta |
| CHAIN-005 | -- | Computes final platform state (active components after all deltas applied) |

### Valid State Transitions

| Current State | ADDED | MODIFIED | REMOVED |
| --- | --- | --- | --- |
| Not present | Valid | Invalid | Invalid |
| Present | Invalid | Valid | Valid |
| Added | Invalid | Valid | Valid |
| Removed | Valid (re-add) | Invalid | Invalid |

---

## JSON Output

All commands that support `--json` produce a structured JSON report suitable for CI/CD pipelines.

### Lint JSON

```json
{
  "tool": "tcg-platform-cert-util",
  "version": "0.1.0",
  "command": "lint",
  "timestamp": "2026-02-07T12:00:00Z",
  "mode": "OperationalCompatibility",
  "certType": null,
  "subject": null,
  "layers": {
    "configLint": {
      "executed": true,
      "results": [
        {
          "checkId": "VAL-001",
          "level": "Must",
          "status": "Pass",
          "message": "platformManufacturerStr is valid",
          "suggestion": null
        }
      ],
      "summary": { "pass": 15, "fail": 0, "warn": 2 }
    },
    "compliance": null
  },
  "compliant": true,
  "outputFile": null,
  "exitCode": 0
}
```

### Compliance JSON

```json
{
  "tool": "tcg-platform-cert-util",
  "version": "0.1.0",
  "command": "compliance",
  "timestamp": "2026-02-07T12:00:00Z",
  "mode": "OperationalCompatibility",
  "layers": {
    "configLint": null,
    "compliance": {
      "totalChecks": 66,
      "passed": 64,
      "failed": 2,
      "categories": [...]
    }
  },
  "compliant": false,
  "exitCode": 1
}
```

### Chain Compliance JSON

```json
{
  "tool": "tcg-platform-cert-util",
  "version": "0.1.0",
  "command": "compliance --chain",
  "layers": {
    "configLint": null,
    "compliance": {
      "base": "base.pem",
      "deltaCount": 2,
      "mode": "OperationalCompatibility",
      "checks": [
        { "checkId": "CHAIN-001", "level": "Must", "status": "Pass", "message": "..." },
        { "checkId": "CHAIN-002", "level": "Should", "status": "Pass", "message": "..." }
      ],
      "finalState": { "activeComponents": 5, "deltasApplied": 2 },
      "compliant": true
    }
  },
  "compliant": true,
  "exitCode": 0
}
```

### Generate JSON

When `--json` is passed to `generate`, JSON output replaces all text output:

```json
{
  "command": "generate",
  "layers": {
    "configLint": { "executed": true, "results": [...], "summary": {...} },
    "compliance": null
  },
  "compliant": true,
  "outputFile": "platform-cert.pem",
  "exitCode": 0
}
```

---

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Success -- all checks passed |
| 1 | Failure -- compliance failures, config errors, file I/O errors |
| 2 | Warnings only -- OperationalCompatibility mode, lint command only |

**Mode-specific behavior:**

- **OperationalCompatibility**: exit 1 on failures, exit 2 on warnings-only, exit 0 on clean
- **StrictV11**: exit 1 on any failures or warnings, exit 0 on clean

---

## Troubleshooting

### "Error: --compat and --strict-v11 cannot be used together."

These flags are mutually exclusive. Use one or the other (or neither for the default OperationalCompatibility mode).

### Lint shows warnings but generate succeeds

In OperationalCompatibility mode, `Should`-level checks produce warnings but do not block generation. To enforce all warnings, use `--strict-v11`.

### "Pre-issuance config lint FAILED"

Layer 1 config lint found `Must`-level failures. Fix the YAML configuration and retry. Run `lint --verbose` to see all checks including passes.

### "Post-generation compliance check FAILED"

Layer 2 found issues in the generated certificate that could not be detected at the config level. Review the compliance output and adjust the configuration.

### Delta identity mismatch (DLT-009~011)

The Delta certificate's `manufacturer`, `model`, or `version` does not match the Base certificate. These fields must be identical.

### "Cannot MODIFY non-existent component" (CHAIN-003)

A Delta certificate attempts to modify a component that is not present in the current platform state. Ensure the component was added in the Base or a preceding Delta.

### Hash algorithm ignored for Ed25519/Ed448

Ed25519 and Ed448 use intrinsic hashing. The `--hash` option has no effect when using these key types.

### Large URI warnings (G-003)

URIs exceeding 2048 characters trigger a warning. While not a hard failure in OperationalCompatibility mode, consider shortening the URI.

### String exceeding STRMAX (G-004)

String fields exceeding 256 characters trigger a warning. The IWG specification defines STRMAX as the recommended maximum length for UTF8String fields.

---

## Cryptographic Support

### Signature Algorithms

| Algorithm | Auto-detected | Notes |
| --- | --- | --- |
| RSA (PKCS#1 v1.5) | Yes | Most common for Platform Certificates |
| ECDSA | Yes | Recommended for new deployments |
| DSA | Yes | Legacy support |
| Ed25519 | Yes | Intrinsic hashing, `--hash` ignored |
| Ed448 | Yes | Intrinsic hashing, `--hash` ignored |

### Hash Algorithms

| Algorithm | Flag | Notes |
| --- | --- | --- |
| SHA-256 | `--hash sha256` | Widely supported |
| SHA-384 | `--hash sha384` | Default, CNSA 2.0 recommended |
| SHA-512 | `--hash sha512` | Maximum security |

---

## Example Workflows

### Quick Start: Generate and Test

```bash
# 1. Create a config template
tcg-platform-cert-util create-config my-platform.yaml
# Edit my-platform.yaml with your platform details

# 2. Validate the config
tcg-platform-cert-util lint my-platform.yaml

# 3. Generate the certificate
tcg-platform-cert-util generate \
  --config my-platform.yaml \
  --ca-key ca-key.pem --ca-cert ca-cert.pem --ek-cert ek-cert.pem

# 4. Inspect and test
tcg-platform-cert-util show platform-cert.pem
tcg-platform-cert-util compliance --verbose platform-cert.pem
```

### Delta Certificate Lifecycle

```bash
# Generate Base certificate
tcg-platform-cert-util generate --config server.yaml \
  --ca-key ca-key.pem --ca-cert ca-cert.pem --ek-cert ek-cert.pem \
  --output base.pem

# After hardware change: validate Delta config against Base
tcg-platform-cert-util lint --base base.pem delta-config.yaml

# Generate Delta certificate
tcg-platform-cert-util generate-delta --base-cert base.pem \
  --config delta-config.yaml \
  --ca-key ca-key.pem --ca-cert ca-cert.pem --output delta.pem

# Verify the full chain
tcg-platform-cert-util compliance --chain base.pem delta.pem
```

### CI/CD Integration

```bash
#!/bin/bash
set -e

# Lint with strict mode -- any warnings fail the build
tcg-platform-cert-util lint --json --strict-v11 config.yaml > lint-report.json

# Generate certificate
tcg-platform-cert-util generate \
  --config config.yaml \
  --ca-key "$CA_KEY" --ca-cert "$CA_CERT" --ek-cert "$EK_CERT" \
  --strict-v11 --json --output cert.pem > generate-report.json

# Full compliance check
tcg-platform-cert-util compliance --json --strict-v11 cert.pem > compliance-report.json
```

### Convert from paccor

```bash
# Convert paccor JSON to YAML
tcg-platform-cert-util convert paccor-output.json --output device.yaml

# Review and optionally edit the converted config
tcg-platform-cert-util lint device.yaml

# Generate certificate
tcg-platform-cert-util generate --config device.yaml \
  --ca-key ca-key.pem --ca-cert ca-cert.pem --ek-cert ek-cert.pem
```
