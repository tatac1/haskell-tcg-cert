# haskell-tcg-cert

Haskell libraries and CLI tool for generating, validating, and testing [TCG Platform Certificates](https://trustedcomputinggroup.org/resource/tcg-platform-certificate-profile/) per the IWG Platform Certificate Profile v1.1.

## Packages

| Package | Description |
|---------|-------------|
| **tcg-platform-cert** | Core data types, ASN.1/DER encoding and decoding |
| **tcg-platform-cert-compliance** | IWG v1.1 compliance framework (66 checks + chain compliance) |
| **tcg-platform-cert-util** | CLI tool for generation, lint, compliance, and inspection |
| **tcg-platform-cert-validation** | Certificate validation and signature verification |
| **platform-hardware-info** | Cross-platform hardware information collection |

## Quick Start

### Install

Download a pre-built binary from [Releases](https://github.com/tatac1/haskell-tcg-cert/releases):

| Platform | Binary |
| --- | --- |
| Linux x86_64 | `tcg-platform-cert-util-*-linux-x86_64` (static, musl) |
| Linux aarch64 | `tcg-platform-cert-util-*-linux-aarch64` (static, musl) |
| macOS Universal | `tcg-platform-cert-util-*-macos-universal` |
| Windows x86_64 | `tcg-platform-cert-util-*-windows-x86_64.exe` |

### Build from Source

Requires GHC 9.6+ and Cabal 3.10+.

```bash
cabal update && cabal build all
cabal test all    # run all tests
```

Or with Stack: `stack build`

## CLI Commands

```text
tcg-platform-cert-util <command> [options]

  generate        Generate a Base Platform Certificate
  generate-delta  Generate a Delta Platform Certificate
  show            Display certificate details
  validate        Validate a certificate
  components      Extract component information
  compliance      Run IWG v1.1 compliance checks
  lint            Validate a YAML configuration before generation
  create-config   Create an example YAML configuration file
  convert         Convert paccor JSON to YAML format
```

### generate

Generate a Base Platform Certificate with pre-issuance compliance checking.

```bash
# From a YAML config (recommended)
tcg-platform-cert-util generate \
  --config platform-config.yaml \
  --ca-key ca-key.pem --ca-cert ca-cert.pem --ek-cert ek-cert.pem

# From command-line options
tcg-platform-cert-util generate \
  --manufacturer "Acme Corp" --model "Server X1" --version "1.0" \
  --ca-key ca-key.pem --ca-cert ca-cert.pem --ek-cert ek-cert.pem

# From paccor config files (auto-detects PolicyReference.json + Extensions.json)
tcg-platform-cert-util generate \
  --config ComponentList_PCUseCase1.json \
  --ca-key ca-key.pem --ca-cert ca-cert.pem \
  --ek-cert ek-cert.pem \
  --output platform-cert.pem

# With explicit paths for PolicyReference and Extensions
tcg-platform-cert-util generate \
  --config ComponentList.json \
  --policy-ref PolicyReference.json \
  --extensions Extensions.json \
  --ca-key ca-key.pem --ca-cert ca-cert.pem \
  --ek-cert ek-cert.pem \
  --output platform-cert.pem
```

| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `--ca-key FILE` | `-k` | Yes | CA private key (PEM) |
| `--ca-cert FILE` | `-c` | Yes | CA certificate (PEM) |
| `--ek-cert FILE` | `-e` | Yes | TPM EK certificate (PEM) |
| `--config FILE` | `-f` | No | YAML config file (replaces `--manufacturer`/`--model`/`--version`) |
| `--manufacturer NAME` | `-m` | Yes* | Platform manufacturer (*or use `--config`) |
| `--model NAME` | | Yes* | Platform model |
| `--version VER` | | Yes* | Platform version |
| `--serial NUM` | `-s` | No | Platform serial number |
| `--output FILE` | `-o` | No | Output file (default: `platform-cert.pem`) |
| `--hash ALG` | | No | `sha256` / `sha384` / `sha512` (default: `sha384`) |
| `--key-size BITS` | | No | RSA key size (default: 2048) |
| `--validity DAYS` | | No | Validity period (default: 365) |
| `--skip-compliance` | | No | Skip pre-issuance compliance checks |
| `--compat` | | No | OperationalCompatibility mode (default) |
| `--strict-v11` | | No | Strict IWG v1.1 mode |
| `--policy-ref FILE` | | No | `PolicyReference.json` path (auto-detected from `--config` dir) |
| `--extensions FILE` | | No | `Extensions.json` path (auto-detected from `--config` dir) |
| `--json` | | No | Output results as JSON |

Pre-issuance checking runs automatically unless `--skip-compliance` is set:

- **Layer 1 (Config Lint)**: validates YAML config against spec rules before generation
- **Layer 2 (Post-generation Compliance)**: runs 66 compliance checks on the generated certificate

### lint

Validate a YAML configuration file without generating a certificate.

```bash
# Lint a Base config
tcg-platform-cert-util lint platform-config.yaml

# Lint a Delta config against a Base certificate
tcg-platform-cert-util lint --base base-cert.pem delta-config.yaml

# JSON output for CI integration
tcg-platform-cert-util lint --json platform-config.yaml

# Verbose: show passing checks too
tcg-platform-cert-util lint --verbose platform-config.yaml
```

| Option | Short | Description |
|--------|-------|-------------|
| `--base FILE` | `-b` | Base certificate for Delta config validation |
| `--compat` | | OperationalCompatibility mode (default) |
| `--strict-v11` | | Strict v1.1 mode (warnings also cause failure) |
| `--json` | | JSON output |
| `--verbose` | `-v` | Show all checks including passes |

Lint checks include:

- **Preflight checks**: VAL-001~013, STR-011~013, SEC-001~005, DLT-008~012, REG-001~002, ERR-003
- **Config-only checks**: CFG-001 (duplicate serials), CFG-002 (UTF-8 encodability), CFG-003 (registry range)
- **General guards**: G-002 (URI hash pairs), G-003 (URI length), G-004 (STRMAX overflow)

### compliance

Run IWG v1.1 compliance checks on existing certificates.

```bash
# Single certificate
tcg-platform-cert-util compliance platform-cert.pem

# Delta against Base
tcg-platform-cert-util compliance --base base-cert.pem delta-cert.pem

# Chain compliance (Base + Deltas)
tcg-platform-cert-util compliance --chain base.pem delta1.pem delta2.pem

# Strict mode with JSON output
tcg-platform-cert-util compliance --strict-v11 --json platform-cert.pem
```

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Per-check details and spec references |
| `--base FILE` | `-b` | Base certificate for Delta comparison |
| `--chain` | | Chain compliance mode (first file = Base, rest = Deltas) |
| `--compat` | | OperationalCompatibility profile (default) |
| `--strict-v11` | | Strict v1.1 profile |
| `--json` | | JSON output |

66 compliance checks across 8 categories:

| Category | Checks | Description |
|----------|--------|-------------|
| STR | 13 | Certificate structure (version, holder, issuer, serial, validity, extensions) |
| VAL | 17 | Field value validation (platform info, components, security assertions) |
| DLT | 12 | Delta certificate requirements (base consistency, status, credential type) |
| CHN | 5 | Chain requirements (AKI, AIA, CRL DP, targeting information) |
| REG | 4 | Component Class Registry conformance (TCG/SMBIOS/PCIe/Storage) |
| EXT | 5 | Extension requirements (certificate policies, SAN, issuer unique ID) |
| SEC | 5 | Security assertions constraints (TBB, measurement root, URI hash pairs) |
| ERR | 5 | Errata v3 corrections (order independence, MAC format, PEN as OID) |

Chain compliance (`--chain`) runs 5 additional cross-certificate checks:

| Check | Description |
|-------|-------------|
| CHAIN-001 | Platform identity consistency across all certificates |
| CHAIN-002 | Delta serial number ordering (strictly ascending) |
| CHAIN-003 | Component state transition validity (ADD/MODIFY/REMOVE) |
| CHAIN-004 | Holder reference chain validation |
| CHAIN-005 | Final platform state computation |

**Compliance modes:**

- **OperationalCompatibility** (default): permits `tcg/ietf/dmtf/pcie/storage` registry OIDs
- **StrictV11**: permits only `tcg/ietf/dmtf` per the original v1.1 text

### show / validate / components

```bash
tcg-platform-cert-util show platform-cert.pem
tcg-platform-cert-util show --verbose platform-cert.pem

tcg-platform-cert-util validate platform-cert.pem
tcg-platform-cert-util validate --ca-cert ca-cert.pem platform-cert.pem

tcg-platform-cert-util components platform-cert.pem
```

### generate-delta

```bash
tcg-platform-cert-util generate-delta \
  --base-cert base-cert.pem \
  --config delta-config.yaml \
  --ca-key ca-key.pem --ca-cert ca-cert.pem
```

### create-config / convert

```bash
tcg-platform-cert-util create-config my-platform.yaml
tcg-platform-cert-util convert paccor-output.json --output platform.yaml
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / all checks passed |
| 1 | Failure (compliance failures, config errors, file errors) |
| 2 | Warnings only (OperationalCompatibility mode, lint command) |

In **StrictV11** mode, warnings are treated as failures (exit code 1).

## JSON Output

The `--json` flag produces machine-readable output for CI/CD integration:

```json
{
  "tool": "tcg-platform-cert-util",
  "version": "0.1.0",
  "command": "lint",
  "timestamp": "2026-02-07T12:00:00Z",
  "mode": "OperationalCompatibility",
  "layers": {
    "configLint": {
      "executed": true,
      "results": [...],
      "summary": { "pass": 15, "fail": 0, "warn": 2 }
    }
  },
  "compliant": true,
  "exitCode": 0
}
```

## Typical Workflows

### 1. Generate and validate

```bash
tcg-platform-cert-util create-config my-platform.yaml
# Edit my-platform.yaml

tcg-platform-cert-util lint my-platform.yaml
tcg-platform-cert-util generate \
  --config my-platform.yaml \
  --ca-key ca-key.pem --ca-cert ca-cert.pem --ek-cert ek-cert.pem
tcg-platform-cert-util show platform-cert.pem
tcg-platform-cert-util compliance platform-cert.pem
```

### 2. Delta certificate lifecycle

```bash
tcg-platform-cert-util generate --config server.yaml \
  --ca-key ca-key.pem --ca-cert ca-cert.pem --ek-cert ek-cert.pem \
  --output base.pem

# After hardware change
tcg-platform-cert-util lint --base base.pem delta-config.yaml
tcg-platform-cert-util generate-delta --base-cert base.pem \
  --config delta-config.yaml \
  --ca-key ca-key.pem --ca-cert ca-cert.pem --output delta.pem

tcg-platform-cert-util compliance --chain base.pem delta.pem
```

### 3. CI/CD pipeline

```bash
tcg-platform-cert-util lint --json --strict-v11 config.yaml > lint.json
tcg-platform-cert-util compliance --json --strict-v11 cert.pem > compliance.json
```

### 4. Convert from paccor

```bash
tcg-platform-cert-util convert paccor-output.json --output device.yaml
tcg-platform-cert-util generate --config device.yaml \
  --ca-key ca-key.pem --ca-cert ca-cert.pem --ek-cert ek-cert.pem
```

## YAML Configuration

See the [User Guide](docs/user-guide.md) for the full YAML reference and [examples/](tcg-platform-cert-util/examples/) for ready-to-use configurations.

### Example Configurations

| File | Platform |
|------|----------|
| `enterprise-server.yaml` | Dell PowerEdge R750 (dual Xeon, 64GB DDR4, NVMe, 25GbE, TPM 2.0) |
| `workstation.yaml` | HP Z4 G5 (Xeon W-2245, NVIDIA RTX A4000) |
| `iot-device.yaml` | Raspberry Pi 4 Model B (ARM Cortex-A72, WiFi/BT/Ethernet) |
| `edge-gateway.yaml` | Advantech ARK-3531L (NXP i.MX 8M Plus, 5G cellular) |
| `embedded-system.yaml` | STM32MP157F Discovery Kit (dual Cortex-A7 + M4) |
| `congatec-pa5-embedded.yaml` | Congatec PA5 embedded platform |
| `*-delta.yaml` | Corresponding delta certificates for each platform |

## Cryptographic Support

| Category | Supported |
|----------|-----------|
| Signature | RSA (PKCS#1 v1.5), ECDSA, DSA, Ed25519, Ed448 |
| Hash | SHA-256, **SHA-384** (default, CNSA 2.0), SHA-512 |

Key type is auto-detected. Ed25519/Ed448 use intrinsic hashing (`--hash` is ignored).

## Documentation

- **[User Guide](docs/user-guide.md)** -- YAML reference, lint checks, compliance modes, troubleshooting
- **[Compliance Test Guide](docs/compliance-test-guide.md)** -- full 66-check specification with normative interpretation
- **[Examples](tcg-platform-cert-util/examples/)** -- ready-to-use YAML configurations

## Reference Specifications

- [IWG Platform Certificate Profile v1.1 R19](docs/IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.pdf)
- [Platform Certificate Profile v1.1 R19 Errata v3](docs/TCG_PlatformCertificateProfilev1p1_r19_Errata_v3_pub.pdf)
- [TCG Component Class Registry v1.0 rev14](docs/TCG_Component_Class_Registry_v1.0_rev14_pub.pdf)
- [SMBIOS Component Class Registry v1.01](docs/SMBIOS-Component-Class-Registry_v1.01_finalpublication.pdf)
- [PCIe Component Class Registry v1 r18](docs/TCG_PCIe_Component_Class_Registry_v1_r18_pub10272021.pdf)
- [Storage Component Class Registry v1.0 rev22](docs/Storage-Component-Class-Registry-Version-1.0-Revision-22_pub.pdf)

## Requirements

Depends on [crypton-certificate](https://github.com/kazu-yamamoto/crypton-certificate) with Attribute Certificate support.

## License

BSD-3-Clause
