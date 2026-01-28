# haskell-tcg-cert

Haskell libraries for TCG (Trusted Computing Group) Platform Certificates.

## Packages

- **platform-hardware-info**: Cross-platform hardware information collection
- **tcg-platform-cert**: TCG Platform Certificate data types and ASN.1 processing
- **tcg-platform-cert-validation**: TCG Platform Certificate validation
- **tcg-platform-cert-util**: CLI utilities for TCG certificate operations

## Requirements

This library depends on [crypton-certificate](https://github.com/kazu-yamamoto/crypton-certificate) for X.509 and Attribute Certificate support.

## Building

```bash
stack build
```

## License

BSD-3-Clause
