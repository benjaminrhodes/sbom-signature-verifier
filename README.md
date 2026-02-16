# SBOM Signature Verifier

Verify SBOM integrity and signatures for SPDX and CycloneDX formats.

## Features

- Parse SPDX (tag-value) and CycloneDX (JSON) SBOM formats
- Verify package integrity via SHA256/SHA512 checksums
- Verify cryptographic signatures
- CLI interface for easy integration

## Installation

```bash
pip install sbom-signature-verifier
```

## Usage

```bash
# Parse and display SBOM
python -m src.cli parse sample.spdx.txt

# Verify integrity
python -m src.cli verify sample.spdx.txt --directory /path/to/packages

# Verify with signature
python -m src.cli verify sample.spdx.txt --key public_key.pem
```

## Testing

```bash
pytest tests/ -v
pytest tests/ --cov=src --cov-report=term-missing
```

## Security

- Uses synthetic/test data only
- No real credentials or production systems

## License

MIT
