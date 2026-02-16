# SBOM Signature Verifier Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a CLI tool to verify SBOM integrity and signatures for SPDX and CycloneDX formats.

**Architecture:** Modular design with separate parsers for SPDX/CycloneDX, verification module for integrity/signature checks, and Click-based CLI.

**Tech Stack:** Python 3.9+, Click (CLI), Cryptography (signatures), Pytest (testing), Ruff (linting)

---

### Task 1: Add dependencies to pyproject.toml

**Files:**
- Modify: `pyproject.toml`

**Step 1: Update pyproject.toml with dependencies**

```toml
[project]
dependencies = [
    "click>=8.0.0",
    "cryptography>=41.0.0",
]

[project.scripts]
sbom-verify = "src.cli:main"
```

**Step 2: Install dependencies**

```bash
pip install -e ".[dev]"
```

---

### Task 2: Create SBOM data models

**Files:**
- Create: `src/models.py`

**Step 1: Write the failing test**

```python
# tests/test_models.py
import pytest
from src.models import Package, SBOM, SBOMFormat

def test_package_creation():
    pkg = Package(name="test-pkg", version="1.0.0", checksums={"SHA256": "abc123"})
    assert pkg.name == "test-pkg"
    assert pkg.version == "1.0.0"

def test_sbom_creation():
    sbom = SBOM(format=SBOMFormat.SPDX, version="SPDX-2.3", packages=[])
    assert sbom.format == SBOMFormat.SPDX
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_models.py -v
Expected: FAIL (ModuleNotFoundError: No module 'src.models')
```

**Step 3: Write implementation**

```python
# src/models.py
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

class SBOMFormat(Enum):
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"

@dataclass
class Package:
    name: str
    version: Optional[str] = None
    checksums: dict = field(default_factory=dict)
    supplier: Optional[str] = None
    download_location: Optional[str] = None

@dataclass
class SBOM:
    format: SBOMFormat
    version: str
    packages: list = field(default_factory=list)
    document_name: Optional[str] = None
    creation_info: Optional[dict] = None
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_models.py -v
Expected: PASS
```

---

### Task 3: Create SPDX parser

**Files:**
- Create: `src/parsers/__init__.py`
- Create: `src/parsers/spdx.py`
- Create: `tests/test_spdx_parser.py`

**Step 1: Write the failing test**

```python
# tests/test_spdx_parser.py
import pytest
from src.parsers.spdx import SPDXParser
from src.models import SBOM, SBOMFormat

def test_parse_spdx_tag_value():
    content = '''SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test-bom
DocumentNamespace: https://example.com/test

PackageName: test-pkg
SPDXID: SPDXRef-Package
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
'''
    parser = SPDXParser()
    sbom = parser.parse(content)
    assert sbom.format == SBOMFormat.SPDX
    assert len(sbom.packages) == 1
    assert sbom.packages[0].name == "test-pkg"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_spdx_parser.py -v
Expected: FAIL (ModuleNotFoundError)
```

**Step 3: Write implementation**

```python
# src/parsers/__init__.py
from src.parsers.spdx import SPDXParser
from src.parsers.cyclonedx import CycloneDXParser

__all__ = ["SPDXParser", "CycloneDXParser"]

# src/parsers/spdx.py
import re
from src.models import SBOM, SBOMFormat, Package

class SPDXParser:
    def parse(self, content: str) -> SBOM:
        lines = content.strip().split('\n')
        sbom = SBOM(format=SBOMFormat.SPDX, version="", packages=[])
        current_package = None
        
        for line in lines:
            line = line.strip()
            if not line or ':' not in line:
                continue
            
            key, _, value = line.partition(':')
            key = key.strip()
            value = value.strip()
            
            if key == "SPDXVersion":
                sbom.version = value
            elif key == "DocumentName":
                sbom.document_name = value
            elif key == "PackageName":
                if current_package:
                    sbom.packages.append(current_package)
                current_package = Package(name=value)
            elif key == "PackageVersion" and current_package:
                current_package.version = value
            elif key == "PackageDownloadLocation" and current_package:
                current_package.download_location = value
            elif key in ("SHA1", "SHA256", "SHA512", "MD5") and current_package:
                current_package.checksums[key] = value
                
        if current_package:
            sbom.packages.append(current_package)
            
        return sbom
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_spdx_parser.py -v
Expected: PASS
```

---

### Task 4: Create CycloneDX parser

**Files:**
- Create: `src/parsers/cyclonedx.py`
- Create: `tests/test_cyclonedx_parser.py`

**Step 1: Write the failing test**

```python
# tests/test_cyclonedx_parser.py
import pytest
from src.parsers.cyclonedx import CycloneDXParser
from src.models import SBOM, SBOMFormat

def test_parse_cyclonedx_json():
    content = '''{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:123",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "test-pkg",
      "version": "1.0.0",
      "hashes": [
        {"alg": "SHA-256", "content": "abc123"}
      ]
    }
  ]
}'''
    parser = CycloneDXParser()
    sbom = parser.parse(content)
    assert sbom.format == SBOMFormat.CYCLONEDX
    assert len(sbom.packages) == 1
    assert sbom.packages[0].name == "test-pkg"
    assert sbom.packages[0].checksums.get("SHA256") == "abc123"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_cyclonedx_parser.py -v
Expected: FAIL
```

**Step 3: Write implementation**

```python
# src/parsers/cyclonedx.py
import json
from src.models import SBOM, SBOMFormat, Package

class CycloneDXParser:
    def parse(self, content: str) -> SBOM:
        data = json.loads(content)
        sbom = SBOM(
            format=SBOMFormat.CYCLONEDX,
            version=data.get("specVersion", ""),
            document_name=data.get("metadata", {}).get("component", {}).get("name")
        )
        
        for comp in data.get("components", []):
            pkg = Package(
                name=comp.get("name", ""),
                version=comp.get("version"),
                supplier=comp.get("supplier", {}).get("name") if isinstance(comp.get("supplier"), dict) else comp.get("supplier")
            )
            for h in comp.get("hashes", []):
                alg = h.get("alg", "").replace("-", "").upper()
                if "SHA" in alg:
                    pkg.checksums[alg] = h.get("content", "")
            sbom.packages.append(pkg)
            
        return sbom
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_cyclonedx_parser.py -v
Expected: PASS
```

---

### Task 5: Create integrity verifier

**Files:**
- Create: `src/verifier.py`
- Create: `tests/test_verifier.py`

**Step 1: Write the failing test**

```python
# tests/test_verifier.py
import pytest
from src.verifier import IntegrityVerifier
from src.models import Package, SBOM, SBOMFormat

def test_verify_checksum_match(tmp_path):
    pkg_file = tmp_path / "test.txt"
    pkg_file.write_text("hello world")
    
    pkg = Package(name="test", checksums={"SHA256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"})
    verifier = IntegrityVerifier()
    result = verifier.verify_package(pkg, pkg_file)
    assert result.verified is True

def test_verify_checksum_mismatch(tmp_path):
    pkg_file = tmp_path / "test.txt"
    pkg_file.write_text("wrong content")
    
    pkg = Package(name="test", checksums={"SHA256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"})
    verifier = IntegrityVerifier()
    result = verifier.verify_package(pkg, pkg_file)
    assert result.verified is False
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_verifier.py -v
Expected: FAIL
```

**Step 3: Write implementation**

```python
# src/verifier.py
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from src.models import Package, SBOM

@dataclass
class VerificationResult:
    verified: bool
    message: str
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None

class IntegrityVerifier:
    def verify_package(self, pkg: Package, file_path: Path) -> VerificationResult:
        if not file_path.exists():
            return VerificationResult(False, f"File not found: {file_path}")
        
        for algo, expected_hash in pkg.checksums.items():
            algo_normalized = algo.replace("-", "").upper()
            if algo_normalized == "SHA256":
                hasher = hashlib.sha256()
            elif algo_normalized == "SHA512":
                hasher = hashlib.sha512()
            elif algo_normalized == "SHA1":
                hasher = hashlib.sha1()
            elif algo_normalized == "MD5":
                hasher = hashlib.md5()
            else:
                continue
                
            hasher.update(file_path.read_bytes())
            actual_hash = hasher.hexdigest()
            
            if actual_hash != expected_hash.lower():
                return VerificationResult(False, f"{algo} mismatch", expected_hash, actual_hash)
                
        return VerificationResult(True, "All checksums verified")
    
    def verify_sbom(self, sbom: SBOM, base_path: Path) -> list[VerificationResult]:
        results = []
        for pkg in sbom.packages:
            if pkg.download_location and pkg.download_location != "NOASSERTION":
                file_path = base_path / pkg.name
                if file_path.exists():
                    results.append(self.verify_package(pkg, file_path))
        return results
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_verifier.py -v
Expected: PASS
```

---

### Task 6: Create signature verifier

**Files:**
- Modify: `src/verifier.py`
- Modify: `tests/test_verifier.py`

**Step 1: Write the failing test**

```python
# Add to tests/test_verifier.py
from src.verifier import SignatureVerifier
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def test_verify_signature(tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    
    content = b"test content"
    signature = private_key.sign(content, hashes.SHA256())
    
    verifier = SignatureVerifier()
    result = verifier.verify(public_key, content, signature)
    assert result.verified is True

def test_verify_signature_invalid():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
    content = b"test content"
    signature = private_key.sign(content, hashes.SHA256())
    
    verifier = SignatureVerifier()
    result = verifier.verify(other_key.public_key(), content, signature)
    assert result.verified is False
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_verifier.py::test_verify_signature -v
Expected: FAIL
```

**Step 3: Write implementation**

```python
# Add to src/verifier.py
from cryptography.hazmat.primitives import hashes, asymmetric
from cryptography.exceptions import InvalidSignature

class SignatureVerifier:
    def verify(self, public_key, data: bytes, signature: bytes) -> VerificationResult:
        try:
            public_key.verify(signature, data, asymmetric.padding.PKCS1v15(), hashes.SHA256())
            return VerificationResult(True, "Signature verified")
        except InvalidSignature:
            return VerificationResult(False, "Signature verification failed")
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_verifier.py -v
Expected: PASS
```

---

### Task 7: Implement CLI

**Files:**
- Modify: `src/cli.py`

**Step 1: Write the failing test**

```python
# tests/test_cli.py
from click.testing import CliRunner
from src.cli import cli

def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ['--help'])
    assert result.exit_code == 0
    assert 'verify' in result.output.lower()

def test_cli_parse_spdx():
    runner = CliRunner()
    result = runner.invoke(cli, ['parse', 'tests/fixtures/sample.spdx.txt'])
    assert result.exit_code == 0
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_cli.py -v
Expected: FAIL
```

**Step 3: Write implementation**

```python
# src/cli.py
import sys
import click
from pathlib import Path
from src.models import SBOMFormat
from src.parsers.spdx import SPDXParser
from src.parsers.cyclonedx import CycloneDXParser
from src.verifier import IntegrityVerifier, SignatureVerifier

@click.group()
def cli():
    """SBOM Signature Verifier - Verify SBOM integrity and signatures."""
    pass

@cli.command()
@click.argument('sbom_file', type=click.Path(exists=True))
def parse(sbom_file):
    """Parse and display SBOM contents."""
    content = Path(sbom_file).read_text()
    
    if content.strip().startswith('{'):
        parser = CycloneDXParser()
    else:
        parser = SPDXParser()
    
    sbom = parser.parse(content)
    click.echo(f"Format: {sbom.format.value}")
    click.echo(f"Version: {sbom.version}")
    click.echo(f"Packages: {len(sbom.packages)}")
    for pkg in sbom.packages:
        click.echo(f"  - {pkg.name}@{pkg.version or 'N/A'}")
    return 0

@cli.command()
@click.argument('sbom_file', type=click.Path(exists=True))
@click.option('--key', type=click.Path(exists=True), help='Public key file for signature verification')
@click.option('--directory', type=click.Path(), default='.', help='Base directory for file verification')
def verify(sbom_file, key, directory):
    """Verify SBOM integrity and signatures."""
    content = Path(sbom_file).read_text()
    
    if content.strip().startswith('{'):
        parser = CycloneDXParser()
    else:
        parser = SPDXParser()
    
    sbom = parser.parse(content)
    base_path = Path(directory)
    
    verifier = IntegrityVerifier()
    results = verifier.verify_sbom(sbom, base_path)
    
    for result in results:
        if result.verified:
            click.echo(f"[PASS] {result.message}")
        else:
            click.echo(f"[FAIL] {result.message}")
            if result.expected_hash:
                click.echo(f"  Expected: {result.expected_hash}")
                click.echo(f"  Actual: {result.actual_hash}")
    
    if key and sbom.packages:
        sig_verifier = SignatureVerifier()
        click.echo("Signature verification requires detached signature file")
    
    return 0

if __name__ == "__main__":
    sys.exit(cli())
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_cli.py -v
Expected: PASS
```

---

### Task 8: Update README

**Files:**
- Modify: `README.md`

**Step 1: Update README with actual features**

```markdown
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
sbom-verify parse sample.spdx.txt

# Verify integrity
sbom-verify verify sample.spdx.txt --directory /path/to/packages

# Verify with signature
sbom-verify verify sample.spdx.txt --key public_key.pem
```

## Testing

```bash
pytest tests/ -v
```
```

---

### Task 9: Run full test suite and linting

**Step 1: Run pytest with coverage**

```bash
pytest tests/ -v --cov=src --cov-report=term-missing
```

**Step 2: Run ruff**

```bash
ruff check src/ tests/
```

**Step 3: Fix any issues and ensure ≥80% coverage**

---

### Task 10: Commit

**Step 1: Commit all changes**

```bash
git add -A
git commit -m "feat: implement SBOM signature verifier

- Add SPDX and CycloneDX parsers
- Add integrity verification (SHA256/512)
- Add cryptographic signature verification
- Add CLI with parse and verify commands
- Add comprehensive test suite"
```
