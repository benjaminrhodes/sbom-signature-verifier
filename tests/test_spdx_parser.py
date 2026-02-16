import pytest
from src.parsers.spdx import SPDXParser
from src.models import SBOM, SBOMFormat


def test_parse_spdx_tag_value():
    content = """SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test-bom
DocumentNamespace: https://example.com/test

PackageName: test-pkg
SPDXID: SPDXRef-Package
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
SHA256: abc123def456
"""
    parser = SPDXParser()
    sbom = parser.parse(content)
    assert sbom.format == SBOMFormat.SPDX
    assert sbom.version == "SPDX-2.3"
    assert len(sbom.packages) == 1
    assert sbom.packages[0].name == "test-pkg"
    assert sbom.packages[0].version == "1.0.0"
    assert sbom.packages[0].checksums.get("SHA256") == "abc123def456"


def test_parse_spdx_multiple_packages():
    content = """SPDXVersion: SPDX-2.3
DocumentName: multi-pkg

PackageName: pkg1
SHA256: hash1

PackageName: pkg2
SHA256: hash2
"""
    parser = SPDXParser()
    sbom = parser.parse(content)
    assert len(sbom.packages) == 2
    assert sbom.packages[0].name == "pkg1"
    assert sbom.packages[1].name == "pkg2"
