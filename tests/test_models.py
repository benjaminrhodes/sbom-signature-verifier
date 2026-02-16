import pytest
from src.models import Package, SBOM, SBOMFormat


def test_package_creation():
    pkg = Package(name="test-pkg", version="1.0.0", checksums={"SHA256": "abc123"})
    assert pkg.name == "test-pkg"
    assert pkg.version == "1.0.0"
    assert pkg.checksums["SHA256"] == "abc123"


def test_sbom_creation():
    sbom = SBOM(format=SBOMFormat.SPDX, version="SPDX-2.3", packages=[])
    assert sbom.format == SBOMFormat.SPDX
    assert sbom.version == "SPDX-2.3"
    assert sbom.packages == []


def test_sbom_format_enum():
    assert SBOMFormat.SPDX.value == "spdx"
    assert SBOMFormat.CYCLONEDX.value == "cyclonedx"
