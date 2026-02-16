import pytest
from src.parsers.cyclonedx import CycloneDXParser
from src.models import SBOM, SBOMFormat


def test_parse_cyclonedx_json():
    content = """{
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
}"""
    parser = CycloneDXParser()
    sbom = parser.parse(content)
    assert sbom.format == SBOMFormat.CYCLONEDX
    assert sbom.version == "1.5"
    assert len(sbom.packages) == 1
    assert sbom.packages[0].name == "test-pkg"
    assert sbom.packages[0].checksums.get("SHA256") == "abc123"


def test_parse_cyclonedx_multiple_components():
    content = """{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {"name": "comp1", "hashes": [{"alg": "SHA-256", "content": "hash1"}]},
    {"name": "comp2", "hashes": [{"alg": "SHA-256", "content": "hash2"}]}
  ]
}"""
    parser = CycloneDXParser()
    sbom = parser.parse(content)
    assert len(sbom.packages) == 2
    assert sbom.packages[0].name == "comp1"
    assert sbom.packages[1].name == "comp2"
