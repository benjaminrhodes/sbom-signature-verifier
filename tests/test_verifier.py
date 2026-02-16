import pytest
from pathlib import Path
from src.verifier import IntegrityVerifier, SignatureVerifier
from src.models import Package, SBOM, SBOMFormat


def test_verify_checksum_match(tmp_path):
    pkg_file = tmp_path / "test.txt"
    pkg_file.write_text("hello world")

    pkg = Package(
        name="test",
        checksums={"SHA256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"},
    )
    verifier = IntegrityVerifier()
    result = verifier.verify_package(pkg, pkg_file)
    assert result.verified is True


def test_verify_checksum_mismatch(tmp_path):
    pkg_file = tmp_path / "test.txt"
    pkg_file.write_text("wrong content")

    pkg = Package(
        name="test",
        checksums={"SHA256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"},
    )
    verifier = IntegrityVerifier()
    result = verifier.verify_package(pkg, pkg_file)
    assert result.verified is False
    assert "mismatch" in result.message.lower()


def test_verify_file_not_found():
    pkg = Package(name="test", checksums={"SHA256": "abc123"})
    verifier = IntegrityVerifier()
    result = verifier.verify_package(pkg, Path("/nonexistent/file.txt"))
    assert result.verified is False
    assert "not found" in result.message.lower()


def test_verify_signature():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, asymmetric
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    content = b"test content"
    signature = private_key.sign(content, asymmetric.padding.PKCS1v15(), hashes.SHA256())

    verifier = SignatureVerifier()
    result = verifier.verify(public_key, content, signature)
    assert result.verified is True


def test_verify_signature_invalid():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, asymmetric
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    other_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    content = b"test content"
    signature = private_key.sign(content, asymmetric.padding.PKCS1v15(), hashes.SHA256())

    verifier = SignatureVerifier()
    result = verifier.verify(other_key.public_key(), content, signature)
    assert result.verified is False


def test_verify_sbom(tmp_path):
    pkg_file = tmp_path / "test.txt"
    pkg_file.write_text("hello world")

    pkg = Package(
        name="test.txt",
        checksums={"SHA256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"},
        download_location="https://example.com/test.txt",
    )
    sbom = SBOM(format=SBOMFormat.SPDX, version="SPDX-2.3", packages=[pkg])
    verifier = IntegrityVerifier()
    results = verifier.verify_sbom(sbom, tmp_path)
    assert len(results) == 1
    assert results[0].verified is True


def test_verify_sha512(tmp_path):
    import hashlib

    content = b"test content"
    expected_hash = hashlib.sha512(content).hexdigest()
    pkg_file = tmp_path / "test.txt"
    pkg_file.write_bytes(content)

    pkg = Package(name="test.txt", checksums={"SHA512": expected_hash})
    verifier = IntegrityVerifier()
    result = verifier.verify_package(pkg, pkg_file)
    assert result.verified is True
