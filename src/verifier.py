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


class SignatureVerifier:
    def verify(self, public_key, data: bytes, signature: bytes) -> VerificationResult:
        from cryptography.hazmat.primitives import hashes, asymmetric
        from cryptography.exceptions import InvalidSignature

        try:
            public_key.verify(signature, data, asymmetric.padding.PKCS1v15(), hashes.SHA256())
            return VerificationResult(True, "Signature verified")
        except InvalidSignature:
            return VerificationResult(False, "Signature verification failed")
