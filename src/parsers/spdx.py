from src.models import SBOM, SBOMFormat, Package


class SPDXParser:
    def parse(self, content: str) -> SBOM:
        lines = content.strip().split("\n")
        sbom = SBOM(format=SBOMFormat.SPDX, version="", packages=[])
        current_package = None

        for line in lines:
            line = line.strip()
            if not line or ":" not in line:
                continue

            key, _, value = line.partition(":")
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
