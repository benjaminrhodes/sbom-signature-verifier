import json
from src.models import SBOM, SBOMFormat, Package


class CycloneDXParser:
    def parse(self, content: str) -> SBOM:
        data = json.loads(content)
        sbom = SBOM(
            format=SBOMFormat.CYCLONEDX,
            version=data.get("specVersion", ""),
            document_name=data.get("metadata", {}).get("component", {}).get("name"),
        )

        for comp in data.get("components", []):
            pkg = Package(
                name=comp.get("name", ""),
                version=comp.get("version"),
                supplier=comp.get("supplier", {}).get("name")
                if isinstance(comp.get("supplier"), dict)
                else comp.get("supplier"),
            )
            for h in comp.get("hashes", []):
                alg = h.get("alg", "").replace("-", "").upper()
                if "SHA" in alg:
                    pkg.checksums[alg] = h.get("content", "")
            sbom.packages.append(pkg)

        return sbom
