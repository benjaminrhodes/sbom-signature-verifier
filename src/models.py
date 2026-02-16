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
