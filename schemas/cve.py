from dataclasses import dataclass


@dataclass
class CVE:
    code: str
    severity: str
    product: str
    version: str
