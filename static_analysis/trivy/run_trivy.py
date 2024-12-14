import json
import subprocess
import uuid

from sbom.cyclonedx.get_sbom import get_cyclonedx_sbom
from schemas.cve import CVE


def run_trivy(image_name: str) -> dict:
    output_path = f"./{uuid.uuid4()}.json"
    subprocess.run(
        ["trivy", "image", image_name, "--format", "json", "--output", output_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with open(output_path, "r") as file:
        result = json.load(file)
    return result


def run_trivy_with_sbom(image_name: str) -> dict:
    sbom_path: str = get_cyclonedx_sbom(image_name)

    output_path = f"./{uuid.uuid4()}.json"
    subprocess.run(
        ["trivy", "sbom", sbom_path, "--format", "json", "--output", output_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with open(output_path, "r") as file:
        result = json.load(file)
    return result


def aggregate_trivy_cves(trivy_result: dict) -> list[CVE]:
    cves: list[CVE] = []

    if "Results" not in trivy_result:
        return cves

    for result in trivy_result["Results"]:
        if result["Class"] == "secret":
            continue

        if "Vulnerabilities" not in result:
            continue

        for vulnerability in result["Vulnerabilities"]:
            cves.append(
                CVE(
                    code=vulnerability["VulnerabilityID"],
                    severity=vulnerability["Severity"],
                    product=vulnerability["PkgName"],
                    version=vulnerability["InstalledVersion"]
                )
            )

    return cves
