import json
import subprocess

from sbom.cyclonedx.get_sbom import get_syft_cyclonedx_sbom


def run_snyk_without_sbom(image_name: str) -> dict:
    result = subprocess.run(
        ["snyk", "container", "test", "--json", image_name, "--platform=linux/amd64"],
        capture_output=True,
        text=True,
    ).stdout.strip()

    return json.loads(result)


def run_snyk_with_sbom(image_name: str):
    sbom_path: str = get_syft_cyclonedx_sbom(image_name)
    result = subprocess.run(
        ["snyk", "sbom", "test", "--experimental", f"--file={sbom_path}", "--json"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    return json.loads(result)
