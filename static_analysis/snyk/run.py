import json
import subprocess
import uuid

from sbom.cyclonedx.get_sbom import get_cyclonedx_sbom


def run_snyk_without_sbom(image_name: str, arm64: bool) -> dict:
    if arm64:
        result = subprocess.run(
            ["snyk", "container", "test", "--json", image_name, "--platform=linux/arm64"],
            capture_output=True,
            text=True,
        ).stdout.strip()
    else:
        result = subprocess.run(
            ["snyk", "container", "test", "--json", image_name, "--platform=linux/amd64"],
            capture_output=True,
            text=True,
        ).stdout.strip()

    return json.loads(result)

    # with open(output_path, "w") as txt:
    #     txt.write(result)
    #
    # return output_path


def run_snyk_with_sbom(image_name: str):
    sbom_path: str = get_cyclonedx_sbom(image_name)
    result = subprocess.run(
        ["snyk", "sbom", "test", "--experimental", f"--file={sbom_path}", "--json"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    return json.loads(result)
