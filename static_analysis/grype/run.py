import subprocess
import uuid

from sbom.cyclonedx.get_sbom import get_cyclonedx_sbom


def run_grype(image_name: str) -> str:
    sbom_path: str = get_cyclonedx_sbom(image_name)

    output_path = f"{uuid.uuid4()}.json"
    result = subprocess.run([
        "grype", f"sbom:{sbom_path}", "-o", "json"],
        capture_output=True,
        text=True,
    ).stdout.strip()

    with open(output_path, "w") as txt:
        txt.write(result)

    return output_path


def run_grype_without_sbom(image_name: str) -> str:
    result = subprocess.run(
        ["grype", image_name, "--scope", "all-layers", "-o", "json"],
        capture_output=True,
        text=True,
    ).stdout.strip()

    output_path = f"{uuid.uuid4()}.json"

    with open(output_path, "w") as txt:
        txt.write(result)

    return output_path
