import json
import subprocess


def run_docker_scout_without_sbom(image_name: str) -> dict:
    result = subprocess.run(
        ["docker", "scout", "cves", "--format", "gitlab", image_name],
        capture_output=True,
        text=True,
    ).stdout.strip()

    return json.loads(result)


def run_docker_scout_with_sbom(sbom_path: str) -> dict:
    result = subprocess.run(
        ["docker", "scout", "cves", "--format", "gitlab", f"sbom://{sbom_path}"],
        capture_output=True,
        text=True,
    ).stdout.strip()

    return json.loads(result)
