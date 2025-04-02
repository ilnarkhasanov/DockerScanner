import subprocess
import uuid


def get_cyclonedx_sbom(image_name: str) -> str:
    output_path = f"{uuid.uuid4()}.json"

    if image_name == "registry:2":
        image_name = "docker.io/library/" + image_name

    result: str = subprocess.run(
        ["syft", image_name, "-o", "cyclonedx-json"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    with open(output_path, "w") as txt:
        txt.write(result)
    return output_path
