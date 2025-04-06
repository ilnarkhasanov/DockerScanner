from dataclasses import asdict
from datetime import datetime
import json
import os

from schemas.cve import CVE


def read_json_file(json_output_path: str):
    with open(json_output_path, "r") as file:
        data = json.load(file)
    return data


def write_cves_to_json_file(
    cves: list[CVE],
    image_name: str,
    tool_name: str
) -> str:
    raw_cves: list[dict] = list(map(lambda cve: asdict(cve), cves))

    formatted_image_name = image_name.replace("/", "_")

    try:
        os.mkdir("reports")
    except FileExistsError:
        pass

    try:
        os.mkdir(f"reports/{formatted_image_name}")
    except FileExistsError:
        pass

    try:
        os.mkdir(f"reports/{formatted_image_name}/{tool_name}")
    except FileExistsError:
        pass

    path: str = (
        "reports/"
        f"{formatted_image_name}/"
        f"{tool_name}/"
        f"{datetime.now().isoformat()}.json"
    )

    with open(path, "w") as f:
        json.dump(raw_cves, f)

    print(f"Results are saved in {path}")

    return path
