import json
import os
import subprocess
import uuid

from utils.filesystem_utils import read_json_file
from utils.tar_utils import extract_tar


def scan_file(file_path: str) -> tuple[str, int]:
    output_json = f"./experiment/{uuid.uuid4()}.json"
    result = subprocess.run(
        ["cve-bin-tool", file_path, "--format", "json", "--output", output_json],
        stdout=subprocess.DEVNULL
    )
    return output_json, result.returncode


def scan_layer_folder(folder_path: str):
    cves = []
    report_path, return_code = scan_file(folder_path)
    result = read_json_file(report_path)

    for cve in result:
        cves.append(cve)

    return cves


def scan(layer: str, global_cves, folder_output_path):
    path_to_tar = os.path.join(folder_output_path, f"blobs/sha256/{layer}")
    layer_folder = extract_tar(path_to_tar)
    cves = scan_layer_folder(layer_folder)
    global_cves.extend(cves)

    with open(f"./experiment/results_{uuid.uuid4()}.json", "w") as json_file:
        json.dump(cves, json_file)
