import json
import os
import subprocess
import uuid

from cve_bin_tool_utils.aggregate import aggregate_my_cves
from dockerfile_utils.scan_layers import get_possibly_vulnerable_layers
from schemas.cve import CVE
from utils.filesystem_utils import read_json_file
from utils.tar_utils import extract_tar, save_to_tar


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


def cve_bin_tool_scan_entrypoint(image_name: str) -> list[CVE]:
    print("CVE-bin-tool scanning...")

    tar_output_path = save_to_tar(image_name)
    folder_output_path = extract_tar(tar_output_path)

    with open(folder_output_path + "/manifest.json", "r") as manifest_file:
        manifest = json.load(manifest_file)

    config_path: str = manifest[0]["Config"]

    with open(folder_output_path + "/" + config_path) as config_file:
        config = json.load(config_file)

    history = list(filter(lambda layer: "empty_layer" not in layer, config["history"]))
    layer_ids = config["rootfs"]["diff_ids"]

    identified_instructions = list(zip(history, layer_ids))

    possibly_vulnerable_layers = get_possibly_vulnerable_layers(identified_instructions)

    for layer_index in range(len(possibly_vulnerable_layers)):
        if possibly_vulnerable_layers[layer_index].startswith("sha256:"):
            possibly_vulnerable_layers[layer_index] = possibly_vulnerable_layers[layer_index][len("sha256:"):]

    my_cve = []

    # Create a shared list
    for layer in possibly_vulnerable_layers:
        scan(layer, my_cve, folder_output_path)

    my_cve = aggregate_my_cves(list(my_cve))

    return my_cve
