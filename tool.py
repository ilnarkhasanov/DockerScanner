import json
import os.path
import subprocess
import uuid
import tarfile

import docker


def save_to_tar(image_name: str) -> str:
    tar_output_path = f"/tmp/{uuid.uuid4()}"
    subprocess.run(
        ["docker", "save", image_name, "-o", tar_output_path]
    )
    return tar_output_path


def extract_tar(tar_path: str) -> str:
    folder_output_file = f"/tmp/{uuid.uuid4()}"
    with tarfile.open(tar_path, "r") as tar:
        tar.extractall(path=folder_output_file)
    return folder_output_file


def get_layers(image_name: str) -> list[str]:
    client = docker.from_env()
    image = client.images.pull(image_name)
    return list(map(lambda layer: layer.lstrip("sha256:"), image.attrs["RootFS"]["Layers"]))


def get_all_paths_in_folder(folder_path) -> list[str]:
    all_paths: list[str] = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            full_path: str = os.path.join(root, file)
            assert type(full_path) is str
            all_paths.append(full_path)
    return all_paths


def scan_file(file_path: str) -> str:
    output_json = f"/private/tmp/{uuid.uuid4()}.json"
    print("cve-bin-tool", file_path, "--format", "json", "--output", output_json)
    os.system(
        # ["cve-bin-tool", file_path, "--format", "json", "--output", output_json]
        f"cve-bin-tool {file_path} --format json --output {output_json}"
    )
    return output_json


def get_results(json_output_path: str):
    try:
        with open(json_output_path, "r") as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        return []


def scan_layer_folder(folder_path: str):
    paths = get_all_paths_in_folder(folder_path)

    cves = []

    for path in paths:
        report_path = scan_file(path)
        result = get_results(report_path)

        for cve in result:
            cves.append(cve["cve_number"])

    return cves


if __name__ == "__main__":
    image_name = "brutaljesus/bad-python-app-kek:latest"
    tar_output_path = save_to_tar(image_name)
    folder_output_path = extract_tar(tar_output_path)
    layers = get_layers(image_name)

    all_cves = []

    for layer in layers[1:]:
        path_to_tar = os.path.join(folder_output_path, f"blobs/sha256/{layer}")
        layer_folder = extract_tar(path_to_tar)
        cves = scan_layer_folder(layer_folder)
        all_cves.extend(cves)

    print(all_cves)
