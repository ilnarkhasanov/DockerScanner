import datetime
import json
import multiprocessing
import os.path
import subprocess
import uuid
import tarfile
from dataclasses import dataclass

import docker


@dataclass
class CVE:
    code: str
    severity: str
    product: str
    version: str


def save_to_tar(image_name: str) -> str:
    tar_output_path = f"./experiment/{uuid.uuid4()}"
    subprocess.run(
        ["docker", "save", image_name, "-o", tar_output_path],
        stdout=subprocess.DEVNULL
    )
    return tar_output_path


def extract_tar(tar_path: str) -> str:
    folder_output_file = f"./experiment/{uuid.uuid4()}"
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


def scan_file(file_path: str) -> tuple[str, int]:
    output_json = f"./experiment/{uuid.uuid4()}.json"
    result = subprocess.run(
        ["cve-bin-tool", file_path, "--format", "json", "--output", output_json],
        stdout=subprocess.DEVNULL
    )
    return output_json, result.returncode


def get_results(json_output_path: str):
    with open(json_output_path, "r") as file:
        data = json.load(file)
    return data


def scan_layer_folder(folder_path: str):
    cves = []
    report_path, return_code = scan_file(folder_path)
    result = get_results(report_path)

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


def check_if_possibly_manually_installed_software(instruction: str) -> bool:
    if (
            "make" in instruction or
            "wget" in instruction or
            "COPY" in instruction or
            "ADD" in instruction
    ):
        return True
    return False


def get_possibly_vulnerable_layers(identified_instructions: list[dict, str]):
    result = []

    for identified_instruction in identified_instructions:
        layer, layer_id = identified_instruction

        instruction = layer["created_by"]

        if check_if_possibly_manually_installed_software(instruction):
            result.append(layer_id)

    return result


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


def aggregate_trivy_cves(trivy_result: dict) -> list[CVE]:
    cves: list[CVE] = []

    for result in trivy_result["Results"]:
        if result["Class"] == "secret":
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


def aggregate_my_cves(result: list) -> list[CVE]:
    cve_list: list[CVE] = []

    for row in result:
        cve_list.append(
            CVE(
                code=row["cve_number"],
                severity=row["severity"],
                product=row["product"],
                version=row["version"]
            )
        )

    return cve_list


def get_cyclonedx_sbom(image_name: str) -> str:
    output_path = f"{uuid.uuid4()}.json"
    result: str = subprocess.run(
        ["syft", image_name, "-o", "cyclonedx-json"],
        capture_output=True,        # Capture both stdout and stderr
        text=True                   # Decode bytes to string
    ).stdout.strip()
    with open(output_path, "w") as txt:
        txt.write(result)
    return output_path


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


def aggregate_grype_results(result_path: str):
    cves = []

    with open(result_path) as txt:
        result = json.load(txt)

    for match_ in result["matches"]:
        vulnerability = match_["vulnerability"]
        artifact = match_["artifact"]
        cves.append(
            CVE(
                code=vulnerability["id"],
                severity=vulnerability["severity"],
                product=artifact["name"],
                version=artifact["version"]
            )
        )

    for match_ in result["ignoredMatches"]:
        vulnerability = match_["vulnerability"]
        artifact = match_["artifact"]
        cves.append(
            CVE(
                code=vulnerability["id"],
                severity=vulnerability["severity"],
                product=artifact["name"],
                version=artifact["version"]
            )
        )

    return cves


def find_cve_intersection(cve_list_1: list[CVE], cve_list_2: list[CVE]) -> list[CVE]:
    cve_intersection: list[CVE] = []

    for left_cve in cve_list_1:
        for right_cve in cve_list_2:
            if left_cve.code == right_cve.code:
                cve_intersection.append(left_cve)

    return cve_intersection


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


if __name__ == "__main__":
    image_name = "brutaljesus/everynight-app:vuln-binary"

    print("Starting...")

    print("Scanning by Trivy...")

    trivy_result = run_trivy(image_name)
    trivy_cve = aggregate_trivy_cves(trivy_result)

    results_path = f"scanning_results_{datetime.datetime.now().isoformat()}"
    os.mkdir(results_path)

    trivy_cve_output = f"{results_path}/trivy.json"

    with open(trivy_cve_output, "w") as json_file:
        json.dump(
            list(map(lambda cve: cve.__dict__, trivy_cve)),
            json_file
        )

    print("Scanning by Grype without SBOM...")
    grype_no_sbom_result = run_grype_without_sbom(image_name)
    grype_no_sbom_cve = aggregate_grype_results(grype_no_sbom_result)

    print("Scanning by Grype with SBOM...")
    grype_result = run_grype(image_name)
    grype_cve = aggregate_grype_results(grype_result)

    print("Custom scanning...")

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

    processes = []

    with multiprocessing.Manager() as manager:
        my_cve = manager.list()

        # Create a shared list
        for layer in possibly_vulnerable_layers:
            process = multiprocessing.Process(
                target=scan, args=(layer, my_cve, folder_output_path)
            )
            processes.append(process)
            process.start()

        for process in processes:
            process.join()

        my_cve = aggregate_my_cves(list(my_cve))

        my_cve_output = f"{results_path}/tool.json"

        with open(my_cve_output, "w") as json_file:
            json.dump(
                list(map(lambda cve: cve.__dict__, my_cve)),
                json_file
            )

    print(f"Image scanned: {image_name}")
    print(f"Amount of CVEs catched by Trivy: {len(trivy_cve)}")
    print(f"Amount of CVEs catched by Grype (+ sbom): {len(grype_cve)}")
    print(f"Amount of CVEs catched by this tool: {len(my_cve)}")
    print(f"Intersections with Grype (+ sbom) and CVE-bin-tool: {len(find_cve_intersection(grype_cve, my_cve))}")
    print(f"Results are available at: {results_path}")
