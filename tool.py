import datetime
import json
import os.path

from cve_bin_tool_utils.aggregate import aggregate_my_cves
from cve_bin_tool_utils.scan import scan
from dockerfile_utils.scan_layers import get_possibly_vulnerable_layers
from static_analysis.grype.aggregate import aggregate_grype_results
from static_analysis.grype.run import run_grype_without_sbom, run_grype
from static_analysis.trivy.run_trivy import run_trivy, aggregate_trivy_cves
from utils.cve_utils import find_cve_intersection
from utils.tar_utils import save_to_tar, extract_tar

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

    my_cve = []

    # Create a shared list
    for layer in possibly_vulnerable_layers:
        scan(layer, my_cve, folder_output_path)

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
