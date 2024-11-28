import datetime
import json
import os.path

from cve_bin_tool_utils.scan import cve_bin_tool_scan_entrypoint
from static_analysis.grype.aggregate import aggregate_grype_results
from static_analysis.grype.run import run_grype_without_sbom, run_grype
from static_analysis.trivy.run_trivy import run_trivy, aggregate_trivy_cves
from utils.cve_utils import find_cve_intersection

if __name__ == "__main__":
    image_name = "brutaljesus/everynight-app:vuln-binary"

    print("Starting...")

    cve_bin_tool_cve = cve_bin_tool_scan_entrypoint(image_name)

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

    trivy_intersections_with_cve_bin_tools = find_cve_intersection(cve_bin_tool_cve, trivy_cve)
    print(f"Intersections with Trivy (no SBOM) and CVE-bin-tool: {len(trivy_intersections_with_cve_bin_tools)}")

    trivy_intersections_with_cve_bin_tools_output = f"{results_path}/trivy_intersections_with_cve_bin_tools.json"

    with open(trivy_intersections_with_cve_bin_tools_output, "w") as json_file:
        json.dump(
            list(map(lambda cve: cve.__dict__, trivy_intersections_with_cve_bin_tools)),
            json_file
        )

    print("Scanning by Grype without SBOM...")
    grype_no_sbom_result = run_grype_without_sbom(image_name)
    grype_no_sbom_cve = aggregate_grype_results(grype_no_sbom_result)

    print("Scanning by Grype with SBOM...")
    grype_result = run_grype(image_name)
    grype_cve = aggregate_grype_results(grype_result)

    my_cve_output = f"{results_path}/tool.json"

    with open(my_cve_output, "w") as json_file:
        json.dump(
            list(map(lambda cve: cve.__dict__, cve_bin_tool_cve)),
            json_file
        )

    print(f"Image scanned: {image_name}")
    print(f"Amount of CVEs catched by Trivy: {len(trivy_cve)}")
    print(f"Amount of CVEs catched by Grype (+ sbom): {len(grype_cve)}")
    print(f"Amount of CVEs catched by this tool: {len(cve_bin_tool_cve)}")
    print(
        f"Intersections with Grype (+ sbom) and "
        f"CVE-bin-tool: {len(find_cve_intersection(grype_cve, cve_bin_tool_cve))}")
    print(f"Results are available at: {results_path}")
