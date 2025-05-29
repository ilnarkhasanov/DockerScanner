import argparse

from cve_bin_tool_utils.scan import cve_bin_tool_scan_entrypoint
from schemas.cve import CVE
from static_analysis.docker_scout.entrypoint import (
    docker_scout_no_sbom_entrypoint,
    docker_scout_sbom_entrypoint,
)
from static_analysis.grype.entrypoint import (
    grype_entrypoint,
    grype_sbom_entrypoint,
)
from static_analysis.snyk.entrypoint import (
    entrypoint_run_snyk_without_sbom,
)
from static_analysis.trivy.entrypoint import (
    trivy_entrypoint,
    trivy_own_sbom_entrypoint,
    trivy_sbom_entrypoint
)
from utils.filesystem_utils import write_cves_to_json_file

parser = argparse.ArgumentParser("")
parser.add_argument(
    "image_name",
    help="A name of Docker image that is to be scanned"
)

image_name = parser.parse_args().image_name

# Scan CVE-bin-tool
cve_bin_tool_cve: list[CVE] = cve_bin_tool_scan_entrypoint(image_name)
write_cves_to_json_file(
    cve_bin_tool_cve, image_name, "cve-bin-tool"
)

# Scan Trivy
trivy_cve: list[CVE] = trivy_entrypoint(image_name)
write_cves_to_json_file(trivy_cve, image_name, "trivy")

# Scan Trivy Syft SBOM
trivy_sbom_cve: list[CVE] = trivy_sbom_entrypoint(image_name)
write_cves_to_json_file(trivy_sbom_cve, image_name, "trivy-sbom")

# Scan Trivy own SBOM
trivy_own_sbom_cve: list[CVE] = trivy_own_sbom_entrypoint(image_name)
write_cves_to_json_file(trivy_own_sbom_cve, image_name, "trivy-own-sbom")

# Scan Grype
grype_cve: list[CVE] = grype_entrypoint(image_name)
write_cves_to_json_file(grype_cve, image_name, "grype")

# Scan Grype SBOM
grype_sbom_cve: list[CVE] = grype_sbom_entrypoint(image_name)
write_cves_to_json_file(grype_sbom_cve, image_name, "grype-sbom")

# Scan Snyk
snyk_cve: list[CVE] = entrypoint_run_snyk_without_sbom(image_name)
write_cves_to_json_file(snyk_cve, image_name, "snyk")

# Scan Docker Scout
docker_scout_cve: list[CVE] = docker_scout_no_sbom_entrypoint(image_name)
write_cves_to_json_file(docker_scout_cve, image_name, "docker-scout")

# Scan Docker Scout SBOM
docker_scout_sbom_cve: list[CVE] = docker_scout_sbom_entrypoint(image_name)
write_cves_to_json_file(docker_scout_sbom_cve, image_name, "docker-scout-sbom")

# Clair is self-hosted
