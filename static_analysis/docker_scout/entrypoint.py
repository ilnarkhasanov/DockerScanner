from sbom.cyclonedx.get_sbom import get_cyclonedx_sbom
from schemas.cve import CVE
from static_analysis.docker_scout.aggregate import aggregate_docker_scout_results
from static_analysis.docker_scout.run import run_docker_scout_without_sbom, run_docker_scout_with_sbom


def docker_scout_no_sbom_entrypoint(image_name: str) -> list[CVE]:
    print("Running Docker Scout without SBOM...")
    docker_scout_results = run_docker_scout_without_sbom(image_name)
    results: list[CVE] = aggregate_docker_scout_results(docker_scout_results)
    return results


def docker_scout_sbom_entrypoint(image_name: str) -> list[CVE]:
    print("Running Docker Scout with SBOM...")
    sbom_path = get_cyclonedx_sbom(image_name)
    docker_scout_results = run_docker_scout_with_sbom(sbom_path)
    results: list[CVE] = aggregate_docker_scout_results(docker_scout_results)
    return results
