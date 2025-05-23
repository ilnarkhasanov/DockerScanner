from sbom.cyclonedx.get_sbom import (
    get_syft_cyclonedx_sbom,
    get_docker_scout_cyclonedx_sbom,
)
from schemas.cve import CVE
from static_analysis.docker_scout.aggregate import (
    aggregate_docker_scout_results,
)
from static_analysis.docker_scout.run import (
    run_docker_scout_without_sbom,
    run_docker_scout_with_sbom,
)


def docker_scout_no_sbom_entrypoint(image_name: str) -> list[CVE]:
    print("Docker Scout scanning...")
    docker_scout_results = run_docker_scout_without_sbom(image_name)
    results: list[CVE] = aggregate_docker_scout_results(docker_scout_results)
    return results


def docker_scout_sbom_entrypoint(image_name: str) -> list[CVE]:
    print("Docker Scout SBOM scanning...")
    sbom_path = get_syft_cyclonedx_sbom(image_name)
    docker_scout_results = run_docker_scout_with_sbom(sbom_path)
    results: list[CVE] = aggregate_docker_scout_results(docker_scout_results)
    return results


def docker_scout_own_sbom_entrypoint(image_name: str) -> list[CVE]:
    print("Running Docker Scout with Docker Scout SBOM generation...")
    sbom_path = get_docker_scout_cyclonedx_sbom(image_name)
    docker_scout_results = run_docker_scout_with_sbom(sbom_path)
    results: list[CVE] = aggregate_docker_scout_results(docker_scout_results)
    return results
