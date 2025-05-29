from schemas.cve import CVE
from static_analysis.trivy.run_trivy import (
    aggregate_trivy_cves,
    run_trivy,
    run_trivy_with_syft_sbom,
    run_trivy_with_trivy_sbom,
)


def trivy_entrypoint(image_name: str) -> list[CVE]:
    trivy_result = run_trivy(image_name)
    return aggregate_trivy_cves(trivy_result)


def trivy_sbom_entrypoint(image_name: str) -> list[CVE]:
    trivy_with_syft_sbom_result = run_trivy_with_syft_sbom(image_name)
    return aggregate_trivy_cves(
        trivy_with_syft_sbom_result
    )


def trivy_own_sbom_entrypoint(image_name: str) -> list[CVE]:
    trivy_with_trivy_sbom_result = run_trivy_with_trivy_sbom(image_name)
    return aggregate_trivy_cves(
        trivy_with_trivy_sbom_result
    )
