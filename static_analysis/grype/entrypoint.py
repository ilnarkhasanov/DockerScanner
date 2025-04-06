from schemas.cve import CVE
from static_analysis.grype.aggregate import aggregate_grype_results
from static_analysis.grype.run import run_grype, run_grype_without_sbom


def grype_entrypoint(image_name: str) -> list[CVE]:
    grype_no_sbom_result = run_grype_without_sbom(image_name)
    return aggregate_grype_results(grype_no_sbom_result)


def grype_sbom_entrypoint(image_name: str) -> list[CVE]:
    grype_result = run_grype(image_name)
    return aggregate_grype_results(grype_result)
