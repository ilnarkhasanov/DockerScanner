from json import JSONDecodeError
from schemas.cve import CVE
from static_analysis.snyk.aggregate import aggregate_snyk_results
from static_analysis.snyk.run import run_snyk_without_sbom, run_snyk_with_sbom


def entrypoint_run_snyk_without_sbom(image_name: str) -> list[CVE]:
    print("Snyk scanning...")
    try:
        scanning_result: dict = run_snyk_without_sbom(image_name)
    except JSONDecodeError:
        return []

    return aggregate_snyk_results(scanning_result)


def entrypoint_run_snyk_with_sbom(image_name: str) -> list[CVE]:
    scanning_result: dict = run_snyk_with_sbom(image_name)
    return aggregate_snyk_results(scanning_result)
