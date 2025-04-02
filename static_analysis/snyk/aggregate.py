from schemas.cve import CVE


def aggregate_snyk_results(results: dict) -> list[CVE]:
    cve_list: list[CVE] = []

    if "vulnerabilities" not in results:
        return cve_list

    for vulnerability in results["vulnerabilities"]:
        cve_list.append(
            CVE(
                code=vulnerability["identifiers"]["CVE"][0],
                severity=vulnerability["severity"],
                product=vulnerability["name"],
                version=vulnerability["version"],
            )
        )

    return cve_list
