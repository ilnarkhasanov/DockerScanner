from schemas.cve import CVE


def aggregate_snyk_results(results: dict) -> list[CVE]:
    cve_list: list[CVE] = []

    if "vulnerabilities" not in results:
        return cve_list

    for vulnerability in results["vulnerabilities"]:
        for identifier, value in vulnerability["identifiers"].items():
            if value != []:
                code = value[0]

        try:
            cve_list.append(
                CVE(
                    code=code,
                    severity=vulnerability["severity"],
                    product=vulnerability["name"],
                    version=vulnerability["version"],
                )
            )
        except Exception:
            assert False, vulnerability

    return cve_list
