from schemas.cve import CVE


def find_cve_intersection(
    cve_list_1: list[CVE], cve_list_2: list[CVE]
) -> list[CVE]:
    cve_intersection: list[CVE] = []

    cve_list_2_codes = list(map(lambda cve: cve.code, cve_list_2))

    for left_cve in cve_list_1:
        if left_cve.code in cve_list_2_codes:
            cve_intersection.append(left_cve)

    return cve_intersection


def find_unique_vulnerabilities(
        static_analysis_tool_vulnerabilities: list[CVE],
        sbom_vulnerabilities: list[CVE],
) -> list[CVE]:
    unique_vulnerabilities: list[CVE] = []

    static_analysis_tool_vulnerabilities_codes: list[str] = list(map(
        lambda vulnerability: vulnerability.code,
        static_analysis_tool_vulnerabilities
    ))

    for sbom_vulnerability in sbom_vulnerabilities:
        if (
            sbom_vulnerability.code not in
            static_analysis_tool_vulnerabilities_codes
        ):
            unique_vulnerabilities.append(sbom_vulnerability)

    return unique_vulnerabilities
