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
