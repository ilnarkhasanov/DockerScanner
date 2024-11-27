from schemas.cve import CVE


def find_cve_intersection(cve_list_1: list[CVE], cve_list_2: list[CVE]) -> list[CVE]:
    cve_intersection: list[CVE] = []

    for left_cve in cve_list_1:
        for right_cve in cve_list_2:
            if left_cve.code == right_cve.code:
                cve_intersection.append(left_cve)

    return cve_intersection
