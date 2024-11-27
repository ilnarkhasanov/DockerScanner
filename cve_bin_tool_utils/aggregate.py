from schemas.cve import CVE


def aggregate_my_cves(result: list) -> list[CVE]:
    cve_list: list[CVE] = []

    for row in result:
        cve_list.append(
            CVE(
                code=row["cve_number"],
                severity=row["severity"],
                product=row["product"],
                version=row["version"]
            )
        )

    return cve_list
