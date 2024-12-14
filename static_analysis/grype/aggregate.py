import json

from schemas.cve import CVE


def aggregate_grype_results(result_path: str):
    cves = []

    with open(result_path) as txt:
        a = txt.readlines()

        if a == []:
            return cves

    with open(result_path) as txt:
        result = json.load(txt)

    for match_ in result["matches"]:
        vulnerability = match_["vulnerability"]
        artifact = match_["artifact"]
        cves.append(
            CVE(
                code=vulnerability["id"],
                severity=vulnerability["severity"],
                product=artifact["name"],
                version=artifact["version"]
            )
        )

    if "ignoredMatches" in result:
        for match_ in result["ignoredMatches"]:
            vulnerability = match_["vulnerability"]
            artifact = match_["artifact"]
            cves.append(
                CVE(
                    code=vulnerability["id"],
                    severity=vulnerability["severity"],
                    product=artifact["name"],
                    version=artifact["version"]
                )
            )

    return cves
