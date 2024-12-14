import json

from schemas.cve import CVE


def aggregate_docker_scout_results(report: dict) -> list[CVE]:
    return [
        CVE(
            code=vulnerability["cve"],
            severity=vulnerability["severity"],
            product=vulnerability["location"]["dependency"]["package"]["name"],
            version=vulnerability["location"]["dependency"]["version"]
        )
        for vulnerability in report["vulnerabilities"]
    ]
