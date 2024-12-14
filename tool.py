import datetime
import json
import os.path
import subprocess

from cve_bin_tool_utils.scan import cve_bin_tool_scan_entrypoint
from schemas.cve import CVE
from static_analysis.docker_scout.entrypoint import docker_scout_no_sbom_entrypoint, docker_scout_sbom_entrypoint
from static_analysis.grype.aggregate import aggregate_grype_results
from static_analysis.grype.run import run_grype_without_sbom, run_grype
from static_analysis.snyk.entrypoint import entrypoint_run_snyk_without_sbom, entrypoint_run_snyk_with_sbom
from static_analysis.trivy.run_trivy import run_trivy, aggregate_trivy_cves, run_trivy_with_sbom
from utils.cve_utils import find_cve_intersection


def run_tool(image_name: str, arm64=True) -> None:
    print(f"Starting scanning {image_name}...")

    results_path = f"grype_scanning_results_{image_name.replace("/", "_")}_{datetime.datetime.now().isoformat()}"
    os.mkdir(results_path)

    cve_bin_tool_cve = cve_bin_tool_scan_entrypoint(image_name)

    docker_scout_with_sbom: list[CVE] = docker_scout_sbom_entrypoint(image_name)
    docker_scout_sbom_results_output = f"{results_path}/docker_scout_with_sbom.json"
    with open(docker_scout_sbom_results_output, "w") as json_file:
        json.dump(
            list(map(lambda cve: cve.__dict__, docker_scout_with_sbom)),
            json_file
        )
    #
    # # return
    #
    # docker_scout_no_sbom_result: list[CVE] = docker_scout_no_sbom_entrypoint(image_name)
    # results_output = f"{results_path}/docker_scout_no_sbom.json"
    # with open(results_output, "w") as json_file:
    #     json.dump(
    #         list(map(lambda cve: cve.__dict__, docker_scout_no_sbom_result)),
    #         json_file
    #     )

    snyk_no_sbom_scanning = entrypoint_run_snyk_without_sbom(image_name, arm64)

    snyk_no_sbom_cve_output = f"{results_path}/snyk_no_sbom.json"

    with open(snyk_no_sbom_cve_output, "w") as json_file:
        json.dump(
            list(map(lambda cve: cve.__dict__, snyk_no_sbom_scanning)),
            json_file
        )

    # snyk_sbom_scanning = entrypoint_run_snyk_with_sbom(image_name)
    # snyk_sbom_output = f"{results_path}/snyk_sbom.json"
    # with open(snyk_sbom_output, "w") as txt:
    #     json.dump(
    #         list(map(lambda cve: cve.__dict__, snyk_sbom_scanning)),
    #         txt
    #     )

    print("Scanning by Trivy without SBOM...")

    trivy_result = run_trivy(image_name)
    trivy_cve = aggregate_trivy_cves(trivy_result)

    trivy_cve_output = f"{results_path}/trivy.json"

    with open(trivy_cve_output, "w") as json_file:
        json.dump(
            list(map(lambda cve: cve.__dict__, trivy_cve)),
            json_file
        )

    # trivy_intersections_with_cve_bin_tools = find_cve_intersection(cve_bin_tool_cve, trivy_cve)
    # print(f"Intersections with Trivy (no SBOM) and CVE-bin-tool: {len(trivy_intersections_with_cve_bin_tools)}")
    #
    # trivy_intersections_with_cve_bin_tools_output = f"{results_path}/trivy_intersections_with_cve_bin_tools.json"
    #
    # with open(trivy_intersections_with_cve_bin_tools_output, "w") as json_file:
    #     json.dump(
    #         list(map(lambda cve: cve.__dict__, trivy_intersections_with_cve_bin_tools)),
    #         json_file
    #     )

    print("Scanning by Trivy with SBOM...")

    trivy_with_sbom_result = run_trivy_with_sbom(image_name)
    trivy_with_sbom_cve = aggregate_trivy_cves(trivy_with_sbom_result)

    trivy_sbom_cve_output = f"{results_path}/trivy_sbom.json"

    with open(trivy_sbom_cve_output, "w") as json_file:
        json.dump(
            list(map(lambda cve: cve.__dict__, trivy_with_sbom_cve)),
            json_file
        )

    # trivy_sbom_intersections_with_cve_bin_tools = find_cve_intersection(cve_bin_tool_cve, trivy_with_sbom_cve)
    # print(f"Intersections with Trivy (with SBOM) and CVE-bin-tool: {len(trivy_sbom_intersections_with_cve_bin_tools)}")
    #
    # trivy_sbom_intersections_with_cve_bin_tools_output = f"{results_path}/trivy_sbom_intersections_with_cve_bin_tools.json"
    #
    # with open(trivy_sbom_intersections_with_cve_bin_tools_output, "w") as json_file:
    #     json.dump(
    #         list(map(lambda cve: cve.__dict__, trivy_sbom_intersections_with_cve_bin_tools)),
    #         json_file
    #     )

    print(f"Amount of CVEs catched by Trivy: {len(trivy_with_sbom_cve)}")

    print("Scanning by Grype without SBOM...")
    grype_no_sbom_result = run_grype_without_sbom(image_name)
    grype_no_sbom_cve = aggregate_grype_results(grype_no_sbom_result)

    grype_without_sbom_cve_output = f"{results_path}/grype_without_sbom_no_sbom.json"

    with open(grype_without_sbom_cve_output, "w") as json_file:
        json.dump(
            list(map(lambda cve: cve.__dict__, grype_no_sbom_cve)),
            json_file
        )

    print("Scanning by Grype with SBOM...")
    grype_result = run_grype(image_name)
    grype_cve = aggregate_grype_results(grype_result)
    grype_sbom_output = f"{results_path}/grype_sbom.json"

    with open(grype_sbom_output, "w") as txt:
        json.dump(
            list(map(lambda cve: cve.__dict__, grype_cve)),
            txt
        )

    my_cve_output = f"{results_path}/tool.json"

    with open(my_cve_output, "w") as json_file:
        json.dump(
            list(map(lambda cve: cve.__dict__, cve_bin_tool_cve)),
            json_file
        )

    # print("Scanning by Docker Scout without SBOM...")
    #
    print(f"Image scanned: {image_name}")
    print(f"Amount of CVEs catched by Trivy: {len(trivy_cve)}")
    print(f"Amount of CVEs catched by Grype (+ sbom): {len(grype_cve)}")
    print(f"Amount of CVEs catched by this tool: {len(cve_bin_tool_cve)}")
    print(
        f"Intersections with Grype (+ sbom) and "
        f"CVE-bin-tool: {len(find_cve_intersection(grype_cve, cve_bin_tool_cve))}")
    print(f"Results are available at: {results_path}")

if __name__ == "__main__":
    # image_name = "brutaljesus/everynight-app:vuln-binary"
    image_names = [
        # "memcached:1.6.32",
        # "tensorflow/tensorflow:nightly",  # tensorflow/tensorflow:nightly
        # "nginx:1.27",
        # "busybox:1.37",
        # "alpine:3.20",
        # "ubuntu:25.04",
        # "redis:7.4",
        # "postgres:16.6",
        # "python:3.13",
        # "node:23",
        # "httpd:2.4.62",
        # "mongo:8.0",
        # # "mysql:9", not used
        # "rabbitmq:4",
        # "mariadb:11",
        # "openjdk:24", not used
        # "golang:1.23", not used
        # "registry:2",
        "debian:12",
        "php:8.2",
        "centos:centos7",
        "influxdb:1.11.8",
        "consul:1.15.4",
    ]

    # for image in image_names:
    #     subprocess.run(["docker", "pull", image])
    #
    # exit()

    vulhub_images = [
        # "vulhub/activemq:5.17.3",
        # "vulhub/adminer:4.7.8",
        # "vulhub/apache-druid:0.20.0",  # not used
        # "vulhub/apereo-cas:4.1.5",  # not used
        # "vulhub/apisix:2.9",
        # "vulhub/appweb:7.0.1",
        # "vulhub/aria2:1.18.8",
        # "vulhub/bash:4.3.0-with-httpd",
        # "vulhub/cacti:1.2.22",
        # "vulhub/celery:3.1.23",
        # "vulhub/ffmpeg:2.8.4-with-php",  # not used
        "vulhub/cups-browsed:2.0.1",
        "vulhub/git:2.12.2-with-openssh",
    ]

    # non_arm64_image_names = [
    #     "ruby:3.4",
    #     "sonarqube:9",
    #     "haproxy:3.2",
    # ]

    for image_name in vulhub_images:
        run_tool(image_name, arm64=False)
        print("-" * 100)
