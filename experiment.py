import datetime
import json
import os.path
import subprocess

from cve_bin_tool_utils.scan import cve_bin_tool_scan_entrypoint
from schemas.cve import CVE
from static_analysis.docker_scout.entrypoint import docker_scout_no_sbom_entrypoint, docker_scout_own_sbom_entrypoint, docker_scout_sbom_entrypoint
from static_analysis.grype.aggregate import aggregate_grype_results
from static_analysis.grype.run import run_grype_without_sbom, run_grype
from static_analysis.snyk.entrypoint import entrypoint_run_snyk_without_sbom, entrypoint_run_snyk_with_sbom
from static_analysis.trivy.run_trivy import run_trivy, aggregate_trivy_cves, run_trivy_with_syft_sbom, run_trivy_with_trivy_sbom
from utils.cve_utils import find_cve_intersection, find_unique_vulnerabilities


def run_tool(image_name: str, arm64=True) -> None:
    # # breakpoint()

    print(f"Starting scanning {image_name}...")

    # results_path = (
    #     f"scanning_results_{image_name.replace("/", "_")}"
    #     f"_{datetime.datetime.now().isoformat()}")
    # os.mkdir(results_path)
    # # CVE-bin-tool
    # cve_bin_tool_cve = cve_bin_tool_scan_entrypoint(image_name)

    # my_cve_output = f"{results_path}/tool.json"

    # with open(my_cve_output, "w") as json_file:
    #     json.dump(
    #         list(map(lambda cve: cve.__dict__, cve_bin_tool_cve)),
    #         json_file
    #     )

    # print(f"Amount of CVE-bin-tool vulnerabilities: {len(cve_bin_tool_cve)}")
    # print("-" * 100)

    # Docker Scout no SBOM
    # docker_scout_no_sbom_cve: list[CVE] = (
    #     docker_scout_no_sbom_entrypoint(image_name)
    # )
    # print("Amount of Docker Scout (scanning"
    #       f"image directly) vulnerabilities: {len(docker_scout_no_sbom_cve)}")
    # cve_bin_tool_docker_scout_no_sbom_unique_vulnerabilities: list[CVE] = (
    #     find_unique_vulnerabilities(
    #         docker_scout_no_sbom_cve, cve_bin_tool_cve
    #     )
    # )
    # print("Unique vulnerabilities found by CVE-bin-tool (Docker Scout,"
    #       "direct scanning): "
    #       f"{len(cve_bin_tool_docker_scout_no_sbom_unique_vulnerabilities)}")
    # print("-" * 100)

    # Docker Scout Syft SBOM
    # docker_scout_sbom_cve: list[CVE] = docker_scout_sbom_entrypoint(image_name)
    # print("Amount of Docker Scout (scanning SBOM) "
    #       f"vulnerabilities: {len(docker_scout_sbom_cve)}")
    # unique_docker_scout_sbom_vulnerabilities: list[CVE] = (
    #     find_unique_vulnerabilities(
    #         docker_scout_no_sbom_cve, docker_scout_sbom_cve
    #     )
    # )
    # print("Amount of unique vulnerabilities found by scanning SBOM using "
    #       f"Docker Scout: {len(unique_docker_scout_sbom_vulnerabilities)}")
    # cve_bin_tool_docker_scout_sbom_unique_cves: list[CVE] = (
    #     find_unique_vulnerabilities(docker_scout_sbom_cve, cve_bin_tool_cve)
    # )
    # print("Unique vulnerabilities found by CVE-bin-tool "
    #       "(Docker Scout, scanning SBOM): "
    #       f"{len(cve_bin_tool_docker_scout_sbom_unique_cves)}")
    # print("-" * 100)

    # # Docker Scout own SBOM
    # try:
    #     docker_scout_own_sbom_cve: list[CVE] = (
    #         docker_scout_own_sbom_entrypoint(image_name)
    #     )
    #     print("Amount of Docker Scout (scanning own SBOM) vulnerabilities: "
    #         f"{len(docker_scout_own_sbom_cve)}")
    #     unique_docker_scout_own_sbom_cves: list[CVE] = (
    #         find_unique_vulnerabilities(
    #             docker_scout_no_sbom_cve, docker_scout_sbom_cve
    #         )
    #     )
    #     print("Amount of unique Docker Scout (scanning own SBOM) vulnerabilities: "
    #         f"{len(unique_docker_scout_own_sbom_cves)}")

    #     cve_bin_tool_docker_scout_own_sbom_unique_cves: list[CVE] = (
    #         find_unique_vulnerabilities(
    #             docker_scout_own_sbom_cve, cve_bin_tool_cve
    #         )
    #     )
    #     print("Unique vulnerabilities found by CVE-bin-tool "
    #           "(Docker Scout, scanning own SBOM): "
    #           f"{len(cve_bin_tool_docker_scout_own_sbom_unique_cves)}")

    #     print("-" * 100)
    # except json.JSONDecodeError:
    #     print("Docker Scout own SBOM scanning was failed")

    # # Snyk

    # snyk_no_sbom_cve: list[CVE] = (
    #     entrypoint_run_snyk_without_sbom(image_name, arm64)
    # )
    # print("Amount of Snyk (direct image scanning): "
    #       f"{len(snyk_no_sbom_cve)}")
    # cve_bin_tool_snyk_no_sbom_unique_cve: list[CVE] = (
    #     find_unique_vulnerabilities(
    #         snyk_no_sbom_cve, cve_bin_tool_cve
    #     )
    # )
    # print("Unique vulnerabilities found by CVE-bin-tool "
    #       "(Snyk, direct scanning): "
    #       f"{len(cve_bin_tool_snyk_no_sbom_unique_cve)}")
    # print("-" * 100)

    # Trivy

    print("Scanning by Trivy without SBOM...")

    trivy_result = run_trivy(image_name)
    trivy_cve = aggregate_trivy_cves(trivy_result)

    print(f"Amount of Trivy without SBOM: {len(trivy_cve)}")

    # trivy_no_sbom_unique_cve_bin_tool_vulnerabilities = (
    #     find_unique_vulnerabilities(trivy_cve, cve_bin_tool_cve)
    # )
    # print("Amount of unique CVE-bin-tool vulnerabilities: "
    #       f"{len(trivy_no_sbom_unique_cve_bin_tool_vulnerabilities)}")
    # print("-" * 100)

    # Trivy + Syft SBOM

    print("Scanning by Trivy with Syft SBOM...")

    trivy_with_syft_sbom_result = run_trivy_with_syft_sbom(image_name)
    trivy_with_syft_sbom_cve: list[CVE] = aggregate_trivy_cves(
        trivy_with_syft_sbom_result
    )
    print("Amount of vulnerabilities found by Trivy + "
          f"Syft: {len(trivy_with_syft_sbom_cve)}")
    unique_syft_vulnerabilities: list[CVE] = find_unique_vulnerabilities(
        trivy_cve,
        trivy_with_syft_sbom_cve
    )
    for cve in unique_syft_vulnerabilities:
        print(cve)
    # print("Amount of unique vulnerabilities found by Trivy + Syft:"
    #       f"{len(unique_syft_vulnerabilities)}")
    # trivy_syft_unique_cve_bin_tool_vulnerabilities: list[CVE] = (
    #     find_unique_vulnerabilities(trivy_with_syft_sbom_cve, cve_bin_tool_cve)
    # )
    # print("Amount of unique CVE-bin-tool vulnerabilities:"
    #       f" {len(trivy_syft_unique_cve_bin_tool_vulnerabilities)}")
    # print("-" * 100)

    # # Trivy + Trivy SBOM

    # print("Scanning by Trivy with Trivy SBOM...")

    # trivy_with_trivy_sbom_result = run_trivy_with_trivy_sbom(image_name)
    # trivy_with_trivy_sbom_cve = aggregate_trivy_cves(
    #     trivy_with_trivy_sbom_result
    # )
    # unique_trivy_sbom_vulnerabilities: list[CVE] = find_unique_vulnerabilities(
    #     trivy_cve,
    #     trivy_with_trivy_sbom_cve
    # )

    # print(f"Amount of Trivy with Trivy SBOM: {len(trivy_with_trivy_sbom_cve)}")
    # print("Amount of unique Trivy CVEs with Trivy SBOM vulnerabilities: "
    #       f"{len(unique_trivy_sbom_vulnerabilities)}")

    # trivy_trivy_sbom_unique_cve_bin_tool_vulnerabilities: list[CVE] = (
    #     find_unique_vulnerabilities(
    #         trivy_with_trivy_sbom_cve, cve_bin_tool_cve
    #     )
    # )
    # print("Amount of unique CVE-bin-tool vulnerabilities: "
    #       f"{len(trivy_trivy_sbom_unique_cve_bin_tool_vulnerabilities)}")
    # print("-" * 100)

    # Grype (no SBOM)

    # print("Scanning by Grype without SBOM...")
    # grype_no_sbom_result = run_grype_without_sbom(image_name)
    # grype_no_sbom_cve = aggregate_grype_results(grype_no_sbom_result)
    # print(f"Grype vulnerabilities amount: {len(grype_no_sbom_cve)}")
    
    # grype_no_sbom_unique_cve_bin_tool_vulnerabilities: list[CVE] = (
    #     find_unique_vulnerabilities(grype_no_sbom_cve, cve_bin_tool_cve)
    # )
    # print(f"Amount of unique CVE-bin-tool vulnerabilities: "
    #       f"{len(grype_no_sbom_unique_cve_bin_tool_vulnerabilities)}")
    # print("-" * 100)

    # Grype (Syft SBOM)

    # print("Scanning by Grype with SBOM...")
    # grype_result = run_grype(image_name)
    # grype_cve = aggregate_grype_results(grype_result)
    # print(f"Grype SBOM vulnerabilities amount: {len(grype_cve)}")

    # grype_syft_unique_cve = find_unique_vulnerabilities(
    #     grype_no_sbom_cve, grype_cve
    # )
    # print(f"Grype Syft unique vulnerabilities:")
    # for a in grype_syft_unique_cve:
    #     print(a)
    # print("-" * 100)
    # for b in grype_no_sbom_cve:
    #     print(b)
    # print(grype_syft_unique_cve, sep="\n")

    # grype_syft_unique_cve_bin_tool_vulnerabilities: list[CVE] = (
    #     find_unique_vulnerabilities(grype_cve, cve_bin_tool_cve)
    # )
    # print("Amount of unique CVE-bin-tool vulnerabilities: "
    #       f"{len(grype_syft_unique_cve_bin_tool_vulnerabilities)}")
    # print("-" * 100)


if __name__ == "__main__":
    # image_name = "brutaljesus/everynight-app:vuln-binary"
    image_names = [
        # "memcached:1.6.32",
        "tensorflow/tensorflow:nightly",  # tensorflow/tensorflow:nightly
        # "nginx:1.27",
        # "busybox:1.37",
        # "alpine:3.20",
        # "ubuntu:25.04",
        # "redis:7.4",
        # "postgres:16.6",
        # "python:3.13",
        # "node:23",
        # "httpd:2.4.62",
        "mongo:8.0",
        # # "mysql:9", not used
        "rabbitmq:4",
        # "mariadb:11",
        # # "openjdk:24", not used
        # # "golang:1.23", not used
        # "registry:2",
        # "debian:12",
        # "php:8.2",
        # "centos:centos7",
        "influxdb:1.11.8",
        # "consul:1.15.4",
    ]

    # for image in image_names:
    #     subprocess.run(["docker", "pull", image])
    #
    # exit()

    vulhub_images = [
        # "vulhub/activemq:5.17.3",
        # "vulhub/adminer:4.7.8",
        # # "vulhub/apache-druid:0.20.0",  # not used
        # # "vulhub/apereo-cas:4.1.5",  # not used
        # "vulhub/apisix:2.9",
        # "vulhub/appweb:7.0.1",
        # "vulhub/aria2:1.18.8",
        # "vulhub/bash:4.3.0-with-httpd",
        "vulhub/cacti:1.2.22",
        # "vulhub/celery:3.1.23",
        # "vulhub/ffmpeg:2.8.4-with-php",  # not used
        # "vulhub/cups-browsed:2.0.1",
        # "vulhub/git:2.12.2-with-openssh",
    ]

    # non_arm64_image_names = [
    #     "ruby:3.4",
    #     "sonarqube:9",
    #     "haproxy:3.2",
    # ]

    random_images: list[str] = [
        "doughnutdough5/bangbangbang-lobby",
        # "balenalib/up-core-fedora-node",
        # "vaibhavsingh007/rp_lyra",
        # "psimler/myworkerservice",
        # "binartist/mo-service-graph",
        # "kubesphere/whizard-telemetry-apiserver",
        # "hexlo/terraria-tmodloader-server",
        "llidor1223/kaplatdb",
        "bytez/mlfoundations-dev_mistral_7b_0-3_oh-dcft-v3.1-llama-3.1-8b",
        # "tryuu/my-computeclass",
    ]

    # for image_name in random_images:
    #     subprocess.run(["docker", "pull", image_name])

    # exit()

    for image_name in image_names:
        run_tool(image_name, arm64=False)
        print("-" * 100)

    for image_name in vulhub_images:
        run_tool(image_name, arm64=False)
        print("-" * 100)

    for image_name in random_images:
        run_tool(image_name, arm64=False)
        print("-" * 100)
