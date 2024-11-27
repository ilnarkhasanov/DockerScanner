import subprocess
import tarfile
import uuid


def save_to_tar(image_name: str) -> str:
    tar_output_path = f"./experiment/{uuid.uuid4()}"
    subprocess.run(
        ["docker", "save", image_name, "-o", tar_output_path],
        stdout=subprocess.DEVNULL
    )
    return tar_output_path


def extract_tar(tar_path: str) -> str:
    folder_output_file = f"./experiment/{uuid.uuid4()}"
    with tarfile.open(tar_path, "r") as tar:
        tar.extractall(path=folder_output_file)
    return folder_output_file
