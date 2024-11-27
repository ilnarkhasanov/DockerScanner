import json
import os
import typing


def get_all_paths_in_folder(folder_path) -> list[str]:
    all_paths: list[str] = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            full_path: str = typing.cast(
                os.path.join(root, file),
                str,
            )
            assert type(full_path) is str
            all_paths.append(full_path)
    return all_paths


def read_json_file(json_output_path: str):
    with open(json_output_path, "r") as file:
        data = json.load(file)
    return data
