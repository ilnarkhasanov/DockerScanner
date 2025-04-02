import json


def read_json_file(json_output_path: str):
    with open(json_output_path, "r") as file:
        data = json.load(file)
    return data
