def check_if_possibly_manually_installed_software(instruction: str) -> bool:
    if (
            "make" in instruction or
            "wget" in instruction or
            "COPY" in instruction or
            "ADD" in instruction
    ):
        return True
    return False


def get_possibly_vulnerable_layers(identified_instructions: list[dict, str]):
    result = []

    for identified_instruction in identified_instructions:
        layer, layer_id = identified_instruction

        instruction = layer["created_by"]

        if check_if_possibly_manually_installed_software(instruction):
            result.append(layer_id)

    return result
