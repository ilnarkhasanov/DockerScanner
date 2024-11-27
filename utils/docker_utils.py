import docker


def get_layers(image_name: str) -> list[str]:
    client = docker.from_env()
    image = client.images.pull(image_name)
    return list(map(lambda layer: layer.lstrip("sha256:"), image.attrs["RootFS"]["Layers"]))
