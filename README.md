# Prerequisites

1. Install Python 3.12+
https://www.python.org/

2. Install Docker
https://www.docker.com/

4. Install Poetry
https://python-poetry.org/

5. Activate environment and install dependencies
```
poetry shell
poetry install --no-root
```

4. Install Trivy
https://trivy.dev/latest/

5. Install Grype
https://github.com/anchore/grype

6. Install Snyk
https://docs.snyk.io/

# Usage

1. Pull the image you want to scan
```
docker pull <image_name>
```

2. Run the scanning
```
poetry run python3 tool.py <image_name>
```

or

```
poetry shell
python3 tool.py <image_name>
```
