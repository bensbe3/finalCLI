# The CLI plus its three external tools in one image.
# The project you want to scan is MOUNTED at /target - it is never copied
# into the image, so nothing of yours ends up in a layer.
#
#   docker build -t secscan .
#   docker run --rm -v "$(pwd)/sample_vuln_app:/target" -v "$(pwd)/reports:/out" \
#       secscan /target --all --report /out
#
# Windows PowerShell:
#   docker run --rm -v "${PWD}\sample_vuln_app:/target" -v "${PWD}\reports:/out" `
#       secscan /target --all --report /out

FROM python:3.12-slim

ARG TRIVY_VERSION=0.72.0
ARG GITLEAKS_VERSION=8.30.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Trivy (dependency CVEs)
RUN curl -sSfL -o /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz

# Gitleaks (secrets)
RUN curl -sSfL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz

WORKDIR /app
COPY requirements.txt .
# Semgrep ships as a Python package, so it installs with our own deps.
RUN pip install --no-cache-dir -r requirements.txt semgrep

COPY . .

# Arguments after the image name go straight to the CLI.
ENTRYPOINT ["python", "main.py"]
CMD ["/target", "--all", "--report", "/out"]
