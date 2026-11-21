# Imagen de Jenkins para el pipeline DevSecOps del P3 (OCY1102).
# Mismo enfoque que la clase del 30-oct: las herramientas de seguridad viven DENTRO
# de Jenkins, así el pipeline no necesita el socket de Docker del host.
# 21-nov: se sube desde 2.541.3-lts-jdk17 porque Jenkins avisó 4 grupos de vulnerabilidades
# del núcleo (corregidas en LTS 2.580.2) y el fin de soporte de Java 17.
FROM jenkins/jenkins:2.580.2-lts-jdk21

USER root

# Python para correr la app en staging + utilidades que usa el pipeline.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv python3-pip curl jq \
 && rm -rf /var/lib/apt/lists/*

# Herramientas de seguridad en un venv aparte (/opt/sec), agregadas al PATH:
#   bandit    -> SAST (analiza el código sin ejecutarlo)
#   pip-audit -> SCA  (cruza las dependencias con bases de CVE)
RUN python3 -m venv /opt/sec \
 && /opt/sec/bin/pip install --no-cache-dir bandit pip-audit
ENV PATH="/opt/sec/bin:${PATH}"

# OWASP ZAP (DAST). Se fija la versión para que la imagen sea reproducible.
ARG ZAP_VERSION=2.17.0
RUN curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
      | tar -xz -C /opt \
 && ln -s "/opt/ZAP_${ZAP_VERSION}/zap.sh" /usr/local/bin/zap.sh

USER jenkins

# Complementos de ZAP actualizados (incluye el Automation Framework que lee zap.yaml).
RUN zap.sh -cmd -silent -addonupdate || true

# Plugins de Jenkins que usa el Jenkinsfile.
RUN jenkins-plugin-cli --plugins \
    workflow-aggregator git github pipeline-stage-view \
    junit htmlpublisher credentials-binding timestamper ws-cleanup
