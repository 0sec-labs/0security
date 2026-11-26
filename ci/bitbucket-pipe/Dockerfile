# Build from the repository root:
# docker build -f ci/bitbucket-pipe/Dockerfile -t 0security-pipe:0.46.0 .
FROM debian:bookworm-slim
ARG VERSION=0.46.0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git && rm -rf /var/lib/apt/lists/*
COPY install.sh /opt/zero/install.sh
COPY ci/scripts/ /opt/zero/ci/scripts/
COPY ci/bitbucket-pipe/pipe.sh /opt/zero/ci/bitbucket-pipe/pipe.sh
# The installer verifies the release binary against the published checksums.txt.
# Signatures are additionally checked when cosign is supplied by a downstream build.
RUN printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
    && INSTALL_DIR=/usr/local/bin RELEASE_BASE_URL="https://github.com/0sec-labs/0security/releases/download/v${VERSION}" sh /opt/zero/install.sh \
    && chmod 755 /opt/zero/ci/bitbucket-pipe/pipe.sh \
    && 0security --version
ENTRYPOINT ["/opt/zero/ci/bitbucket-pipe/pipe.sh"]
