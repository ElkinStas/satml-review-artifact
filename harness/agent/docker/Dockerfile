# rerag-re: base image for the reverse_rag execution path.
#
# Network model: the ORCHESTRATOR (this container) needs outbound network for the Anthropic API. Per-tool
# ISOLATION is enforced *inside* the container by bubblewrap (--unshare-net gives each tool call its own
# empty network namespace); do NOT run the container itself with --network=none, or the API is unreachable.
#
# Ghidra is intentionally out of scope for this study (angr/r2/gdb cover the tasks); not a deferred TODO.

# Base image pinned by DIGEST, not the floating 24.04 tag -- otherwise a rebuild after Ubuntu
# republishes 24.04 gets a different base and a different image digest.
FROM ubuntu:24.04@sha256:1e622c5f073b4f6bfad6632f2616c7f59ef256e96fe78bf6a595d1dc4376ac02

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1 \
    BLIS_NUM_THREADS=1 \
    VECLIB_MAXIMUM_THREADS=1

# System toolchain + bubblewrap (the sandbox constructor the execution backend requires).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc gdb strace ltrace file binutils radare2 \
        bubblewrap \
        python3 python3-pip python3-venv \
        git curl ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Python analysis stack + the Anthropic SDK, baked into the image from requirements-pilot.txt. BEFORE the
# canary build, pin the SDK there to the exact verified version (`anthropic==X.Y.Z`, not a floor). The SDK
# is never pip-installed by hand into a running container -- that breaks image reproducibility.
COPY requirements-pilot.txt /tmp/requirements-pilot.txt
# The analysis stack (angr/capstone/pwntools/z3/lief/pyelftools) is NO LONGER installed by
# bare name here -- that pulled "latest" on every rebuild and floated the image digest. All
# versions, including that stack, are pinned with == in requirements-pilot.txt and installed
# ONLY from it. --no-deps is deliberately NOT used (angr has a deep tree), but the top-level
# pins fix the versions that matter for reproducibility.
RUN pip3 install --break-system-packages --no-cache-dir -r /tmp/requirements-pilot.txt

# Image digest is provided at RUN time, not baked as a build-arg: baking a digest into the image would
# itself change the digest (circular). After building, capture the id and pass it in:
#   docker build -t rerag-re:week8 .
#   IMG=$(docker image inspect --format='{{.Id}}' rerag-re:week8)   # or the registry RepoDigest after push
#   docker run -e RERAG_IMAGE_DIGEST="$IMG" rerag-re:week8 ...
# pin_environment reads RERAG_IMAGE_DIGEST (or /etc/rerag_image_digest) and REQUIRES a sha256: value.

WORKDIR /work

# Sanity check: every tool launches (bubblewrap + RE toolchain).
COPY agent/docker/tools_install.sh /usr/local/bin/tools_install.sh
RUN chmod +x /usr/local/bin/tools_install.sh && /usr/local/bin/tools_install.sh

# First-run, inside this image (captures the real versions/digest into the locks):
#   python -m agent.pin_environment --regenerate && python -m agent.preflight --regenerate
#   python -m agent.integration_selftest        # must PASS before any registered run
CMD ["/bin/bash"]
