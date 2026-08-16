# Chainwatch — the whole product, not just the agent.
#
# The image carries the deterministic engine (Slither + solc + the nine rules),
# the scan pipeline, the web app AND the reporting agent, because the claim
# being demonstrated is end to end: a repository's history goes in, an
# attributed finding with a verdict comes out, and only then does a model write
# about it. An image containing only the agent would demo the least defensible
# half.
#
# CREDENTIALS ARE NEVER BAKED IN. There is no ARG or ENV for GEMINI_API_KEY
# here and no .env is copied (see .dockerignore). The key is injected at RUN
# time — locally with `-e`, on Cloud Run with a Secret Manager reference:
#
#   docker run -p 8080:8080 -e GEMINI_API_KEY=... chainwatch
#   gcloud run deploy chainwatch --image ... \
#       --set-secrets=GEMINI_API_KEY=chainwatch-gemini-key:latest
#
# A key baked into a layer is readable by anyone who can pull the image, and
# `docker history` will show it even if a later layer deletes it.
#
# Python 3.12 deliberately, not the 3.14 this project develops on: ADK declares
# >=3.10 but is not tested on 3.14, and an image is the wrong place to find out.

FROM python:3.12-slim

# git      - the walker reads target history through it
# nodejs   - per-commit dependency reconstruction (npm/yarn/pnpm)
# curl/ca- - solc-select downloads compiler binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates nodejs npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The app user is created BEFORE the compilers are installed, and the install
# runs AS that user, because solc-select resolves its artifact directory from
# `Path.home()` and has no override. Installing as root put the compilers in
# /root/.solc-select where the app user cannot see them; solc-select then
# silently auto-installed whatever was latest (0.8.36) at run time, and every
# fixture pinned to 0.8.20 failed with "requires different compiler version".
# Caught by the container smoke test, which is the entire reason it exists.
RUN useradd -m -u 1000 chainwatch && chown -R chainwatch:chainwatch /app
USER chainwatch

# Bake the compilers this project's own fixtures and its documented real-world
# targets need. More can be added at run time; a missing one is reported as a
# per-file skip ("solc <v> not installed") rather than a silent wrong answer,
# which is the HIST-L2 pre-flight doing its job.
RUN solc-select install 0.7.6 0.8.20 0.8.27 0.8.28 && solc-select use 0.8.20

# A repository mounted into the container is owned by the host's uid, not this
# user's, so git refuses it with "detected dubious ownership" and every scan
# fails before it starts. `safe.directory=*` is the correct scope HERE and
# would not be on a workstation: the container is isolated, target repos are
# mounted read-only, and Chainwatch only ever READS them (CHARTER rule 5 — no
# commit, no push, no lifecycle scripts). The setting relaxes an
# ownership-spoofing protection whose threat model is a shared multi-user host;
# it is not what stops Chainwatch writing to a target, and nothing here does.
RUN git config --global --add safe.directory '*'

COPY --chown=chainwatch:chainwatch src/ ./src/
COPY --chown=chainwatch:chainwatch agent/ ./agent/
COPY --chown=chainwatch:chainwatch webapp/ ./webapp/
COPY --chown=chainwatch:chainwatch chainwatch.py scorer.py guard.sh ./
COPY --chown=chainwatch:chainwatch package.json ./
COPY --chown=chainwatch:chainwatch RULES.md CHARTER.md LIMITATIONS.md README.md \
     AGENT-DESIGN.md SUBMISSION-NOTES.md ./

# The OpenZeppelin trees the frozen fixtures compile against. Small, and it
# keeps `scorer.py` runnable inside the image — a judge can verify the
# precision claim in the container rather than taking it on faith.
COPY --chown=chainwatch:chainwatch node_modules/ ./node_modules/
COPY --chown=chainwatch:chainwatch fixtures/ ./fixtures/
COPY --chown=chainwatch:chainwatch fixtures-r1/ ./fixtures-r1/
COPY --chown=chainwatch:chainwatch fixtures-r2/ ./fixtures-r2/
COPY --chown=chainwatch:chainwatch fixtures-r2b/ ./fixtures-r2b/
COPY --chown=chainwatch:chainwatch fixtures-r4/ ./fixtures-r4/
COPY --chown=chainwatch:chainwatch fixtures-r5/ ./fixtures-r5/
COPY --chown=chainwatch:chainwatch fixtures-r6/ ./fixtures-r6/

# Cloud Run injects PORT; 8080 is its default. Binding 0.0.0.0 is correct
# INSIDE a container (the process is already isolated) — unlike the local
# default of 127.0.0.1, which exists because a scan installs a target
# repository's dependencies.
ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request,os,sys; \
sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",8080)}/healthz', timeout=4).status==200 else 1)"

CMD ["sh", "-c", "python webapp/server.py --host 0.0.0.0 --port ${PORT:-8080}"]
