# syntax=docker/dockerfile:1
#
# sozin-recon — self-contained recon engine image.
# Bakes in every external CLI the pipeline shells out to, plus SecLists and the
# nuclei template set, so `docker run` needs nothing on the host but a run dir.
#
# Multi-stage:
#   gobuild   — all Go tools (ProjectDiscovery suite + community) + massdns
#   rustbuild — x8 (Rust)
#   runtime   — Python 3 + the compiled binaries + Ruby/whatweb + Chromium + data
#
# NOTE: tools are pulled at @latest for a first cut. Pin exact versions before
# treating a build as reproducible (the pipeline verified specific tool
# interfaces; a silent upstream change is exactly what this project's
# "never trust a tool's docs — run it" discipline exists to catch).

########################## Go tools + massdns ##########################
FROM golang:1.25-bookworm AS gobuild
ENV GOBIN=/out
# GOTOOLCHAIN=auto lets `go install ...@latest` fetch a newer toolchain if a
# tool's go.mod requires one (the PD suite tracks recent Go closely), so the
# build doesn't break every time upstream bumps its minimum Go.
ENV GOTOOLCHAIN=auto
RUN mkdir -p /out
RUN apt-get update && apt-get install -y --no-install-recommends \
        git make gcc libpcap-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery + community Go tools (each installs into /out via GOBIN).
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/alterx/cmd/alterx@latest \
 && go install github.com/d3mondev/puredns/v2@latest \
 && go install github.com/owasp-amass/amass/v4/...@master \
 && go install github.com/tomnomnom/assetfinder@latest \
 && go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/bp0lr/gauplus@latest \
 && go install github.com/ffuf/ffuf/v2@latest \
 && go install github.com/BishopFox/jsluice/cmd/jsluice@latest
# NOTE: "certspotter" is NOT a binary here — stage 1 queries the certspotter
# HTTPS JSON API (api.certspotter.com) via curl, which the runtime stage ships.

# massdns — puredns's resolution engine (built from source).
RUN git clone --depth 1 https://github.com/blechschmidt/massdns /tmp/massdns \
 && make -C /tmp/massdns \
 && cp /tmp/massdns/bin/massdns /out/massdns

########################## Rust tools ##########################
FROM rust:1-bookworm AS rustbuild
RUN cargo install x8 --root /out    # → /out/bin/x8

########################## Runtime ##########################
FROM python:3.12-slim-bookworm AS runtime

# Runtime OS deps:
#   whatweb (+ruby)  — stage 9 fingerprinting
#   chromium         — stage C2 screenshots via `httpx -system-chrome`
#   libpcap0.8       — naabu runtime
#   git, curl, ca-certificates, sqlite3 — SecLists clone / TLS / inspection
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git curl sqlite3 \
        libpcap0.8 \
        ruby whatweb \
        chromium \
    && rm -rf /var/lib/apt/lists/*

# Compiled binaries from the builder stages.
COPY --from=gobuild   /out/       /usr/local/bin/
COPY --from=rustbuild /out/bin/x8 /usr/local/bin/x8

# SecLists — cloned to ~/tools/SecLists (i.e. /root/tools/SecLists, since the
# image runs as root). This is the path BOTH wordlist consumers resolve:
#   - stage 3 DNS brute force hardcodes ~/tools/SecLists/Discovery/DNS/...
#   - stage 6.5 content discovery checks ~/tools/SecLists first, else
#     /usr/share/seclists. A symlink covers the fallback + non-root readers.
# (puredns resolvers are a hardcoded in-code set — no resolvers file needed.)
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists /root/tools/SecLists \
 && ln -s /root/tools/SecLists /usr/share/seclists

# nuclei templates (baked in so the first run doesn't need to fetch them).
RUN nuclei -update-templates || true

# Chromium under Docker (root, no user namespace) needs --no-sandbox; expose the
# path so the screenshot stage / httpx can find a system chrome.
ENV CHROME_PATH=/usr/bin/chromium

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir wafw00f \
 && pip install --no-cache-dir 'git+https://github.com/devanshbatham/paramspider.git'

COPY . .

# `docker run sozin-recon --run-dir /runs/<name>`
ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
