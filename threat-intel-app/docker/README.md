# RECON file-analyzer sidecar stack

Ten Dockerised sidecars activate the file analyzers that need native
tools (emulators, honeyclients, daemons) RECON can't ship in-process.
With this stack running, `POST /api/files/analyze` dispatches to each
service in parallel and merges the results into a single verdict.

## What's in the stack

| Service       | Port | Tool                            | File types          |
|---------------|-----:|---------------------------------|---------------------|
| qiling        | 5001 | Qiling PE/ELF emulation         | pe, elf, shellcode  |
| speakeasy     | 5002 | Mandiant Speakeasy (Win PE)     | pe                  |
| thug          | 5003 | Thug honeyclient                | html, js            |
| box_js        | 5004 | Node.js box-js JS emulator      | js                  |
| mobsf         | 5005 | MobSF static+dynamic APK scan   | apk, ipa            |
| quark_engine  | 5006 | Quark rule-based APK scoring    | apk, dex            |
| clamav        | 5007 | ClamAV signature scan           | any                 |
| suricata      | 5008 | Suricata PCAP IDS alerts        | pcap                |
| hfinger       | 5009 | CERT.pl HTTP fingerprint PCAP   | pcap                |
| stringsifter  | 5010 | Mandiant ML-ranked strings      | pe, elf             |

## Activating

```sh
cd threat-intel-app/docker
docker compose up -d                   # all services
# or just the ones you need:
docker compose up -d qiling clamav suricata
```

Then set the matching env vars in the backend before starting
`uvicorn main:app`:

```sh
export RECON_QILING_URL=http://localhost:5001
export RECON_SPEAKEASY_URL=http://localhost:5002
export RECON_THUG_URL=http://localhost:5003
export RECON_BOXJS_URL=http://localhost:5004
export RECON_MOBSF_URL=http://localhost:5005
export RECON_QUARK_URL=http://localhost:5006
export RECON_CLAMAV_URL=http://localhost:5007
export RECON_SURICATA_URL=http://localhost:5008
export RECON_HFINGER_URL=http://localhost:5009
export RECON_STRINGSIFTER_URL=http://localhost:5010
```

Each service also publishes `GET /health` so you can smoke-check
with `curl localhost:5007/health`.

## Service contract

Every sidecar implements the same two endpoints:

```
POST /analyze
  Content-Type: multipart/form-data
  Fields:
    file     — the file bytes
    filename — optional display name

  → 200 application/json  { verdict?, summary?, …tool-specific fields }
  → 4xx/5xx application/json  { error, error_type? }
```

The main backend's `plugins/file_analyzers/_docker_dispatch.py` does
the multipart POST, maps the response into an `AnalysisResult`, and
retries once on transient 5xx / timeout.

## Writing a custom sidecar

Each service is a thin wrapper around `_base_wrapper.build_app`:

```python
# my_service.py
from _base_wrapper import run

def analyze_bytes(data: bytes, filename: str) -> dict:
    # ... run your tool ...
    return {"verdict": "SUSPICIOUS", "summary": "...", "extra_fields": [...]}

if __name__ == "__main__":
    run("my_tool", analyze_bytes, default_port=5099)
```

Build it against `Dockerfile.python`:

```
docker build -f Dockerfile.python \
             --build-arg SERVICE=my_service \
             --build-arg TOOLS="my-pip-package" \
             -t recon-sidecar-my_tool ./sidecars
```

The service is immediately registry-visible via a new entry in
`plugins/file_analyzers/docker_stubs.py` + env var
`RECON_MY_TOOL_URL`.
