---
description: Launch RECON (backend + frontend) and drive the full UI flow — login, paste alert, screenshot the analyst report. Uses Chrome headless via CDP over websocket (no Playwright — greenlet DLL fails on this Windows Python).
---

# Running RECON end-to-end

RECON has two processes and a browser-driven UI. Every `/run` needs
all three, plus real interaction so we can verify the round-N sources
actually surface in the analyst-visible output.

## Prereqs (already satisfied on this machine)

- Python venv at `threat-intel-app/backend/venv` with `websockets` installed
- `frontend/.env.development` present (fixes the CRA5 `allowedHosts` boot crash)
- Chrome installed at `C:\Program Files\Google\Chrome\Application\chrome.exe`
- `data/config.json` populated (VirusTotal / AbuseIPDB / OTX / etc.)

Do NOT install Playwright — its `greenlet` binary fails to load on
this Windows Python (`ImportError: DLL load failed while importing _greenlet`).
CDP over websocket works with the `websockets` package already in the venv.

## Step 1 — spawn both servers

```bash
export AUTH_USERNAME=analyst
export AUTH_PASSWORD_HASH='$2b$10$tDedpRawg4xw1Sx3Xz7DnOulB05GFpZTfiuAMr98zqC.4dsZaOzEq'  # pw: recon-e2e-test-2026
export AUTH_SESSION_SECRET='beeb3bbd8ab0e38cdac6e043a1bae6ee7511123d5691557fa42bbdb6d9a62998'
cd threat-intel-app/backend
./venv/Scripts/python.exe -m uvicorn main:app --port 8000 --host 127.0.0.1 --log-level warning > _be.log 2>&1 &
cd ../frontend && npm start > _fe.log 2>&1 &
```

Then wait for both to bind:

```bash
until curl -sf http://127.0.0.1:8000/api/health -o /dev/null 2>&1 \
   && curl -sf http://127.0.0.1:3000/ -o /dev/null 2>&1; do sleep 5; done
```

Frontend dev server takes ~30-45s to compile on cold start.

## Step 2 — write the drive script

Save the script below as `backend/_run.py`. It:

1. Spawns Chrome headless with `--remote-debugging-port=9222` +
   `--user-data-dir=_shots/profile` (avoids polluting the real Chrome profile)
2. Connects to CDP over websocket
3. Navigates → waits 8s for React hydrate + auth-check fetch → screenshots
4. Fills login form via `dispatchEvent(new Event('input'))` on native setter
5. Pastes alert into textarea (base64-encoded to bypass JS-string escaping),
   clicks Analyze via setTimeout(500ms) inside the paste JS
6. Polls DOM for "Response … Generated" text (~60-100s wall)
7. Full-page screenshot via `Emulation.setDeviceMetricsOverride`

All JS runs synchronously in `Runtime.evaluate` — no `awaitPromise`. Long-
running promises get GC'd by CDP with error `-32000 Promise was collected`.

```python
"""Full RECON drive via Chrome + CDP."""
import asyncio, base64, json, subprocess, sys, time, urllib.request
import websockets

sys.stdout.reconfigure(encoding="utf-8")
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SHOTS  = r"C:\Users\elias\Desktop\threat-intel\threat-intel-app\backend\_shots"
DEBUG_PORT = 9222

proc = subprocess.Popen([
    CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
    "--hide-scrollbars", "--window-size=1400,1000",
    f"--remote-debugging-port={DEBUG_PORT}",
    f"--user-data-dir={SHOTS}\\profile", "about:blank",
])
time.sleep(2)
for _ in range(40):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{DEBUG_PORT}/json") as r:
            page = next((t for t in json.loads(r.read())
                         if t.get("type") == "page"), None)
        if page: break
    except Exception: pass
    time.sleep(0.5)
ws_url = page["webSocketDebuggerUrl"]

ALERT = ("Paste your realistic alert here — this is what the "
         "user would type into the RECON textarea.")

async def main():
    async with websockets.connect(ws_url, max_size=30*1024*1024) as ws:
        _id = [0]
        async def cmd(method, params=None, timeout=30):
            _id[0] += 1; mid = _id[0]
            await ws.send(json.dumps({"id": mid, "method": method,
                                       "params": params or {}}))
            while True:
                r = json.loads(await asyncio.wait_for(ws.recv(), timeout))
                if r.get("id") == mid:
                    if "error" in r: raise RuntimeError(r["error"])
                    return r.get("result") or {}
        async def shot(name):
            r = await cmd("Page.captureScreenshot", {"format": "png"})
            with open(f"{SHOTS}\\{name}.png", "wb") as f:
                f.write(base64.b64decode(r["data"]))
        async def js(expr):
            r = await cmd("Runtime.evaluate", {"expression": expr,
                                                 "returnByValue": True})
            return r.get("result", {}).get("value")

        await cmd("Page.enable"); await cmd("Runtime.enable")
        await cmd("Page.navigate", {"url": "http://localhost:3000/"})
        await asyncio.sleep(8.0)
        await shot("01_login")

        await js("""(()=>{const setV=(el,v)=>{const s=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el),'value').set;s.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));};let u=null,p=null;document.querySelectorAll('input').forEach(el=>{if((el.type||'').toLowerCase()==='password')p=el;else if(!u)u=el;});setV(u,'analyst');setV(p,'recon-e2e-test-2026');[...document.querySelectorAll('button')].find(b=>/sign in/i.test(b.textContent)).click();})()""")
        await asyncio.sleep(4.0)
        await shot("02_dashboard")

        b64 = base64.b64encode(ALERT.encode()).decode()
        await js(f"""(()=>{{const bin=atob('{b64}');const bytes=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)bytes[i]=bin.charCodeAt(i);const txt=new TextDecoder().decode(bytes);const ta=document.querySelector('textarea');const setter=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(ta),'value').set;setter.call(ta,txt);ta.dispatchEvent(new Event('input',{{bubbles:true}}));setTimeout(()=>{{const btn=[...document.querySelectorAll('button')].find(b=>/^\\s*analyze\\s*$/i.test(b.textContent)&&!b.disabled);if(btn)btn.click();}},500);}})()""")
        await asyncio.sleep(3.0)

        for i in range(40):
            await asyncio.sleep(5.0)
            done = await js("(()=>{const t=document.body.innerText||'';return /response/i.test(t)&&/generated/i.test(t);})()")
            if done: break
        await asyncio.sleep(2.0)
        await shot("04_viewport")

        dims = json.loads(await js("JSON.stringify({w:document.documentElement.scrollWidth,h:document.documentElement.scrollHeight})"))
        await cmd("Emulation.setDeviceMetricsOverride", {
            "width": min(dims["w"], 1600), "height": min(dims["h"], 8000),
            "deviceScaleFactor": 1, "mobile": False})
        await asyncio.sleep(0.75)
        await shot("05_full_report")

asyncio.run(main())
proc.terminate()
try: proc.wait(timeout=5)
except: proc.kill()
```

## Step 3 — verify the screenshots

Read `_shots/04_viewport.png` and `_shots/05_full_report.png`. A working
run shows:

- Sidebar: RECON logo, pasted text in textarea, "Analyze again" blue button,
  four green ✓ next to Triage / Enrichment / Investigation / Response
- Main: SUMMARY card with a numeric threat score + tier distribution +
  per-indicator score table + Recommended Action + analyst prose paragraph

A blank frame or a "loading skeleton" screenshot means React never
hydrated — check the wait time in step 4 or the `/api/whoami` response.

## Step 4 — shutdown + cleanup

```bash
for port in 3000 8000 9222; do
  pid=$(netstat -ano | grep LISTENING | grep ":$port " | awk '{print $5}' | head -1)
  [ -n "$pid" ] && taskkill //F //PID $pid
done
taskkill //F //IM chrome.exe 2>/dev/null
rm _run.py _be.log ../frontend/_fe.log
rm -rf _shots/profile
```

Screenshots stay under `_shots/` — remove if you want the tree clean.

## Known behaviours (not bugs)

- **crt.sh returns 502 frequently** — has retry + 40s timeout + graceful
  degrade in `intel/crt_sh.py`. Missing crt.sh row for a domain is normal.
- **Ransomware.live only surfaces active groups** — dormant families
  (LockBit post-Cronos) won't render even if the analyst prose names them.
- **MISP warninglist filters common IOCs upstream** — Tor exits from the
  MISP snapshot, `contoso.onmicrosoft.com`, `login.microsoftonline.com`
  land in `suppressed_iocs` and don't get enriched. This is correct.
- **Textarea auto-submits on Enter** — the paste JS uses setTimeout(500)
  to click Analyze explicitly, but paste alone often triggers analysis.
