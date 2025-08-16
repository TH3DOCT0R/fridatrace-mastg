# FridaTrace-MASTG — Mobile Runtime Instrumentation (Educational)

Purpose: observe **runtime flows** in Android apps aligned with MASTG (dynamic analysis), without bypassing protections.  
This toolkit attaches via Frida and logs:
- Crypto API usage (algorithm, mode, input/output sizes — **no raw secrets**)
- OkHttp requests (method, URL, header **names**; no bodies)
- WebView loads/evaluations (URLs, lengths)
- Pinning **detection only** (CertificatePinner/TrustManager callbacks) — no bypass

> Use only on devices/apps you own or have explicit permission to test. Do **not** disable security features; this repo avoids bypass code by design.

---

## Requirements
- Android device/emulator with **USB debugging** enabled
- `adb` on PATH
- Python 3.10+
- Frida server matching device ABI/version (push & run manually)
- Pip packages: `frida`, `frida-tools`, `rich`

Install:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
Quick start
List processes:

bash
Copy
Edit
frida-ps -Uai
Attach & trace (pick one or more scripts):

bash
Copy
Edit
python runner.py -p com.example.app \
  --crypto --okhttp --webview --pinning \
  --out ./logs
Stop: Ctrl+C (graceful detach). Logs land under ./logs/<timestamp>/.

Options
lua
Copy
Edit
-p, --package         Android package name (required)
--crypto              Load scripts/trace_crypto.js
--okhttp              Load scripts/trace_okhttp.js
--webview             Load scripts/trace_webview.js
--pinning             Load scripts/detect_pinning.js (detect-only)
--out                 Logs directory (default: ./logs)
--spawn               Spawn the app instead of attach (cold start)
--enable-stacks       Include Java stacks for selected events (verbose)
Output
events.jsonl — one JSON object per event

session.log — pretty console transcript (colorized)

notes.txt — quick jot area for your observations

Sample event (crypto):

json
Copy
Edit
{"type":"crypto","cls":"javax.crypto.Cipher","algo":"AES/ECB/PKCS5Padding","op":"doFinal","in_len":128,"out_len":144,"ts":"2025-08-16T10:15:35.123Z"}
Safety guardrails
No key material or plaintext dumps

No certificate override / no hook that “returns true” for checks

OkHttp: URL + method + header names only

MASTG mapping (high level)
MASVS-RESILIENCE-1/2 (detection only), MAS-I, MAS-C (runtime observation)
