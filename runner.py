#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List
import frida
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

SCRIPTS = {
    "crypto": "scripts/trace_crypto.js",
    "okhttp": "scripts/trace_okhttp.js",
    "webview": "scripts/trace_webview.js",
    "pinning": "scripts/detect_pinning.js",
}

def iso_now():
    return datetime.now(timezone.utc).isoformat()

def load_script(session: frida.core.Session, path: Path):
    src = path.read_text(encoding="utf-8")
    script = session.create_script(src)
    return script

def main():
    ap = argparse.ArgumentParser(description="FridaTrace-MASTG")
    ap.add_argument("-p", "--package", required=True, help="Android package name")
    ap.add_argument("--crypto", action="store_true")
    ap.add_argument("--okhttp", action="store_true")
    ap.add_argument("--webview", action="store_true")
    ap.add_argument("--pinning", action="store_true", help="Detect CertificatePinner/TrustManager usage (no bypass)")
    ap.add_argument("--spawn", action="store_true", help="Spawn instead of attach")
    ap.add_argument("--enable-stacks", action="store_true", help="Include Java stacks (verbose)")
    ap.add_argument("--out", default="./logs", help="Output directory")
    args = ap.parse_args()

    enabled = [k for k in ["crypto","okhttp","webview","pinning"] if getattr(args,k)]
    if not enabled:
        console.print("[red]No scripts selected. Use --crypto/--okhttp/--webview/--pinning[/]")
        sys.exit(2)

    out_root = Path(args.out)
    run_dir = out_root / datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    ev_path = run_dir / "events.jsonl"
    log_path = run_dir / "session.log"
    notes_path = run_dir / "notes.txt"
    notes_path.write_text("# jot observations here\n", encoding="utf-8")

    console.rule("[bold]FridaTrace-MASTG")
    info = Panel.fit(f"Package: [bold]{args.package}[/] • Scripts: {', '.join(enabled)} • Spawn: {args.spawn}")
    console.print(info)

    device = frida.get_usb_device(timeout=8)

    pid = None
    if args.spawn:
        pid = device.spawn([args.package])
        session = device.attach(pid)
    else:
        session = device.attach(args.package)

    scripts = []
    for key in enabled:
        path = Path(SCRIPTS[key]).resolve()
        s = load_script(session, path)

        def on_message(msg, data):
            if msg["type"] == "send":
                payload = msg.get("payload", {})
                if isinstance(payload, dict):
                    payload.setdefault("ts", iso_now())
                    ev_path.write_text("", encoding="utf-8") if not ev_path.exists() else None
                    with ev_path.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
                    console.print(payload)
                else:
                    console.print(payload)
            elif msg["type"] == "error":
                console.print(f"[red]Script error:[/] {msg.get('stack') or msg}")

        s.on("message", on_message)

        # Enable optional stacks in scripts
        s.load()
        s.post({"type": "config", "enableStacks": bool(args.enable_stacks)})
        scripts.append(s)

    if args.spawn and pid:
        device.resume(pid)

    console.print(Panel.fit(f"Logging to: {run_dir}"))
    try:
        while True:
            time.sleep(0.25)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Detaching...[/]")
        for s in scripts:
            try: s.unload()
            except Exception: pass
        try: session.detach()
        except Exception: pass
        console.print("[green]Done.[/]")
        sys.exit(0)

if __name__ == "__main__":
    main()
