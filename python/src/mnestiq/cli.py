"""mnestiq command line: verify, keygen, inspect, redact, dashboard, signer."""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path

from .canonical import canonical_json
from .hashing import redact
from .keys import ED25519, SIG_ALGS, generate_private_key, key_id, load_public_key_b64, public_key_b64, save_keypair
from .verify import verify_file

EXIT_OK, EXIT_INVALID, EXIT_USAGE = 0, 1, 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mnestiq", description="Agent evidence chain tools.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("verify", help="verify an evidence file")
    p.add_argument("file")
    p.add_argument("--trusted-key", action="append", default=[], metavar="KEY",
                   help="public key (base64 or path to .pub) allowed to sign checkpoints; repeatable")
    p.add_argument("--head", metavar="FILE",
                   help="latest checkpoint kept elsewhere (HeadFile); detects a file cut back to an earlier one")
    p.add_argument("--json", action="store_true", help="machine-readable output")

    p = sub.add_parser("keygen", help="generate a signing keypair")
    p.add_argument("--out", default=".", help="directory for signing.key / signing.pub")
    p.add_argument("--name", default="signing")
    p.add_argument("--alg", choices=SIG_ALGS, default=ED25519)

    p = sub.add_parser("inspect", help="print a timeline of an evidence file")
    p.add_argument("file")
    p.add_argument("--run", help="only show this run_id")

    p = sub.add_parser("redact", help="strip prompt/tool content; the result still verifies")
    p.add_argument("file")
    p.add_argument("out")

    p = sub.add_parser("dashboard", help="open the local evidence dashboard (127.0.0.1 only)")
    p.add_argument("path", nargs="?", default=".", help="evidence file or folder of .jsonl files (default: .)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--trusted-key", action="append", default=[], metavar="KEY")
    p.add_argument("--no-open", action="store_true", help="don't open a browser")

    p = sub.add_parser("signer", help="a signing service that keeps the key away from the agent")
    signer = p.add_subparsers(dest="signer_command", required=True)
    s = signer.add_parser("init", help="create a key and an access token in a folder only the service can read")
    s.add_argument("dir")
    s.add_argument("--alg", choices=SIG_ALGS, default=ED25519)
    s = signer.add_parser("serve", help="sign checkpoints for agents that hold the token")
    s.add_argument("dir")
    s.add_argument("--listen", default="127.0.0.1:8741", help="127.0.0.1:<port>, or a Unix socket path")
    s.add_argument("--max-skew", type=float, default=300.0,
                   help="refuse checkpoints whose time is further than this from the signer's clock (seconds)")

    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):  # evidence may hold characters the console can't encode
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
    try:
        return {"verify": _verify, "keygen": _keygen, "inspect": _inspect, "redact": _redact,
                "dashboard": _dashboard, "signer": _signer}[args.command](args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


def _verify(args: argparse.Namespace) -> int:
    keys = [load_public_key_b64(k) for k in args.trusted_key]
    head = None
    if args.head:
        head = json.loads(Path(args.head).read_text("utf-8"))
        if not isinstance(head, dict):  # e.g. "null": must not quietly turn the check off
            raise ValueError(f"{args.head} does not hold a checkpoint record")
    report = verify_file(args.file, keys, head)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return EXIT_OK if report.ok else EXIT_INVALID

    print(f"{'VALID' if report.ok else 'INVALID'}  {args.file}")
    print(f"  chain     {report.chain_id}")
    print(f"  records   {report.records} ({report.events} events, {report.checkpoints} checkpoints)")
    if report.signed_through_seq is not None:
        print(f"  signed    through seq {report.signed_through_seq} by {', '.join(report.signer_keys)}")
    for rot in report.rotations:
        print(f"  handover  at seq {rot['seq']}: {rot['from_key']} -> {rot['to_key']}")
    if report.head_seq is not None:
        print(f"  head      matches the checkpoint at seq {report.head_seq} kept elsewhere")
    for issue in report.errors:
        print(f"  ERROR   {_where(issue)}{issue.code}: {issue.message}")
    for issue in report.warnings:
        print(f"  warning {_where(issue)}{issue.code}: {issue.message}")
    return EXIT_OK if report.ok else EXIT_INVALID


def _where(issue) -> str:
    parts = []
    if issue.line is not None:
        parts.append(f"line {issue.line}")
    if issue.seq is not None:
        parts.append(f"seq {issue.seq}")
    return f"[{', '.join(parts)}] " if parts else ""


def _keygen(args: argparse.Namespace) -> int:
    key = generate_private_key(args.alg)
    priv, pub = save_keypair(key, args.out, args.name)
    print(f"private key  {priv}   (keep secret; give it to the recorder only)")
    print(f"public key   {pub}   (pin this with verify --trusted-key)")
    print(f"key id       {key_id(public_key_b64(key))}")
    return EXIT_OK


def _signer(args: argparse.Namespace) -> int:
    from .signer_service import SignerService, init_signer
    from .signers import SignerError

    try:
        if args.signer_command == "init":
            signer = init_signer(args.dir, args.alg)
            print(f"signer created in {args.dir}")
            print(f"  key id      {key_id(signer.public_key)} ({signer.sig_alg})")
            print(f"  public key  {signer.public_key}   (pin this with verify --trusted-key)")
            print(f"  token       {Path(args.dir) / 'signer.token'}   (give it to the agent, never the key)")
            print("Run `mnestiq signer serve` under the account that owns this folder.")
            return EXIT_OK
        service = SignerService(args.dir, max_skew=args.max_skew)
        server = service.start(args.listen)
    except SignerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(f"signing as {service.key_id} on {server.address}; every signature is logged in "
          f"{Path(args.dir) / 'signatures.jsonl'}. Ctrl+C stops.", flush=True)
    try:
        server.wait()
    except KeyboardInterrupt:
        server.close()
    return EXIT_OK


def _inspect(args: argparse.Namespace) -> int:
    with open(args.file, "rb") as fh:
        for raw in fh:
            if not raw.strip():
                continue
            rec = json.loads(raw)
            if args.run and rec.get("run_id") != args.run:
                continue
            ts = rec.get("ts", {}).get("wall", "?")
            if rec.get("kind") == "checkpoint":
                c = rec.get("covers", {})
                print(f"{ts}  #{rec['seq']:<5} ---- checkpoint seq {c.get('from_seq')}..{c.get('to_seq')} "
                      f"signed by {rec.get('key_id')}")
                continue
            print(f"{ts}  #{rec['seq']:<5} {rec.get('run_id', '')[:8]}/{rec.get('step_id', '-'):<3} "
                  f"{rec.get('event_type', '?'):<10} {_summary(rec)}")
    return EXIT_OK


def _summary(rec: dict) -> str:
    et = rec.get("event_type")
    if et == "llm_call":
        model = rec.get("model", {})
        srcs = sorted({s.get("source") for s in rec.get("context", [])})
        calls = [tc.get("name") for tc in rec.get("tool_calls", [])]
        s = f"{model.get('version') or model.get('name')}  context={','.join(srcs)}"
        return s + (f"  -> calls {', '.join(calls)}" if calls else "")
    if et == "tool_call":
        tc = (rec.get("tool_calls") or [{}])[0]
        s = f"{tc.get('name')}  result_source={tc.get('result_source')}"
        return s + (f"  ERROR {tc.get('error')}" if tc.get("error") else "")
    if et == "approval":
        a = (rec.get("approvals") or [{}])[0]
        return f"{a.get('action')}: {a.get('decision')} by {a.get('approver')}"
    if et == "run_start":
        return f"agent={rec.get('agent_id')} parent={rec.get('parent_run_id')}"
    if et == "run_end":
        return f"status={rec.get('status')}" + (f"  {rec.get('error')}" if rec.get("error") else "")
    if et == "egress":
        e = (rec.get("egress") or [{}])[0]
        src = f"{e.get('source_ip')}:{e.get('source_port')}" if e.get("source_port") else "?"
        dst = f"{e.get('dest_ip') or e.get('host')}:{e.get('dest_port')}"
        if e.get("protocol") == "http":
            what = f"{e.get('method')} {e.get('url')} -> {e.get('status')}"
        else:
            what = "TCP connect"
        return f"{what}  [{src} -> {dst}]" + (f"  ERROR {e.get('error')}" if e.get("error") else "")
    if et == "note":
        return str(rec.get("attributes", {}).get("message", ""))
    return ""


def _dashboard(args: argparse.Namespace) -> int:
    from .dashboard import serve

    if not Path(args.path).exists():
        raise ValueError(f"{args.path} does not exist")
    serve(args.path, trusted_keys=[load_public_key_b64(k) for k in args.trusted_key],
          port=args.port, open_browser=not args.no_open)
    return EXIT_OK


def _redact(args: argparse.Namespace) -> int:
    src, dst = Path(args.file), Path(args.out)
    if dst.exists():
        raise ValueError(f"{dst} already exists")
    count = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for raw in fin:
            if raw.strip():
                fout.write(canonical_json(redact(json.loads(raw))) + b"\n")
                count += 1
    print(f"wrote {count} redacted records to {dst}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
