"""Sentinel Authority CLI.

  sentinel scan     - discover what the agent can currently reach
  sentinel plan     - task -> candidate Authority Manifest (rule-based or --llm)
  sentinel test     - adversarially attack the proposed authority
  sentinel compile  - export to Cedar / OPA / Claude hooks
  sentinel run      - execute a real process under enforced authority
  sentinel doctor   - one-command local posture check
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

if os.name == "nt":
    os.system("")  # enable ANSI escape sequences on Windows terminals


def _c(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def green(t): return _c("92", t)
def red(t): return _c("91", t)
def yellow(t): return _c("93", t)
def cyan(t): return _c("96", t)
def bold(t): return _c("1", t)
def dim(t): return _c("90", t)


BANNER = r"""
   __                  _   _   _       _ _
  / _|___  ___ _ __   | | | \ | | ___ | | |
 | __/ __|/ _ \ '__|  | |_|  \| |/ _ \| | |
 | |_\__ \  __/ |     |  _| |\  | (_) | | |
  \___|___/\___|_|     |_| |_| \_|\___/|_|_|   authority
"""


def cmd_scan(args) -> int:
    from .scanner import render_report, scan_profile
    result = scan_profile(args.profile)
    print(bold(BANNER))
    print(render_report(result))
    print()
    print(red(f"  Privilege gap: this agent holds {result['totals']['write_capable']} "
              f"write-capable actions and {len(result['credentials'])} standing credentials "
              "with ZERO task scoping."))
    return 0


def cmd_plan(args) -> int:
    from .planner import plan, verify_manifest
    from .core.schema import Manifest
    from .manifest_io import load as _manifest_load, save as _manifest_save

    task_text = Path(args.task).read_text(encoding="utf-8") if Path(args.task).exists() else args.task
    manifest, source, fallback_err = plan(task_text, use_llm=args.llm)

    if source == "llm":
        print(green("[sentinel] manifest PROPOSED by LLM ("
                    f"{os.environ.get('OPENROUTER_MODEL', 'z-ai/glm-5.2')}) via OpenRouter"))
    else:
        if fallback_err:
            print(yellow(f"[sentinel] LLM planning failed ({fallback_err}); using rule-based planner"))
        else:
            print(cyan("[sentinel] manifest derived by local rule-based planner"))

    warnings = verify_manifest(manifest, task_text)
    for w in warnings:
        print(yellow(f"  [verify] WARNING: {w}"))
    if not warnings:
        print(green("  [verify] deterministic checks passed"))

    out = args.out or "authority.yaml"
    _manifest_save(manifest, out)
    m: Manifest = manifest
    print()
    print(bold(f"Authority Manifest v{m.to_dict()['schema_version']} -> {out}"))
    for line in m.summary_lines():
        print(f"  {line}")
    print()
    print(dim("Note: the planner only PROPOSES. The deterministic evaluator is the boundary."))
    print(cyan("Next: sentinel test --manifest " + out))
    return 0


def cmd_test(args) -> int:
    from .attack_tests import render_report, run_suite
    from .core.schema import Manifest
    from .manifest_io import load as _manifest_load, save as _manifest_save

    manifest = _manifest_load(args.manifest)
    report = run_suite(manifest)
    body = render_report(report)
    print(body)
    return 0 if report["failed"] == 0 else 1


def cmd_compile(args) -> int:
    from .core.schema import Manifest
    from .manifest_io import load as _manifest_load, save as _manifest_save

    manifest = _manifest_load(args.manifest)
    base = Path(args.manifest).with_suffix("")
    out_path = Path(args.out) if args.out else None

    def ensure_parent(p: Path) -> Path:
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    if args.target == "cedar":
        from .compilers.cedar import compile_cedar
        out = ensure_parent(out_path or Path(str(base) + ".cedar"))
        out.write_text(compile_cedar(manifest), encoding="utf-8")
    elif args.target == "opa":
        from .compilers.opa import compile_opa
        out = ensure_parent(out_path or Path(str(base) + ".rego"))
        out.write_text(compile_opa(manifest), encoding="utf-8")
    elif args.target == "hooks":
        from .compilers.hooks import compile_hooks, compile_manifest_json
        hook_path = ensure_parent(out_path or Path("claude_hook.py"))
        manifest_json = Path(str(hook_path.with_suffix("")) + ".manifest.json")
        manifest_json.write_text(compile_manifest_json(manifest), encoding="utf-8")
        script = compile_hooks(manifest, out_path=hook_path, manifest_path=str(manifest_json))
        out = hook_path
        print(script)
        print(green(f"[sentinel] wrote {hook_path} and {manifest_json}"))
        return 0
    else:
        print(red(f"unknown target: {args.target}")); return 2
    print(green(f"[sentinel] compiled {args.manifest} -> {out} ({args.target})"))
    return 0


def cmd_run(args) -> int:
    from .runtime import run_guarded
    return run_guarded(args.manifest, args.cmd)


def cmd_vectors(args) -> int:
    from .vectors import render_summary, run_vectors
    import json as _json
    report = run_vectors()
    if args.format == "json":
        print(_json.dumps(report, indent=2))
    else:
        print(render_summary(report))
    return 0 if report["failed"] == 0 else 1


def cmd_migrate(args) -> int:
    """Upgrade a v0.1 Authority Manifest to schema v1.0 (semantics-preserving).

    mandate_id is derived deterministically from the canonical manifest body
    so re-migrating the same policy yields the same identity.
    """
    import hashlib
    from .core.schema import Manifest
    from .manifest_io import load as _manifest_load, save as _manifest_save

    m = _manifest_load(args.file)
    if not m.mandate_id:
        body = json.dumps(m.to_dict(), sort_keys=True, separators=(",", ":"))
        m.mandate_id = "mdt_" + hashlib.sha256(body.encode()).hexdigest()[:12]
    out = Path(args.out or args.file).with_suffix(".v1.yaml")
    _manifest_save(m, out)
    print(green(f"[sentinel] migrated {args.file} -> {out} (schema 1.0)"))
    for line in m.summary_lines():
        print(f"  {line}")
    return 0


def cmd_doctor(args) -> int:
    from .scanner import doctor_summary, scan_profile
    print(bold(BANNER))
    print(doctor_summary(scan_profile(args.profile)))
    print()
    print(cyan("Want a suggested authority manifest?"))
    print(cyan("  sentinel plan --task \"Fix GitHub issue #482 in acme/backend\""))
    return 0


def _data_home() -> Path:
    return Path(os.environ.get("SENTINEL_HOME_DATA",
                               str(Path.home() / ".sentinel")))


def _default_keys_dir() -> Path:
    return _data_home() / "keys"


def cmd_keygen(args) -> int:
    from .bundle.signing import generate_keypair
    keys_dir = Path(args.out) if args.out else _default_keys_dir()
    info = generate_keypair(keys_dir)
    print(green(f"[sentinel] generated ed25519 keypair"))
    print(f"  key_id  : {info['key_id']}")
    print(f"  private : {info['private']}")
    print(f"  public  : {info['public']}")
    print(dim("Trust anchor = the .pub file. Back up private keys securely; "
              "the PDP only ever reads .pub anchors."))
    return 0


def _resolve_signer(keys_dir: Path, key_id: Optional[str]):
    from .bundle.signing import FileEd25519Signer
    if key_id:
        priv = keys_dir / f"{key_id}.pem"
        if not priv.exists():
            raise FileNotFoundError(f"private key not found: {priv}")
        return FileEd25519Signer(priv)
    # newest private key wins
    privs = sorted(keys_dir.glob("ed25519_*.pem"), key=lambda p: p.stat().st_mtime)
    if not privs:
        raise FileNotFoundError(
            f"no private keys in {keys_dir}; run 'sentinel keygen' first")
    return FileEd25519Signer(privs[-1])


def cmd_sign(args) -> int:
    from .bundle.bundle import PolicyBundle
    from .manifest_io import load as _manifest_load

    manifest = _manifest_load(args.manifest)
    bundle = PolicyBundle.build(manifest, issued_for=args.issued_for,
                                planner_source=args.source)
    signer = _resolve_signer(_default_keys_dir(), args.key_id)
    bundle.sign(signer)
    out = Path(args.out) if args.out else \
        Path("dist") / f"{bundle.bundle_id}.bundle.json"
    bundle.to_file(out)
    print(green(f"[sentinel] signed bundle {bundle.bundle_id}"))
    print(f"  policy sha256 : {bundle.digest}")
    print(f"  signed by     : {signer.key_id}")
    print(f"  expires_at    : {manifest.expires_at or '-'}")
    print(f"  artifact      : {out}")
    return 0


def cmd_verify(args) -> int:
    from .bundle.bundle import PolicyBundle
    from .bundle.revocation import RevocationList
    from .bundle.signing import AnchorVerifier

    try:
        b = PolicyBundle.from_file(args.bundle)
        keys_dir = Path(args.keys) if args.keys else _default_keys_dir(); b.verify_signature(AnchorVerifier(keys_dir))
    except FileNotFoundError as e:
        print(red(f"[sentinel] VERIFY FAIL: trust anchor missing: {e}")); return 1
    except Exception as e:  # noqa: BLE001
        print(red(f"[sentinel] VERIFY FAIL: {e}")); return 1
    rl = RevocationList(_data_home() / "revocations.jsonl")
    revoked = rl.is_revoked(b.bundle_id, verifier=AnchorVerifier(keys_dir),
                            strict=True)
    temporal = []
    m = b.manifest
    if m.not_before:
        temporal.append(f"not_before={m.not_before}")
    if m.expires_at:
        temporal.append(f"expires_at={m.expires_at}")
    print(green("[sentinel] SIGNATURE VALID"))
    print(f"  bundle_id   : {b.bundle_id}")
    print(f"  policy      : sha256 {b.digest[:16]}...")
    print(f"  epoch       : {b.meta.get('epoch')}")
    print(f"  temporal    : {'; '.join(temporal) or 'no gates'}")
    print(f"  revoked     : {'YES' if revoked else 'no'}")
    return 2 if revoked else 0


def cmd_deploy(args) -> int:
    from .bundle.bundle import PolicyBundle, atomic_write_bundle
    from .bundle.signing import AnchorVerifier

    target = Path(args.deploy_path) if args.deploy_path else \
        (_data_home() / "deployed" / "current.bundle.json")
    b = PolicyBundle.from_file(args.bundle)
    keys_dir = Path(args.keys) if args.keys else _default_keys_dir(); b.verify_signature(AnchorVerifier(keys_dir))
    atomic_write_bundle(b, target)
    print(green(f"[sentinel] deployed {b.bundle_id} -> {target}"))
    print(cyan(f"start the decision point: sentinel pdpd"))
    return 0


def cmd_revoke(args) -> int:
    from .bundle.revocation import RevocationList
    from .bundle.signing import AnchorVerifier

    signer = _resolve_signer(_default_keys_dir(), args.key_id)
    rl = RevocationList(_data_home() / "revocations.jsonl")
    entry = rl.revoke(args.bundle_id, args.reason or "", signer)
    print(green(f"[sentinel] revoked {args.bundle_id} (entry #{len(rl.entries())})"))
    print(f"  reason    : {entry['reason'] or '-'}")
    print(f"  list file : {rl.path}")
    return 0


def cmd_pdpd(args) -> int:
    from .pdp.engine import PDPEngine
    from .pdp.server import PDPServer

    deploy = Path(args.deploy) if args.deploy else \
        (_data_home() / "deployed" / "current.bundle.json")
    evidence = Path(args.evidence) if args.evidence else \
        (_data_home() / "evidence.jsonl")
    engine = PDPEngine(
        deploy_path=deploy,
        keys_dir=Path(args.keys) if args.keys else _default_keys_dir(),
        revocations_path=_data_home() / "revocations.jsonl",
        evidence_path=evidence,
        mode=args.mode,
        signer=_resolve_signer(_default_keys_dir(), None),
    )

    worker = None
    if getattr(args, "enroll", None):
        from .cloud.upstream import EgressWorker
        worker = EgressWorker(
            evidence_path=evidence,
            api_url=args.enroll,
            token=args.enroll_token,
            webhook_url=args.webhook_url,
            webhook_secret=args.webhook_secret,
        )
        thread = worker.run_forever()
        print(f"[sentinel-pdp] enrolled: receipts -> {args.enroll} "
              f"(async, at-least-once)")

    server = PDPServer(engine, port=int(args.port), auth_token=args.token)
    health = engine.health()
    if health["status"] == "fail-closed":
        print(yellow(f"[sentinel-pdp] WARNING fail-closed: "
                     f"{health.get('load_error')}"))
    try:
        server.serve_forever()
    finally:
        pass
    return 0


def cmd_evidence(args) -> int:
    from .bundle.signing import AnchorVerifier
    from .evidence import EvidenceError, EvidenceLedger

    path = Path(args.file) if args.file else (_data_home() / "evidence.jsonl")
    verifier = AnchorVerifier(Path(args.keys) if args.keys else _default_keys_dir()) if not args.skip_sig else None
    try:
        report = EvidenceLedger.verify(path, verifier=verifier)
    except EvidenceError as e:
        print(red(f"[sentinel] EVIDENCE TAMPERED: {e}")); return 1
    except FileNotFoundError as e:
        print(red(str(e))); return 2
    print(green(f"[sentinel] evidence chain INTACT"))
    print(f"  receipts checked : {report['lines_checked']}")
    print(f"  head hash        : {report['head_hash'][:32]}...")
    return 0


def _registry(args) -> "PolicyRegistry":
    from .registry.policies import PolicyRegistry
    return PolicyRegistry(getattr(args, "dir", None))


def cmd_registry_init(args) -> int:
    reg = _registry(args)
    reg.store.init()
    print(green(f"[sentinel] policy registry ready at {reg.store.root}"))
    print(dim("versions = commits; approvals are recorded in state files; "
              "rollback = git revert"))
    return 0


def cmd_policy_register(args) -> int:
    from .registry.policies import TransitionDenied
    reg = _registry(args)
    try:
        info = reg.register(args.file, args.name,
                            author=args.author or os.environ.get("USERNAME", "unknown"),
                            note=args.note or "")
    except TransitionDenied as e:
        print(red(f"[sentinel] {e}")); return 2
    print(green(f"[sentinel] registered {info['name']} v{info['version']} "
                f"(risk {info['risk']}) as draft"))
    print(f"  digest : {info['digest'][:16]}...")
    return 0


def cmd_policy_list(args) -> int:
    reg = _registry(args)
    rows = reg.list_workflows()
    if not rows:
        print(dim("no policies registered")); return 0
    print(f"{'WORKFLOW':<28} {'VERSIONS':>8} {'LATEST':>7} "
          f"{'STATE':<10} {'RISK':<9}")
    for r in rows:
        print(f"{r['name']:<28} {r['versions']:>8} {r['latest']:>7} "
              f"{str(r['latest_state']):<10} {str(r['latest_risk']).upper():<9}")
    return 0


def cmd_policy_show(args) -> int:
    reg = _registry(args)
    version = args.version
    if version is None:
        meta = reg._load_json(reg._meta_path(args.name))
        if not meta:
            print(red(f"unknown workflow {args.name}")); return 2
        version = meta["versions"][-1]["version"]
    m = reg.load_version(args.name, version)
    st = reg.state(args.name, version)
    print(bold(f"{args.name} v{version} - state={st['state']} "
               f"risk={st.get('risk', '?').upper()}"))
    for line in m.summary_lines():
        print(f"  {line}")
    print("  history:")
    for h in st["history"]:
        print(f"    {h['at'][:19]}  ->{h['to']:<10} by {h.get('actor','?')}"
              + (f" [{h['note']}]" if h.get("note") else ""))
    log = reg.store.log(path=reg._manifest_path(args.name, version))
    if log:
        print(f"  git: {log[0]['commit']} {log[0]['subject']}")
    return 0


def cmd_policy_transition(args) -> int:
    from .registry.policies import TransitionDenied
    reg = _registry(args)
    actor = args.actor or os.environ.get("USERNAME", "unknown")
    try:
        st = reg.transition(args.name, int(args.version), args.to_state,
                            actor, note=args.note or "")
    except TransitionDenied as e:
        print(red(f"[sentinel] TRANSITION DENIED: {e}")); return 2
    print(green(f"[sentinel] {args.name} v{args.version}: "
                f"state={st['state']} (by {actor})"))

    # convenience hooks on lifecycle milestones
    if st["state"] == "deployed":
        reg.mark_superseded_if_older(args.name, int(args.version))
    return 0


def cmd_diff(args) -> int:
    from .diffing import diff_manifests, render_report
    from .manifest_io import load as _manifest_load

    justifications = {}
    if args.justified:
        for pair in args.justified:
            if "=" in pair:
                k, v = pair.split("=", 1)
                justifications[k] = v.lower() in ("1", "true", "yes")

    if getattr(args, "name", None):
        reg = _registry(args)
        old = reg.load_version(args.name, int(args.frm))
        new = reg.load_version(args.name, int(args.to))
        title = f"Policy: {args.name} v{args.frm} -> v{args.to}"
    else:
        old = _manifest_load(args.old)
        new = _manifest_load(args.new)
        title = f"Diff: {args.old} -> {args.new}"

    report = diff_manifests(old, new, justifications=justifications)
    print(render_report(report, title=title))
    return 0


def cmd_drift(args) -> int:
    from .drift import detect_drift, render_drift
    from .scanner import scan_profile
    from .core.schema import Manifest
    from .manifest_io import load as _manifest_load

    profile = scan_profile(args.profile)
    manifest = (_manifest_load(args.manifest)
                if Path(args.manifest).exists() else Manifest.from_dict({}))
    report = detect_drift(profile, manifest)
    print(render_drift(report, title=f"DRIFT CHECK - agent '{profile['agent']}'"
                                       f" vs approved authority"))
    return 1 if report.max_severity.value in ("HIGH", "CRITICAL") else 0


def cmd_cloud(args) -> int:
    from .cloud import cli as cloud_cli
    sub = args.cloud_cmd
    fn = {"serve": cloud_cli.cmd_cloud_serve,
          "token": cloud_cli.cmd_cloud_token,
          "push": cloud_cli.cmd_cloud_push,
          "pull": cloud_cli.cmd_deploy_pull,
          "backup": cloud_cli.cmd_cloud_backup,
          "restore": cloud_cli.cmd_cloud_restore}[sub]
    return fn(args)


def cmd_adapters(args) -> int:
    from .adapters.configs import print_config
    return print_config(args.platform)


def cmd_ci_check(args) -> int:
    """One-liner CI gate: semantic diff + attack suite + verdict exit code."""
    from .attack_tests import run_suite
    from .diffing import diff_manifests, render_markdown
    from .manifest_io import load as _manifest_load

    fail_on = args.fail_on
    problems = []

    old = _manifest_load(args.old)
    new = _manifest_load(args.new)
    report = diff_manifests(old, new)
    verdict = report.verdict
    md = render_markdown(report, title="Authority Diff")

    blocking = verdict.startswith("REJECT") or (
        fail_on == "review" and verdict.startswith("REVIEW"))
    suite = None
    if args.run_tests:
        suite = run_suite(new)
        if suite["failed"]:
            problems.append(
                f"adversarial suite failures: {suite['failed']} "
                "(policy mismatch)")

    lines = [md, ""]
    if suite is not None:
        lines.append(f"Adversarial suite: {suite['passed']}/"
                     f"{suite['passed'] + suite['failed']} passed, coverage "
                     f"{suite['coverage']}%  ·  RESULT: {suite['verdict']}")
        lines.append("")
    if problems:
        lines += [f"- {p}" for p in problems]
        lines.append("GATE: FAIL")
        final = "FAIL"
    elif blocking:
        lines.append(f"GATE: FAIL ({verdict})")
        final = f"FAIL ({verdict})"
    else:
        lines.append(f"GATE: PASS ({verdict})")
        final = f"PASS ({verdict})"

    body = "\n".join(lines)
    print(body)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(body + "\n")

    failed = final.startswith("FAIL")
    if failed and args.comment_file:
        Path(args.comment_file).parent.mkdir(parents=True, exist_ok=True)
        Path(args.comment_file).write_text(body, encoding="utf-8")
    elif args.comment_file and Path(args.comment_file).exists() is False:
        Path(args.comment_file).write_text(body, encoding="utf-8")
    return 1 if failed else 0


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel Authority - CI/CD for AI-agent permissions.")
    p.add_argument("--version", action="version", version="sentinel-authority 0.1.0")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="discover current agent reach")
    sp.add_argument("--profile", default="examples/agent_profile.yaml")
    sp.set_defaults(fn=cmd_scan)

    pp = sub.add_parser("plan", help="task -> candidate Authority Manifest")
    pp.add_argument("--task", required=True, help="path to task file OR inline task text")
    pp.add_argument("--out", help="output path (.yaml/.json)", default=None)
    pp.add_argument("--llm", action="store_true",
                    help="propose manifest via OpenRouter GLM (needs OPENROUTER_API_KEY)")
    pp.set_defaults(fn=cmd_plan)

    tp = sub.add_parser("test", help="adversarially attack a manifest")
    tp.add_argument("--manifest", default="authority.yaml")
    tp.set_defaults(fn=cmd_test)

    cp = sub.add_parser("compile", help="export policy target")
    cp.add_argument("--manifest", default="authority.yaml")
    cp.add_argument("--target", required=True, choices=["cedar", "opa", "hooks"])
    cp.add_argument("--out", default=None)
    cp.set_defaults(fn=cmd_compile)

    rp = sub.add_parser("run", help="run a real process under enforced authority")
    rp.add_argument("--manifest", required=True)
    rp.add_argument("cmd", nargs=argparse.REMAINDER, help="e.g. -- python examples/injected_agent.py")
    rp.set_defaults(fn=cmd_run)

    dp = sub.add_parser("doctor", help="one-command posture check")
    dp.add_argument("--profile", default="examples/agent_profile.yaml")
    dp.set_defaults(fn=cmd_doctor)

    vp = sub.add_parser("vectors", help="run conformance vectors against the engine")
    vp.add_argument("--format", choices=["table", "json"], default="table")
    vp.add_argument("--dir", default=None, help="alternative vector directory")
    vp.set_defaults(fn=cmd_vectors)

    mp = sub.add_parser("migrate", help="upgrade a manifest to schema v1.0")
    mp.add_argument("--file", required=True)
    mp.add_argument("--out", default=None)
    mp.set_defaults(fn=cmd_migrate)

    kg = sub.add_parser("keygen", help="generate ed25519 signing keypair")
    kg.add_argument("--out", default=None, help="keys directory")
    kg.set_defaults(fn=cmd_keygen)

    sg = sub.add_parser("sign", help="sign an Authority Manifest into a bundle")
    sg.add_argument("--manifest", required=True)
    sg.add_argument("--out", default=None)
    sg.add_argument("--key-id", default=None)
    sg.add_argument("--issued-for", default=None)
    sg.add_argument("--source", default="rules",
                    choices=["rules", "llm", "human", "template"])
    sg.set_defaults(fn=cmd_sign)

    vf = sub.add_parser("verify", help="verify a bundle against trust anchors")
    vf.add_argument("--bundle", required=True)
    vf.add_argument("--keys", default=None, help="trusted public-key dir")
    vf.set_defaults(fn=cmd_verify)

    dp2 = sub.add_parser("deploy", help="atomically deploy a signed bundle")
    dp2.add_argument("--bundle", required=True)
    dp2.add_argument("--keys", default=None)
    dp2.add_argument("--deploy-path", default=None,
                     help="override active-bundle location")
    dp2.set_defaults(fn=cmd_deploy)

    rv = sub.add_parser("revoke", help="append a signed revocation entry")
    rv.add_argument("--bundle-id", required=True)
    rv.add_argument("--reason", default="")
    rv.add_argument("--key-id", default=None)
    rv.set_defaults(fn=cmd_revoke)

    pp = sub.add_parser("pdpd", help="run the local policy decision point")
    pp.add_argument("--port", type=int, default=7433)
    pp.add_argument("--mode", choices=["enforcing", "advisory"],
                    default="enforcing")
    pp.add_argument("--deploy", default=None, help="active bundle path override")
    pp.add_argument("--keys", default=None)
    pp.add_argument("--evidence", default=None, help="receipt ledger path")
    pp.add_argument("--token", default=None, help="require shared token header")
    pp.add_argument("--enroll", default=None, metavar="URL",
                    help="upload receipts to control plane (async worker)")
    pp.add_argument("--enroll-token", dest="enroll_token", default=None)
    pp.add_argument("--webhook-url", dest="webhook_url", default=None)
    pp.add_argument("--webhook-secret", dest="webhook_secret", default=None)
    pp.set_defaults(fn=cmd_pdpd)

    ev = sub.add_parser("evidence", help="verify the receipt chain")
    ev.add_argument("action", nargs="?", default="verify",
                    choices=["verify"])
    ev.add_argument("--file", default=None)
    ev.add_argument("--keys", default=None)
    ev.add_argument("--skip-sig", action="store_true",
                    help="verify hash chain only (no signature check)")
    ev.set_defaults(fn=cmd_evidence)

    cl = sub.add_parser("cloud", help="control-plane operations (Phase 4)")
    cl_sub = cl.add_subparsers(dest="cloud_cmd", required=True)

    cs = cl_sub.add_parser("serve")
    cs.add_argument("--host", default="127.0.0.1")
    cs.add_argument("--port", type=int, default=7600)
    cs.add_argument("--data-root", default=None)
    cs.add_argument("--issuer", default="https://sentinel.local")
    cs.add_argument("--audience", default="sentinel-cloud")
    cs.add_argument("--jwks", default=None, help="OIDC JWKS URL (production)")
    cs.set_defaults(fn=cmd_cloud)

    ct = cl_sub.add_parser("token", help="mint a dev-mode HS256 token")
    ct.add_argument("--org", required=True)
    ct.add_argument("--sub", required=True)
    ct.add_argument("--role", required=True,
                    choices=["OrgOwner", "SecurityAdmin", "PolicyAuthor",
                             "PolicyApprover", "Developer", "Auditor",
                             "ServiceAccount"])
    ct.add_argument("--ttl", default=3600)
    ct.set_defaults(fn=cmd_cloud)

    cp = cl_sub.add_parser("push", help="upload signed bundle to cloud")
    cp.add_argument("--bundle", required=True)
    cp.add_argument("--workflow", required=True)
    cp.add_argument("--api", required=True)
    cp.add_argument("--token", required=True)
    cp.set_defaults(fn=cmd_cloud)

    cpl = cl_sub.add_parser("pull", help="fetch + anchor-verify + deploy")
    cpl.add_argument("--workflow", required=True)
    cpl.add_argument("--api", required=True)
    cpl.add_argument("--token", required=True)
    cpl.add_argument("--keys", default=None)
    cpl.add_argument("--deploy-path", default=None)
    cpl.set_defaults(fn=cmd_cloud)

    cb = cl_sub.add_parser("backup")
    cb.add_argument("--out", default="backups")
    cb.add_argument("--dir", default=None, help="registry dir override")
    cb.set_defaults(fn=cmd_cloud)

    cr = cl_sub.add_parser("restore")
    cr.add_argument("--archive", required=True)
    cr.add_argument("--into", required=True)
    cr.set_defaults(fn=cmd_cloud)

    ri = sub.add_parser("registry", help="policy registry operations")
    ri_sub = ri.add_subparsers(dest="registry_cmd", required=True)
    rinit = ri_sub.add_parser("init", help="initialize git-backed registry")
    rinit.add_argument("--dir", default=None)
    rinit.set_defaults(fn=cmd_registry_init)

    po = sub.add_parser("policy", help="register/list/show/transition policies")
    po_sub = po.add_subparsers(dest="policy_cmd", required=True)
    preg = po_sub.add_parser("register")
    preg.add_argument("--file", required=True)
    preg.add_argument("--name", required=True)
    preg.add_argument("--author", default=None)
    preg.add_argument("--note", default="")
    preg.add_argument("--dir", default=None)
    preg.set_defaults(fn=cmd_policy_register)
    plist = po_sub.add_parser("list")
    plist.add_argument("--dir", default=None)
    plist.set_defaults(fn=cmd_policy_list)
    pshow = po_sub.add_parser("show")
    pshow.add_argument("--name", required=True)
    pshow.add_argument("--version", type=int, default=None)
    pshow.add_argument("--dir", default=None)
    pshow.set_defaults(fn=cmd_policy_show)
    ptr = po_sub.add_parser("transition")
    ptr.add_argument("--name", required=True)
    ptr.add_argument("--version", required=True)
    ptr.add_argument("--to", dest="to_state", required=True,
                     choices=["draft", "tested", "review", "approved",
                              "signed", "deployed", "superseded", "revoked"])
    ptr.add_argument("--actor", default=None)
    ptr.add_argument("--note", default="")
    ptr.add_argument("--dir", default=None)
    ptr.set_defaults(fn=cmd_policy_transition)

    df = sub.add_parser("diff", help="semantic authority diff")
    df.add_argument("--name", default=None, help="registry workflow name")
    df.add_argument("--frm", dest="frm", default=None, help="from version")
    df.add_argument("--to", default=None, help="to version")
    df.add_argument("--old", default=None, help="standalone: old manifest file")
    df.add_argument("--new", default=None, help="standalone: new manifest file")
    df.add_argument("--justified", nargs="*", default=[],
                    help="'substring=true/false' evidence annotations")
    df.add_argument("--dir", default=None)
    df.set_defaults(fn=cmd_diff)

    dr = sub.add_parser("drift", help="detect effective-authority drift")
    dr.add_argument("--profile", default="examples/agent_profile.yaml")
    dr.add_argument("--manifest", default="authority.yaml")
    dr.set_defaults(fn=cmd_drift)

    ad = sub.add_parser("adapters", help="adapter configuration helpers")
    ad_sub = ad.add_subparsers(dest="adapters_cmd", required=True)
    adpc = ad_sub.add_parser("print-config",
                             help="emit wiring snippet (never edits dotfiles)")
    adpc.add_argument("platform", choices=["claude-code", "cursor", "codex"])
    adpc.set_defaults(fn=cmd_adapters)

    cc = sub.add_parser("ci-check",
                        help="CI gate: semantic diff + tests + verdict exit code")
    cc.add_argument("--old", default=None, help="base manifest file")
    cc.add_argument("--new", default=None, help="candidate manifest file")
    cc.add_argument("--fail-on", choices=["reject", "review"], default="reject")
    cc.add_argument("--run-tests", action="store_true", default=True)
    cc.add_argument("--no-tests", dest="run_tests", action="store_false")
    cc.add_argument("--comment-file", default=None,
                    help="write PR-comment body here when gate fails")
    cc.set_defaults(fn=cmd_ci_check)

    args = p.parse_args(argv)
    if hasattr(args, "cmd") and args.cmd and args.cmd[0] == "--":
        args.cmd = args.cmd[1:]
    try:
        return args.fn(args)
    except FileNotFoundError as e:
        print(red(f"error: {e}"))
        return 2


if __name__ == "__main__":
    sys.exit(main())





