"""Command-line interface for playbookforge."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .attack import base_technique, tactic_name, ATTACK_TACTICS
from .lint import lint, has_errors, SEVERITY_ERROR, SEVERITY_WARNING
from .model import parse_playbook, PlaybookFormatError
from .render import render_markdown, render_json
from .scaffold import new_playbook


def _read_playbook(path: str, prefer_yaml: bool = False):
    if path == "-":
        text = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    if path.endswith((".yml", ".yaml")):
        prefer_yaml = True
    return parse_playbook(text, prefer_yaml=prefer_yaml)


def cmd_render(args: argparse.Namespace) -> int:
    pb = _read_playbook(args.playbook)
    if args.format == "json":
        out = render_json(pb)
    else:
        out = render_markdown(pb)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out if out.endswith("\n") else out + "\n")
    else:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    pb = _read_playbook(args.playbook)
    findings = lint(pb)

    errors = [f for f in findings if f.severity == SEVERITY_ERROR]
    warnings = [f for f in findings if f.severity == SEVERITY_WARNING]

    for f in findings:
        sys.stdout.write(str(f) + "\n")

    summary = f"\n{len(errors)} error(s), {len(warnings)} warning(s)"
    sys.stdout.write(summary + "\n")

    if has_errors(findings):
        return 1
    if warnings and args.strict:
        return 1
    return 0


def cmd_new(args: argparse.Namespace) -> int:
    pb = new_playbook(args.title)
    out = render_json(pb)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        sys.stdout.write(f"wrote starter playbook to {args.output}\n")
    else:
        sys.stdout.write(out + "\n")
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    pb = _read_playbook(args.playbook)
    techniques = pb.all_techniques()

    if args.json:
        payload = {
            "tactics": [
                {"id": t, "name": tactic_name(t)}
                for t in pb.tactics
            ],
            "techniques": [
                {"id": t, "base": base_technique(t), "sub": "." in t}
                for t in techniques
            ],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    sys.stdout.write(f"Playbook: {pb.title}\n\n")
    if pb.tactics:
        sys.stdout.write("Tactics:\n")
        for t in pb.tactics:
            label = tactic_name(t)
            mark = "" if t in ATTACK_TACTICS else "  (unknown)"
            sys.stdout.write(f"  {t}  {label}{mark}\n")
        sys.stdout.write("\n")

    if techniques:
        sys.stdout.write(f"Techniques ({len(techniques)}):\n")
        for t in techniques:
            kind = "sub-technique" if "." in t else "technique"
            sys.stdout.write(f"  {t}  ({kind}, base {base_technique(t)})\n")
    else:
        sys.stdout.write("No techniques referenced.\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="playbookforge",
        description="Incident-response playbook generator and linter "
        "mapped to MITRE ATT&CK.",
    )
    parser.add_argument(
        "--version", action="version", version=f"playbookforge {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_render = sub.add_parser("render", help="render a playbook to Markdown or JSON")
    p_render.add_argument("playbook", help="path to playbook file (or - for stdin)")
    p_render.add_argument(
        "--format", choices=["md", "json"], default="md", help="output format"
    )
    p_render.add_argument("--output", "-o", help="write to a file instead of stdout")
    p_render.set_defaults(func=cmd_render)

    p_lint = sub.add_parser("lint", help="lint a playbook (non-zero exit on errors)")
    p_lint.add_argument("playbook", help="path to playbook file (or - for stdin)")
    p_lint.add_argument(
        "--strict", action="store_true", help="treat warnings as failures too"
    )
    p_lint.set_defaults(func=cmd_lint)

    p_new = sub.add_parser("new", help="scaffold a starter playbook")
    p_new.add_argument("--title", required=True, help="playbook title")
    p_new.add_argument("--output", "-o", help="write to a file instead of stdout")
    p_new.set_defaults(func=cmd_new)

    p_cov = sub.add_parser("coverage", help="list referenced ATT&CK tactics/techniques")
    p_cov.add_argument("playbook", help="path to playbook file (or - for stdin)")
    p_cov.add_argument("--json", action="store_true", help="emit JSON")
    p_cov.set_defaults(func=cmd_coverage)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        sys.stderr.write(f"error: file not found: {exc.filename}\n")
        return 2
    except PlaybookFormatError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
