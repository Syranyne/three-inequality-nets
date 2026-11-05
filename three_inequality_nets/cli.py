# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright 2026 Syranyne

"""命令行：check、run-cases、demo、scan。"""

from __future__ import annotations

import argparse
import os
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Callable

from three_inequality_nets.core.contract import validate as validate_contract
from three_inequality_nets.core.convergence import validate as validate_convergence
from three_inequality_nets.core.ledger import evaluate as evaluate_ledger
from three_inequality_nets.core.receipt import validate as validate_receipt
from three_inequality_nets.core.report import make_result, to_json, to_text
from three_inequality_nets.core.reviewers import FIXTURE_ENV
from three_inequality_nets.demo_run import main as demo_main
from three_inequality_nets.demo_run import project_root
from three_inequality_nets.nets.authority.validator import evaluate as evaluate_authority
from three_inequality_nets.nets.catalog import NETS
from three_inequality_nets.nets.composition.validator import evaluate as evaluate_composition
from three_inequality_nets.nets.learning_claim.validator import evaluate as evaluate_learning
from three_inequality_nets.nets.production.validator import evaluate as evaluate_production
from three_inequality_nets.nets.retrieval.validator import evaluate as evaluate_retrieval

NET_EVALUATORS: dict[str, Callable[[Any, Path], dict[str, Any]]] = {
    "authority": evaluate_authority,
    "composition": evaluate_composition,
    "learning_claim": evaluate_learning,
    "production": evaluate_production,
    "retrieval": evaluate_retrieval,
}


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass


def _emit(text: str) -> None:
    sys.stdout.buffer.write(text.encode("utf-8"))


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _core_result(name: str, passed: bool, findings: list[dict[str, str]]) -> dict[str, Any]:
    reasons = [f"{item.get('code')} {item.get('field')}" for item in findings]
    return make_result(name, "PASS" if passed else "FAIL", None, None, None, reasons)


def check_path(kind: str, path: Path, root: Path) -> dict[str, Any]:
    payload = _load(path)
    if kind == "contract":
        report = validate_contract(payload, root=root)
        return _core_result("contract", report["passed"], report["findings"])
    if kind == "ledger":
        report = evaluate_ledger(payload, root)
        reasons = [f"{item['code']} {item['location']}" for item in report["violations"]]
        return make_result("ledger", "PASS" if report["passed"] else "FAIL", None, None, report["status"], reasons)
    if kind == "receipt":
        report = validate_receipt(payload, root)
        return _core_result("receipt", report["passed"], report["findings"])
    if kind == "convergence":
        report = validate_convergence(payload, root)
        return _core_result("convergence", report["passed"], report["findings"])
    if kind in NET_EVALUATORS:
        return NET_EVALUATORS[kind](payload, root)
    raise ValueError("unknown check target")


def _case_rows(root: Path, net: str | None) -> list[tuple[str, str, str, str, bool]]:
    nets = [net] if net else list(NETS)
    rows: list[tuple[str, str, str, str, bool]] = []
    for name in nets:
        if name not in NET_EVALUATORS:
            raise ValueError("unknown net")
        folder = root / "cases" / name
        for path in sorted(folder.glob("*.input.json")):
            payload = _load(path)
            expect = _load(path.with_name(path.name.replace(".input.json", ".expect.json")))
            result = NET_EVALUATORS[name](payload, root)
            matched = (result["verdict"] == expect["verdict"] and result["broken_link"] == expect["broken_link"]
                       and all(code in result["reasons"] for code in expect.get("required_reasons", [])))
            link = result["broken_link"] or "-"
            rows.append((name, str(payload.get("id")), result["verdict"], link, matched))
    rows.sort(key=lambda item: (item[0], item[1]))
    return rows


def run_cases(root: Path, net: str | None) -> tuple[str, int]:
    rows = _case_rows(root, net)
    lines = [f"{name} {case_id} {verdict} {link}" for name, case_id, verdict, link, _matched in rows]
    matched = all(item[4] for item in rows)
    if not rows:
        return "no cases\n", 2
    text = "\n".join(lines) + "\n"
    return text, (0 if matched else 1)


def _scan(argv: list[str]) -> int:
    script = project_root() / "dev_tools" / "identity_scan.py"
    spec = importlib.util.spec_from_file_location("fournets_identity_scan", script)
    if spec is None or spec.loader is None:
        _emit("scan script missing\n")
        return 2
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return int(module.main(argv))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="three-inequality-nets", description="校验五张网上的主张和证据")
    parser.add_argument("--json", action="store_true", help="只输出确定的 JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="校验一份合同、账本、回执、收敛记录或网主张")
    check.add_argument("kind", choices=["contract", "ledger", "receipt", "convergence", *NETS])
    check.add_argument("file")
    cases = sub.add_parser("run-cases", help="跑用例并对照期望")
    cases.add_argument("net", nargs="?", choices=list(NETS))
    sub.add_parser("demo", help="复现一条合成日志上的当场核对")
    scan = sub.add_parser("scan", help="按词表扫描发布清单")
    scan.add_argument("scan_args", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    raw = list(sys.argv[1:] if argv is None else argv)
    json_mode = "--json" in raw
    raw = [item for item in raw if item != "--json"]
    parser = build_parser()
    args = parser.parse_args(raw)
    args.json = bool(getattr(args, "json", False) or json_mode)
    root = project_root()
    try:
        if args.command == "check":
            result = check_path(args.kind, Path(args.file), root)
            _emit(to_json(result) if args.json else to_text(result))
            if args.kind == "composition" and any(reason.startswith("schema:") for reason in result["reasons"]):
                return 2
            if result["verdict"] == "PASS":
                return 0
            return 1
        if args.command == "run-cases":
            # 仓库自带样例使用名册里的公开测试复核人。
            os.environ[FIXTURE_ENV] = "1"
            text, code = run_cases(root, args.net)
            if args.json:
                payload = []
                for line in text.splitlines():
                    parts = line.split(" ", 3)
                    if len(parts) == 4:
                        payload.append({"broken_link": None if parts[3] == "-" else parts[3], "id": parts[1], "net": parts[0], "verdict": parts[2]})
                _emit(to_json(payload))
            else:
                _emit(text)
            return code
        if args.command == "demo":
            os.environ[FIXTURE_ENV] = "1"
            return demo_main()
        if args.command == "scan":
            return _scan(args.scan_args)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        _emit(f"input_error: {exc.__class__.__name__}\n")
        return 2
    _emit("NOT IMPLEMENTED\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
