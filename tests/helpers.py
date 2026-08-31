# -*- coding: utf-8 -*-
"""测试基础设施：stub nuclei 脚本 + 环境隔离辅助。"""
import json
import os
import sys
import tempfile

PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJ)

STUB_SOURCE = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""stub nuclei：模拟真实 nuclei 的可测试行为。
行为由环境变量控制：
  STUB_FINDINGS  : JSON 数组字符串，写入 -jle 指定的 JSONL 文件
  STUB_VALIDATE  : "ok" | "fail" —— 控制 -validate 结果
  STUB_SLEEP     : 秒数，写入前 sleep（用于测试停止）
"""
import sys, os, json, time

args = sys.argv[1:]
out_json, out_txt, validate_path = None, None, None
is_validate = is_tl = is_tgl = False
i = 0
while i < len(args):
    a = args[i]
    if a in ("-jle",) and i + 1 < len(args):
        out_json = args[i + 1]; i += 2; continue
    if a in ("-o",) and i + 1 < len(args):
        out_txt = args[i + 1]; i += 2; continue
    if a == "-validate":
        is_validate = True
    if a == "-tl":
        is_tl = True
    if a == "-tgl":
        is_tgl = True
    if a in ("-t",) and i + 1 < len(args):
        validate_path = args[i + 1]; i += 2; continue
    i += 1

if is_validate:
    if os.environ.get("STUB_VALIDATE", "ok") == "ok":
        print("[INF] Validated %d templates successfully" % (1 if validate_path else 0))
        sys.exit(0)
    else:
        print("[ERR] Error validating template: unknown field 'foo'")
        sys.exit(1)

if is_tl:
    print("http/cves/sample-cve.yaml")
    print("http/exposures/config.yaml")
    print("ssl/detect.yaml")
    sys.exit(0)

if is_tgl:
    print("cve")
    print("tech")
    print("rce")
    sys.exit(0)

sleep = float(os.environ.get("STUB_SLEEP", "0") or 0)
if sleep:
    time.sleep(sleep)

findings = json.loads(os.environ.get("STUB_FINDINGS") or "[]")
if not findings:
    findings = [
        {"template-id": "cve-test", "info": {"name": "Test CVE", "severity": "high",
          "author": ["ngui"], "tags": ["cve"]}, "type": "http",
         "host": "https://example.com", "matched-at": "https://example.com/x",
         "matcher-name": "m1", "timestamp": "2026-01-01T00:00:00Z"},
        {"template-id": "exposure", "info": {"name": "Config", "severity": "medium",
          "author": ["y"], "tags": ["config"]}, "type": "http",
         "host": "http://10.0.0.1:8080", "matched-at": "http://10.0.0.1:8080/c",
         "matcher-name": "m2", "timestamp": "2026-01-01T00:00:01Z"},
    ]
if out_json:
    with open(out_json, "w", encoding="utf-8") as f:
        for x in findings:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")
if out_txt:
    with open(out_txt, "w", encoding="utf-8") as f:
        for x in findings:
            f.write("[%s] %s [%s]\n" % (x["info"]["severity"], x["info"]["name"], x["matched-at"]))
print("[INF] Running templates")
for x in findings:
    print("[%s] %s [%s]" % (x["info"]["severity"].upper()[:3], x["info"]["name"], x["matched-at"]))
sys.exit(0)
'''

DEFAULT_FINDINGS = [
    {"template-id": "cve-test", "info": {"name": "Test CVE", "severity": "high",
      "author": ["ngui"], "tags": ["cve"]}, "type": "http",
     "host": "https://example.com", "matched-at": "https://example.com/x",
     "matcher-name": "m1", "timestamp": "2026-01-01T00:00:00Z"},
    {"template-id": "exposure", "info": {"name": "Config", "severity": "medium",
      "author": ["y"], "tags": ["config"]}, "type": "http",
     "host": "http://10.0.0.1:8080", "matched-at": "http://10.0.0.1:8080/c",
     "matcher-name": "m2", "timestamp": "2026-01-01T00:00:01Z"},
]


def write_stub(tmpdir, source=STUB_SOURCE):
    """写 stub nuclei 脚本到临时目录，返回路径。"""
    p = os.path.join(tmpdir, "stub_nuclei.py")
    with open(p, "w", encoding="utf-8") as f:
        f.write(source)
    return p


def isolate_app(app, tmpdir):
    """把 app 的数据/模板路径重定向到隔离的临时目录，避免污染真实数据。"""
    app.DATA_DIR = os.path.join(tmpdir, "data")
    app.RESULTS_DIR = os.path.join(app.DATA_DIR, "results")
    app.LOGS_DIR = os.path.join(app.DATA_DIR, "logs")
    app.TARGETS_DIR = os.path.join(app.DATA_DIR, "targets")
    app.CONFIG_FILE = os.path.join(app.DATA_DIR, "config.json")
    app.SCANS_FILE = os.path.join(app.DATA_DIR, "scans.json")
    app.CUSTOM_TEMPLATES_DIR = os.path.join(tmpdir, "custom_templates")
    app.ensure_dirs()
    return app


def patch_stub_scan(app, stub_path):
    """让 app 用「python stub_nuclei.py」代替真实 nuclei 执行扫描。
    返回原始引用，便于 tearDown 还原。"""
    orig_resolve = app.resolve_nuclei
    orig_build = app.ScanRunner.build_command

    def fake_resolve():
        return sys.executable

    def patched_build(self, exe):
        cmd = orig_build(self, exe)
        return [cmd[0], stub_path] + cmd[1:]

    app.resolve_nuclei = fake_resolve
    app.ScanRunner.build_command = patched_build
    return orig_resolve, orig_build


def restore_scan(app, origs):
    app.resolve_nuclei, app.ScanRunner.build_command = origs
