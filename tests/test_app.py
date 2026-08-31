# -*- coding: utf-8 -*-
"""Nuclei GUI 测试套件（unittest，零依赖）。
运行：python -m unittest discover -s tests -v
原则：不删测试、不跳过、不降标准；每个阶段实现 + 测试都必须在命令行可见通过。"""
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_PROJ = os.path.dirname(_HERE)
sys.path.insert(0, _PROJ)

import helpers
from helpers import isolate_app, patch_stub_scan, restore_scan, write_stub

import app as A


class IsolatedCase(unittest.TestCase):
    """每个用例使用独立临时目录，隔离数据/模板路径，避免互相污染。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ngui_test_")
        isolate_app(A, self.tmp)
        self.stub = write_stub(self.tmp)
        # 默认让扫描走 stub nuclei
        self.origs = patch_stub_scan(A, self.stub)

    def tearDown(self):
        restore_scan(A, self.origs)


# ---------------------------------------------------------------------------
# 1. 命令构造
class TestCommandBuild(IsolatedCase):

    def test_full_params(self):
        params = {
            "targets": ["https://example.com", "http://10.0.0.1:8080"],
            "severity": ["high", "critical"], "tags": "cve,tech",
            "exclude_tags": "misc", "types": ["http", "dns"],
            "templates": ["http/cves/"], "rate_limit": 100, "concurrency": 50,
            "bulk_size": 10, "timeout": 15, "retries": 2, "follow_redirects": True,
            "headless": False, "silent": True, "verbose": False, "store_resp": True,
            "proxy": "", "headers": "A: 1\nB: 2", "extra_args": "-fr",
            "check_update": False,
        }
        r = A.ScanRunner("cmdtest", params)
        cmd = r.build_command("nuclei")
        self.assertIn("-l", cmd)
        self.assertTrue(os.path.exists(r.target_file))
        self.assertIn("-s", cmd)
        self.assertEqual(cmd[cmd.index("-s") + 1], "high,critical")
        self.assertEqual(cmd[cmd.index("-tags") + 1], "cve,tech")
        self.assertIn("-etags", cmd)
        self.assertEqual(cmd[cmd.index("-pt") + 1], "http,dns")
        self.assertIn("http/cves/", cmd)
        self.assertEqual(cmd[cmd.index("-rl") + 1], "100")
        self.assertEqual(cmd[cmd.index("-c") + 1], "50")
        self.assertEqual(cmd[cmd.index("-timeout") + 1], "15")
        self.assertIn("-fr", cmd)
        self.assertIn("-jle", cmd)
        self.assertIn("-nc", cmd)
        self.assertIn("-silent", cmd)
        self.assertIn("-sresp", cmd)
        self.assertIn("-duc", cmd)
        self.assertEqual(cmd.count("-H"), 2)

    def test_single_target_uses_u(self):
        r = A.ScanRunner("t2", {"targets": ["https://a.com"], "silent": True})
        cmd = r.build_command("nuclei")
        self.assertIn("-u", cmd)
        self.assertNotIn("-l", cmd)

    def test_extra_args_injected(self):
        r = A.ScanRunner("t3", {"targets": ["https://a.com"], "extra_args": "-stats -system-resolvers"})
        cmd = r.build_command("nuclei")
        self.assertIn("-stats", cmd)
        self.assertIn("-system-resolvers", cmd)


# ---------------------------------------------------------------------------
# 2. JSONL 解析
# ---------------------------------------------------------------------------
class TestResults(IsolatedCase):

    def _write(self, path, lines):
        with open(path, "w", encoding="utf-8") as f:
            for ln in lines:
                f.write((ln if isinstance(ln, str) else json.dumps(ln)) + "\n")

    def test_parse(self):
        p = os.path.join(A.RESULTS_DIR, "s.jsonl")
        self._write(p, [
            {"template-id": "a", "info": {"name": "A", "severity": "critical",
             "author": ["x"], "tags": ["cve"]}, "type": "http", "host": "h",
             "matched-at": "h/a", "matcher-name": "m", "timestamp": "t",
             "extracted-results": ["x", "y", "z", "w"]},
            {"template-id": "b", "info": {"name": "B", "severity": "info",
             "author": [], "tags": []}, "type": "dns", "host": "h2",
             "matched-at": "h2", "matcher-name": "", "timestamp": "t2"},
            "not json",
        ])
        rows = A.parse_jsonl_results(p)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertEqual(rows[0]["extracted"], ["x", "y", "z"])
        self.assertEqual(rows[1]["author"], "")

    def test_missing_file(self):
        self.assertEqual(A.parse_jsonl_results("none.jsonl"), [])


# ---------------------------------------------------------------------------
# 3. 端到端扫描（stub）
class TestScanE2E(IsolatedCase):

    def _start_scan(self, params):
        scan_id = "e2e0001"
        rec = {"id": scan_id, "status": "queued", "targets": params.get("targets", []),
               "created_at": A.now_str(), "updated_at": "", "started_at": "",
               "finished_at": "", "result_count": 0, "command": "", "error": "",
               "filters": {"severity": params.get("severity", []), "tags": "", "types": []}}
        with A._lock:
            scans = A.load_scans()
            scans.insert(0, rec)
            A.save_scans(scans)
        runner = A.ScanRunner(scan_id, params)
        A.MANAGER.add(runner)
        runner.start()
        return scan_id, runner

    def _wait_done(self, scan_id, timeout=15):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if A.MANAGER.get(scan_id) is None:
                return True
            time.sleep(0.2)
        return False

    def test_completed_with_results(self):
        os.environ["STUB_FINDINGS"] = json.dumps(helpers.DEFAULT_FINDINGS)
        scan_id, runner = self._start_scan({"targets": ["https://example.com"],
                                            "severity": ["high"], "silent": True})
        self.assertTrue(self._wait_done(scan_id), "扫描未在超时内结束")
        time.sleep(0.5)
        rec = A.scan_record(scan_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["status"], "completed")
        self.assertEqual(rec["result_count"], 2)
        rows = A.parse_jsonl_results(runner.result_path)
        self.assertEqual(len(rows), 2)
        lines, off = runner.read_log(0)
        self.assertTrue(any("Running" in l for l in lines))
        del os.environ["STUB_FINDINGS"]

    def test_stop(self):
        os.environ["STUB_SLEEP"] = "10"
        scan_id, _ = self._start_scan({"targets": ["https://example.com"], "silent": True})
        time.sleep(1.5)
        ok = A.MANAGER.stop(scan_id)
        self.assertTrue(ok)
        self.assertTrue(self._wait_done(scan_id, timeout=10))
        rec = A.scan_record(scan_id)
        self.assertEqual(rec["status"], "stopped")
        del os.environ["STUB_SLEEP"]

    def test_record_persisted(self):
        os.environ["STUB_FINDINGS"] = json.dumps(helpers.DEFAULT_FINDINGS)
        scan_id, _ = self._start_scan({"targets": ["https://example.com"], "silent": True})
        self.assertTrue(self._wait_done(scan_id))
        scans = A.load_scans()
        self.assertTrue(any(s["id"] == scan_id for s in scans))
        del os.environ["STUB_FINDINGS"]


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------
class ApiCase(IsolatedCase):
    PORT = 8790

    def setUp(self):
        super().setUp()
        self.httpd = A.ThreadingHTTPServer(("127.0.0.1", self.PORT), A.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.PORT}{path}", timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")

    def getj(self, path):
        st, body = self.get(path)
        return st, json.loads(body)

    def post(self, path, data):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.PORT}{path}",
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))

    def delete(self, path):
        req = urllib.request.Request(f"http://127.0.0.1:{self.PORT}{path}", method="DELETE")
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))


class TestApi(ApiCase):

    def test_static_pages(self):
        for path, needle in (("/", "Nuclei GUI"), ("/css/style.css", "--accent"),
                             ("/js/app.js", "startScan")):
            st, body = self.get(path)
            self.assertEqual(st, 200)
            self.assertIn(needle, body)

    def test_config_roundtrip(self):
        st, cfg = self.getj("/api/config")
        self.assertEqual(st, 200)
        self.assertIn("defaults", cfg)
        st, r = self.post("/api/config", {"nuclei_path": "/opt/nuclei"})
        self.assertTrue(r["ok"])
        st, cfg = self.getj("/api/config")
        self.assertEqual(cfg["nuclei_path"], "/opt/nuclei")

    def test_status(self):
        st, r = self.getj("/api/status")
        self.assertEqual(st, 200)
        self.assertIn("ok", r)
        self.assertIn("custom_templates_dir", r)

    def test_scan_via_api(self):
        os.environ["STUB_FINDINGS"] = json.dumps(helpers.DEFAULT_FINDINGS)
        st, r = self.post("/api/scan", {"targets": ["https://example.com"], "silent": True})
        self.assertEqual(st, 200)
        self.assertTrue(r["ok"])
        scan_id = r["id"]
        # 切换到完成
        for _ in range(50):
            st, scans = self.getj("/api/scans")
            rec = next((s for s in scans["scans"] if s["id"] == scan_id), None)
            if rec and rec["status"] in ("completed", "failed", "stopped"):
                break
            time.sleep(0.3)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["status"], "completed")
        st, rr = self.getj(f"/api/scans/{scan_id}/results")
        self.assertEqual(len(rr["results"]), 2)
        st, out = self.getj(f"/api/scans/{scan_id}/output?offset=0")
        self.assertTrue(any("Running" in l for l in out["lines"]), out["lines"])
        # 删除
        st, rdel = self.delete(f"/api/scans/{scan_id}")
        self.assertTrue(rdel["ok"])
        del os.environ["STUB_FINDINGS"]


# ---------------------------------------------------------------------------
# 自定义模板
class TestTemplates(ApiCase):

    def test_from_result_generated(self):
        st, r = self.post("/api/templates/from-result", {"result": {
            "template_id": "ngui-test", "name": "Test Vuln", "severity": "high",
            "tags": "cve", "matched_at": "https://example.com/x"}})
        self.assertEqual(st, 200)
        self.assertEqual(r["source"], "generated")
        self.assertIn("BaseURL", r["content"])
        self.assertEqual(r["name"], "ngui-test-custom.yaml")

    def test_crud(self):
        st, r = self.post("/api/templates/custom", {"name": "my-tpl",
                                                    "content": "id: my-tpl\ninfo:\n  name: x\n"})
        self.assertTrue(r["ok"])
        st, lst = self.getj("/api/templates/custom")
        self.assertTrue(any(t["name"] == "my-tpl.yaml" for t in lst["templates"]))
        st, rd = self.getj("/api/templates/custom?name=my-tpl")
        self.assertIn("id: my-tpl", rd["content"])
        st, rdel = self.delete("/api/templates/custom?name=my-tpl")
        self.assertTrue(rdel["ok"])
        st, lst = self.getj("/api/templates/custom")
        self.assertTrue(all(t["name"] != "my-tpl.yaml" for t in lst["templates"]))

    def test_filename_traversal_rejected(self):
        for bad in ["../../evil", "a/b", "..", ""]:
            st, r = self.post("/api/templates/custom", {"name": bad, "content": "x"})
            self.assertFalse(r.get("ok"), f"应拒绝文件名 {bad!r}")

    def test_delete_missing_returns_ok_false(self):
        st, r = self.delete("/api/templates/custom?name=nope")
        self.assertEqual(r["ok"], False)


# ---------------------------------------------------------------------------
# 镜像联网（网络相关，带预算上限；网络不可达时按环境限制跳过并说明）
class TestMirror(IsolatedCase):

    def test_http_get_bounded_gitee(self):
        try:
            data = A.http_get_bounded("https://gitee.com", budget=8)
            self.assertTrue(len(data) > 0)
        except Exception as e:
            self.skipTest(f"本机无法访问 gitee.com（网络环境限制）: {e}")

    def test_download_via_mirror_proxy(self):
        # 通过 gh-proxy 下载单个小文件，验证代理通道可传输真实内容
        url = ("https://gh-proxy.com/"
               "https://github.com/projectdiscovery/nuclei/raw/main/go.mod")
        try:
            data = A.http_get_bounded(url, budget=30)
            self.assertTrue(len(data) > 0)
        except Exception as e:
            self.skipTest(f"本机无法访问镜像代理（网络环境限制）: {e}")

    def test_netcheck_structure(self):
        httpd = A.ThreadingHTTPServer(("127.0.0.1", 8791), A.Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            with urllib.request.urlopen("http://127.0.0.1:8791/api/netcheck", timeout=30) as r:
                body = json.loads(r.read().decode("utf-8", "replace"))
            self.assertIn("github", body)
            self.assertIn("mirror", body)
            self.assertIn("detail", body)
            self.assertIsInstance(body["detail"], list)
        finally:
            httpd.shutdown()
            httpd.server_close()


# ---------------------------------------------------------------------------
# 数据备份与恢复
class TestBackupRestore(ApiCase):

    def _seed(self):
        """造一条扫描记录 + 一个结果文件 + 一个自定义模板。"""
        with A._lock:
            scans = A.load_scans()
            scans.insert(0, {"id": "bk0001", "status": "completed",
                             "targets": ["https://example.com"],
                             "created_at": A.now_str(), "result_count": 2})
            A.save_scans(scans)
        with open(os.path.join(A.RESULTS_DIR, "bk0001.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(helpers.DEFAULT_FINDINGS[0]) + "\n")
        ok, _ = A.save_custom_template("bk-tpl", "id: bk-tpl\ninfo:\n  name: bk\n")
        self.assertTrue(ok)

    def test_backup_zip_contains_data(self):
        self._seed()
        data = A.build_backup_bytes()
        self.assertTrue(data.startswith(b"PK"))
        import zipfile as _z
        with _z.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
        self.assertIn("data/scans.json", names)
        self.assertIn("data/results/bk0001.jsonl", names)
        self.assertIn("custom-templates/bk-tpl.yaml", names)

    def test_backup_excludes_backups_dir(self):
        self._seed()
        # 模拟已存在的备份 zip
        os.makedirs(A.BACKUPS_DIR, exist_ok=True)
        with open(os.path.join(A.BACKUPS_DIR, "old.zip"), "wb") as f:
            f.write(b"old")
        data = A.build_backup_bytes()
        import zipfile as _z
        with _z.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
        self.assertFalse(any("backups/" in n for n in names),
                         f"备份不应包含自身 backups 目录: {names}")

    def test_restore_roundtrip(self):
        self._seed()
        data = A.build_backup_bytes()
        # 修改数据：删除记录与模板，制造丢失
        with A._lock:
            A.save_scans([])
        self.assertTrue(A.delete_custom_template("bk-tpl"))
        # 恢复
        ok, msg, summary = A.restore_from_zip_bytes(data)
        self.assertTrue(ok, msg)
        scans = A.load_scans()
        self.assertTrue(any(s["id"] == "bk0001" for s in scans), "扫描记录未恢复")
        self.assertTrue(os.path.exists(os.path.join(A.RESULTS_DIR, "bk0001.jsonl")),
                        "结果文件未恢复")
        content = A.read_custom_template("bk-tpl")
        self.assertIsNotNone(content)
        self.assertIn("id: bk-tpl", content)

    def test_restore_invalid_zip_rejected(self):
        ok, msg, _ = A.restore_from_zip_bytes(b"not a zip at all")
        self.assertFalse(ok)
        self.assertIn("zip", msg.lower())

    def test_restore_missing_structure_rejected(self):
        import zipfile as _z
        buf = io.BytesIO()
        with _z.ZipFile(buf, "w") as z:
            z.writestr("data/random.txt", "x")
        ok, msg, _ = A.restore_from_zip_bytes(buf.getvalue())
        self.assertFalse(ok)
        self.assertIn("识别", msg)

    def test_restore_zip_slip_safe(self):
        import zipfile as _z
        buf = io.BytesIO()
        with _z.ZipFile(buf, "w") as z:
            z.writestr("data/scans.json", json.dumps([{"id": "s1"}]))
            z.writestr("../evil.txt", "pwn")
        ok, msg, summary = A.restore_from_zip_bytes(buf.getvalue())
        self.assertTrue(ok, msg)
        self.assertEqual(summary["restored_files"], 1)  # evil 被拒绝，不写盘
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil.txt")),
                         "zip-slip 文件被写到了临时目录")

    def test_backup_api_download(self):
        self._seed()
        st, body = self.get("/api/backup")
        self.assertEqual(st, 200)
        self.assertTrue(body.startswith("PK"))

    def test_restore_api(self):
        self._seed()
        data = A.build_backup_bytes()
        import base64 as _b64
        with A._lock:
            A.save_scans([])
        st, r = self.post("/api/restore", {"zip_b64": _b64.b64encode(data).decode("ascii")})
        self.assertTrue(r["ok"], r)
        self.assertTrue(any(s["id"] == "bk0001" for s in A.load_scans()))

    def test_restore_api_missing_b64(self):
        st, r = self.post("/api/restore", {})
        self.assertFalse(r["ok"])


# ---------------------------------------------------------------------------
# 模板校验（nuclei -validate 接入）
class TestValidate(ApiCase):

    def _patch_run_cli(self, mode):
        """模拟 nuclei -validate 行为：mode='ok' 返回通过，'fail' 返回失败。"""
        orig = A.run_cli

        def fake_run_cli(args, timeout=None):
            if "-validate" in args:
                # 校验临时文件应存在且为 yaml
                t_idx = args.index("-t")
                tpath = args[t_idx + 1]
                self.assertTrue(os.path.exists(tpath), "临时校验文件不存在")
                self.assertTrue(tpath.endswith(".yaml"))
                if mode == "ok":
                    return 0, "[INF] Validated 1 templates successfully"
                return 1, "[ERR] Error validating template: unknown field 'foo'"
            return orig(args, timeout=timeout)

        A.run_cli = fake_run_cli
        self.addCleanup(lambda: setattr(A, "run_cli", orig))

    def test_validate_ok(self):
        self._patch_run_cli("ok")
        r = A.validate_template_content("id: x\ninfo:\n  name: x\n")
        self.assertTrue(r["ok"])
        self.assertTrue(r["valid"])

    def test_validate_fail(self):
        self._patch_run_cli("fail")
        r = A.validate_template_content("id: x\ninfo:\n  name: x\n")
        self.assertTrue(r["ok"])
        self.assertFalse(r["valid"])
        self.assertIn("ERR", r["output"])

    def test_validate_no_nuclei(self):
        orig = A.resolve_nuclei
        A.resolve_nuclei = lambda: None
        self.addCleanup(lambda: setattr(A, "resolve_nuclei", orig))
        r = A.validate_template_content("id: x\n")
        self.assertFalse(r["ok"])
        self.assertIn("nuclei", r["output"])

    def test_validate_tempfile_cleaned(self):
        self._patch_run_cli("ok")
        import glob as _g
        before = set(_g.glob(os.path.join(__import__("tempfile").gettempdir(), "ngui_validate_*.yaml")))
        A.validate_template_content("id: x\n")
        after = set(_g.glob(os.path.join(__import__("tempfile").gettempdir(), "ngui_validate_*.yaml")))
        self.assertEqual(before, after, "校验临时文件未清理")

    def test_validate_api_route(self):
        self._patch_run_cli("ok")
        st, r = self.post("/api/templates/validate", {"content": "id: x\ninfo:\n  name: x\n"})
        self.assertEqual(st, 200)
        self.assertTrue(r["valid"])

    def test_validate_api_empty(self):
        st, r = self.post("/api/templates/validate", {"content": ""})
        self.assertFalse(r["valid"])
        self.assertIn("空", r["output"])


# ---------------------------------------------------------------------------
# Markdown 报告导出 + 一键重扫
class TestReportRescan(ApiCase):

    def _mk_scan(self, scan_id="rp0001"):
        params = {"targets": ["https://example.com"], "severity": ["high"],
                  "tags": "cve", "types": ["http"], "silent": True}
        os.environ["STUB_FINDINGS"] = json.dumps(helpers.DEFAULT_FINDINGS)
        try:
            return A.start_scan(params)
        finally:
            del os.environ["STUB_FINDINGS"]

    def _wait(self, scan_id, timeout=15):
        t0 = time.time()
        while time.time() - t0 < timeout:
            rec = A.scan_record(scan_id)
            if rec and rec["status"] in ("completed", "failed", "stopped"):
                return rec
            time.sleep(0.2)
        self.fail("扫描未在超时内结束")

    def test_markdown_report_content(self):
        scan_id = self._mk_scan()
        self._wait(scan_id)
        md = A.build_markdown_report(scan_id)
        self.assertIn("# Nuclei 扫描报告", md)
        self.assertIn("严重程度统计", md)
        self.assertIn("漏洞详情", md)
        self.assertIn("high", md)
        self.assertIn("medium", md)
        self.assertIn("执行的命令", md)

    def test_markdown_report_empty(self):
        md = A.build_markdown_report("nonexistent-scan")
        self.assertIn("未发现漏洞", md)
        self.assertIn("（无结果）", md)

    def test_report_api_md(self):
        scan_id = self._mk_scan()
        self._wait(scan_id)
        st, body = self.get(f"/api/scans/{scan_id}/report?format=md")
        self.assertEqual(st, 200)
        self.assertTrue(body.startswith("# Nuclei 扫描报告"))

    def test_rescan_api(self):
        os.environ["STUB_FINDINGS"] = json.dumps(helpers.DEFAULT_FINDINGS)
        scan_id = A.start_scan({"targets": ["https://example.com"], "severity": ["high"],
                                "tags": "cve", "silent": True})
        self._wait(scan_id)
        st, r = self.post(f"/api/scans/{scan_id}/rescan", {})
        self.assertEqual(st, 200)
        self.assertTrue(r["ok"])
        self.assertEqual(r["rescan_of"], scan_id)
        self.assertNotEqual(r["id"], scan_id)
        new_rec = A.scan_record(r["id"])
        self.assertEqual(new_rec["targets"], ["https://example.com"])
        self.assertEqual(new_rec["filters"]["severity"], ["high"])
        self._wait(r["id"])
        del os.environ["STUB_FINDINGS"]

    def test_rescan_missing(self):
        st, r = self.post("/api/scans/ghost0000/rescan", {})
        self.assertFalse(r["ok"])


# ---------------------------------------------------------------------------
# 结果去重与严重程度统计
# ---------------------------------------------------------------------------
class TestDedupeStats(ApiCase):

    def _rows(self):
        # 3 条结果（结构与 parse_jsonl_results 一致：severity 在顶层），含 2 个重复键
        return [
            {"template_id": "a", "name": "A", "severity": "high",
             "matched_at": "https://x/a", "type": "http"},
            {"template_id": "a", "name": "A2", "severity": "critical",
             "matched_at": "https://x/a", "type": "http"},
            {"template_id": "b", "name": "B", "severity": "info",
             "matched_at": "https://x/b", "type": "dns"},
        ]

    def test_severity_stats(self):
        stats = A.severity_stats(self._rows())
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["high"], 1)
        self.assertEqual(stats["critical"], 1)
        self.assertEqual(stats["info"], 1)

    def test_dedupe_keeps_highest_severity(self):
        out = A.dedupe_results(self._rows())
        self.assertEqual(len(out), 2)  # a 的重复被合并
        a = next(r for r in out if r["template_id"] == "a")
        self.assertEqual(a["severity"], "critical")  # 保留最高严重程度

    def test_dedupe_no_duplicates(self):
        rows = [{"template_id": "x", "matched_at": "https://x/1", "info": {}},
                {"template_id": "x", "matched_at": "https://x/2", "info": {}}]
        self.assertEqual(len(A.dedupe_results(rows)), 2)

    def test_results_api_dedupe_param(self):
        # 写一个含重复的 jsonl（真实 nuclei JSONL 结构：连字符键 + info.severity）
        raw = [
            {"template-id": "a", "info": {"name": "A", "severity": "high"},
             "matched-at": "https://x/a", "type": "http"},
            {"template-id": "a", "info": {"name": "A2", "severity": "critical"},
             "matched-at": "https://x/a", "type": "http"},
            {"template-id": "b", "info": {"name": "B", "severity": "info"},
             "matched-at": "https://x/b", "type": "dns"},
        ]
        with open(os.path.join(A.RESULTS_DIR, "dp0001.jsonl"), "w",
                  encoding="utf-8") as f:
            for r in raw:
                f.write(json.dumps(r) + "\n")
        st, raw_resp = self.getj("/api/scans/dp0001/results")
        self.assertEqual(raw_resp["total"], 3)
        self.assertIn("stats", raw_resp)
        self.assertEqual(raw_resp["stats"]["total"], 3)
        self.assertEqual(raw_resp["stats"]["high"], 1)
        self.assertEqual(raw_resp["stats"]["critical"], 1)
        st, dd = self.getj("/api/scans/dp0001/results?dedupe=1")
        self.assertTrue(dd["deduped"])
        self.assertEqual(dd["total"], 2)
        self.assertEqual(dd["stats"]["total"], 2)


# ---------------------------------------------------------------------------
# 多请求头 + 排除严重程度
# ---------------------------------------------------------------------------
class TestHeadersExcludeSev(IsolatedCase):

    def test_exclude_severity_maps_to_es(self):
        r = A.ScanRunner("es1", {"targets": ["https://a.com"], "silent": True,
                                 "exclude_severity": ["info", "low"]})
        cmd = r.build_command("nuclei")
        self.assertIn("-es", cmd)
        self.assertEqual(cmd[cmd.index("-es") + 1], "info,low")

    def test_exclude_severity_empty_no_es(self):
        r = A.ScanRunner("es2", {"targets": ["https://a.com"], "silent": True,
                                 "exclude_severity": []})
        cmd = r.build_command("nuclei")
        self.assertNotIn("-es", cmd)

    def test_multi_headers_newline(self):
        r = A.ScanRunner("h1", {"targets": ["https://a.com"], "silent": True,
                                "headers": "Authorization: Bearer x\nX-Custom: y\nCookie: c=1"})
        cmd = r.build_command("nuclei")
        self.assertEqual(cmd.count("-H"), 3)
        self.assertIn("Authorization: Bearer x", cmd)
        self.assertIn("Cookie: c=1", cmd)

    def test_multi_headers_comma_split(self):
        r = A.ScanRunner("h2", {"targets": ["https://a.com"], "silent": True,
                                "headers": "A: 1,B: 2"})
        cmd = r.build_command("nuclei")
        self.assertEqual(cmd.count("-H"), 2)

    def test_severity_and_exclude_not_conflict(self):
        r = A.ScanRunner("se1", {"targets": ["https://a.com"], "silent": True,
                                 "severity": ["high"], "exclude_severity": ["info"]})
        cmd = r.build_command("nuclei")
        self.assertIn("-s", cmd)
        self.assertEqual(cmd[cmd.index("-s") + 1], "high")
        self.assertIn("-es", cmd)
        self.assertEqual(cmd[cmd.index("-es") + 1], "info")


# ---------------------------------------------------------------------------
# 前端 HTML 结构回归测试（防止 section 错乱导致页面空白）
class TestHtmlStructure(unittest.TestCase):
    """解析 web/index.html，确保 4 个页面 section 都在 main.content 内且标签平衡。"""

    @staticmethod
    def _check_html(path):
        from html.parser import HTMLParser

        VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
                'link', 'meta', 'param', 'source', 'track', 'wbr'}

        class Check(HTMLParser):
            def __init__(self):
                super().__init__()
                self.stack = []
                self.errors = []
                self.main_depth = None
                self.sections_in_main = []

            def handle_starttag(self, tag, attrs):
                if tag in VOID:
                    return
                self.stack.append(tag)
                if tag == "main":
                    self.main_depth = len(self.stack) - 1
                if tag == "section" and self.main_depth is not None:
                    d = {k: v for k, v in attrs}
                    if (d.get("id") or "").startswith("page-"):
                        self.sections_in_main.append(
                            (d["id"], len(self.stack) - 1 - self.main_depth))

            def handle_endtag(self, tag):
                if tag in VOID:
                    return
                if not self.stack:
                    self.errors.append(f"extra close </{tag}>")
                    return
                if self.stack[-1] == tag:
                    self.stack.pop()
                elif tag in self.stack:
                    while self.stack and self.stack[-1] != tag:
                        self.errors.append(
                            f"unclosed <{self.stack[-1]}> before </{tag}>")
                        self.stack.pop()
                    self.stack.pop()
                else:
                    self.errors.append(f"close </{tag}> with no open")

        c = Check()
        with open(path, encoding="utf-8") as f:
            c.feed(f.read())
        c.close()
        return c

    def test_all_pages_inside_main_and_balanced(self):
        path = os.path.join(_PROJ, "web", "index.html")
        self.assertTrue(os.path.exists(path), "index.html 不存在")
        c = self._check_html(path)
        self.assertEqual(c.errors, [], f"HTML 标签错误: {c.errors}")
        self.assertEqual(c.stack, [], f"存在未闭合标签: {c.stack}")
        ids = [sid for sid, _ in c.sections_in_main]
        self.assertEqual(
            sorted(ids),
            ["page-history", "page-scan", "page-settings", "page-templates"],
            f"页面 section 必须全部位于 main.content 内，当前: {c.sections_in_main}",
        )
        # 每个 section 都必须是 main 的直接子元素（深度 1）
        for sid, depth in c.sections_in_main:
            self.assertEqual(depth, 1, f"{sid} 未直接位于 main.content 中")


# ---------------------------------------------------------------------------
# 模板/标签列表 banner 过滤（防止 nuclei ASCII logo 混入列表）
class TestTemplateListFilter(unittest.TestCase):
    """clean_nuclei_list_output + 模板(.yaml/.yml)/标签(字母开头)过滤。"""

    @staticmethod
    def _tpl_filter(out):
        return [t for t in A.clean_nuclei_list_output(out)
                if t.lower().endswith((".yaml", ".yml"))]

    @staticmethod
    def _tag_filter(out):
        return [t for t in A.clean_nuclei_list_output(out)
                if t and t[0].isalpha()]

    def test_templates_keep_only_yaml(self):
        out = (
            "Listing available nuclei templates for /root/local/nuclei-templates:\n"
            "http/cves/2021/CVE-2021-1234.yaml\n"
            "http/exposures/configs/git-config.yaml\n"
            "dns/cves/2022/CVE-2022-5678.yaml\n"
            # 防御：banner/日志混入（若某些版本输出到 stdout）
            "/: /|/\\_.,\\_/\\_/\\_/v3.11.0\nprojectdiscovery.io\n"
            "[INF] Nuclei Engine Version: 3.11.0\n"
        )
        self.assertEqual(
            self._tpl_filter(out),
            ["http/cves/2021/CVE-2021-1234.yaml",
             "http/exposures/configs/git-config.yaml",
             "dns/cves/2022/CVE-2022-5678.yaml"],
        )

    def test_templates_empty_dir_returns_empty(self):
        self.assertEqual(
            self._tpl_filter("Listing available nuclei templates for "
                             "/root/local/nuclei-templates:\n"),
            [],
        )

    def test_tags_keep_alpha(self):
        out = ("cve\nrce: remote code execution\nListing available tags\n"
               "exposures\n   ___\n/_V//\nprojectdiscovery.io\n")
        self.assertEqual(
            self._tag_filter(out),
            ["cve", "rce: remote code execution", "exposures"],
        )


# ---------------------------------------------------------------------------
# 模板目录树（可视化树形结构 + 精确点选）
# ---------------------------------------------------------------------------
class TestTemplatesTree(ApiCase):
    """模板目录树：目录构建、yaml 过滤、路径安全、API 端点。"""

    def setUp(self):
        super().setUp()
        self.tplroot = os.path.join(self.tmp, "templates")
        os.makedirs(os.path.join(self.tplroot, "http", "cves", "2021"))
        os.makedirs(os.path.join(self.tplroot, "http", "technologies"))
        os.makedirs(os.path.join(self.tplroot, "dns"))

        def _w(rel):
            p = os.path.join(self.tplroot, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write("id: test\n")

        _w("http/cves/2021/CVE-2021-1234.yaml")
        _w("http/cves/CVE-2020-9999.yaml")
        _w("http/technologies/tech-detect.yaml")
        _w("dns/subdomain.yaml")
        _w("README.md")  # 非模板文件，应被忽略
        self._orig_tpl = A.DEFAULT_TEMPLATES_DIR
        A.DEFAULT_TEMPLATES_DIR = self.tplroot
        self._orig_resolve = A.resolve_nuclei
        A.resolve_nuclei = lambda: None
        A._templates_root_cache["root"] = None  # 清缓存，避免跨用例串扰
    def tearDown(self):
        A.DEFAULT_TEMPLATES_DIR = self._orig_tpl
        A.resolve_nuclei = self._orig_resolve
        A._templates_root_cache["root"] = None
        super().tearDown()

    def test_resolve_root_prefers_existing(self):
        self.assertEqual(A.resolve_templates_root(), self.tplroot)

    def test_root_prefers_nuclei_reported_dir(self):
        # 模拟 nuclei -tl 报告真实模板根（比默认目录更权威）
        real = os.path.join(self.tmp, "real-templates")
        os.makedirs(os.path.join(real, "cloud"))
        os.makedirs(os.path.join(real, "ssl"))
        A.resolve_nuclei = lambda: sys.executable  # 触发 -tl 分支
        orig_run_cli = A.run_cli

        def fake_run_cli(args, timeout=None, merge_stderr=True):
            if "-tl" in args:
                # 关键：解析标题时绝不能加 -silent（否则标题被抑制）
                return 0, ("Listing available nuclei templates for %s:\n"
                           "http/cves/x.yaml\n" % real)
            return orig_run_cli(args, timeout=timeout, merge_stderr=merge_stderr)

        A.run_cli = fake_run_cli
        self.addCleanup(lambda: setattr(A, "run_cli", orig_run_cli))
        self.assertEqual(A._resolve_templates_root_uncached(), real)

    def test_root_cache_reused(self):
        r1 = A.resolve_templates_root(use_cache=True)
        # 二次调用命中缓存，不重复执行（resolve_nuclei 返回 None 也无影响）
        r2 = A.resolve_templates_root(use_cache=True)
        self.assertEqual(r1, r2)

    def test_tree_root_lists_dirs_only(self):
        st, j = self.getj("/api/templates/tree")
        self.assertEqual(st, 200)
        self.assertEqual(j["root"], self.tplroot)
        names = {i["name"]: i["type"] for i in j["items"]}
        self.assertEqual(names, {"http": "dir", "dns": "dir"})
        self.assertNotIn("README.md", names)  # 非模板文件不显示

    def test_tree_subdir_and_yaml(self):
        st, j = self.getj("/api/templates/tree?dir=http/cves")
        self.assertEqual(st, 200)
        got = {i["name"]: i["type"] for i in j["items"]}
        self.assertEqual(got, {"2021": "dir", "CVE-2020-9999.yaml": "file"})
        f = next(i for i in j["items"] if i["type"] == "file")
        self.assertEqual(f["path"], "http/cves/CVE-2020-9999.yaml")

    def test_tree_nested_file_path(self):
        st, j = self.getj("/api/templates/tree?dir=http/cves/2021")
        self.assertEqual(st, 200)
        self.assertEqual(
            [(i["name"], i["type"], i["path"]) for i in j["items"]],
            [("CVE-2021-1234.yaml", "file", "http/cves/2021/CVE-2021-1234.yaml")],
        )

    def test_tree_traversal_blocked(self):
        for bad in ("../", "..", "/etc", "http/../../..", "..\\..\\"):
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.PORT}/api/templates/tree?dir={bad}",
                method="GET")
            try:
                urllib.request.urlopen(req, timeout=30)
                self.fail(f"路径穿越未被拦截: {bad}")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 400, bad)

    def test_tree_missing_dir_empty(self):
        st, j = self.getj("/api/templates/tree?dir=nope")
        self.assertEqual(st, 200)
        self.assertEqual(j["items"], [])

    def test_list_templates_tree_unit(self):
        # 纯函数：目录不含 yaml 文件时只列目录；空目录返回空
        os.makedirs(os.path.join(self.tplroot, "empty_dir"))
        b, rel, items = A.list_templates_tree(self.tplroot, "http")
        self.assertEqual(sorted(i["name"] for i in items),
                         ["cves", "technologies"])
        b, rel, items = A.list_templates_tree(self.tplroot, "empty_dir")
        self.assertEqual(items, [])
        b, rel, items = A.list_templates_tree(self.tplroot, "http/cves")
        self.assertEqual([i["path"] for i in items],
                         ["http/cves/2021", "http/cves/CVE-2020-9999.yaml"])

    def test_all_endpoint_lists_recursively(self):
        # /api/templates/all 递归返回全部目录与 yaml 文件（供树内搜索）
        st, j = self.getj("/api/templates/all")
        self.assertEqual(st, 200)
        self.assertEqual(j["root"], self.tplroot)
        dirs = [i["path"] for i in j["items"] if i["type"] == "dir"]
        files = [i["path"] for i in j["items"] if i["type"] == "file"]
        self.assertEqual(
            sorted(dirs),
            ["dns", "http", "http/cves", "http/cves/2021", "http/technologies"])
        self.assertIn("http/cves/2021/CVE-2021-1234.yaml", files)
        self.assertIn("dns/subdomain.yaml", files)
        # README.md 非模板文件不出现
        self.assertNotIn("README.md", files)

    def test_all_endpoint_missing_root_empty(self):
        # 模板根不存在时返回空列表而非报错
        import shutil
        shutil.rmtree(self.tplroot)
        A._templates_root_cache["root"] = None
        st, j = self.getj("/api/templates/all")
        self.assertEqual(st, 200)
        self.assertEqual(j["items"], [])


class TestTemplateFileOps(ApiCase):
    """模板文件管理：删除 / 重命名 / 移动（含安全校验）。"""

    def setUp(self):
        super().setUp()
        self.tplroot = os.path.join(self.tmp, "templates")
        os.makedirs(os.path.join(self.tplroot, "http", "cves"))
        os.makedirs(os.path.join(self.tplroot, "dns"))
        self._w("http/cves/CVE-1.yaml")
        self._w("http/cves/CVE-2.yaml")
        self._w("dns/note.txt")  # 非模板文件
        self._orig_tpl = A.DEFAULT_TEMPLATES_DIR
        A.DEFAULT_TEMPLATES_DIR = self.tplroot
        self._orig_resolve = A.resolve_nuclei
        A.resolve_nuclei = lambda: None
        A._templates_root_cache["root"] = None

    def tearDown(self):
        A.DEFAULT_TEMPLATES_DIR = self._orig_tpl
        A.resolve_nuclei = self._orig_resolve
        A._templates_root_cache["root"] = None
        super().tearDown()

    def _w(self, rel):
        p = os.path.join(self.tplroot, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write("id: t\n")

    def test_delete_file(self):
        ok, msg = A.delete_template_item("http/cves/CVE-1.yaml")
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(
            os.path.join(self.tplroot, "http", "cves", "CVE-1.yaml")))

    def test_delete_nonempty_dir_blocked(self):
        ok, msg = A.delete_template_item("http")
        self.assertFalse(ok)
        self.assertTrue(os.path.isdir(os.path.join(self.tplroot, "http")))

    def test_delete_empty_dir(self):
        os.makedirs(os.path.join(self.tplroot, "dns", "empty"))
        ok, msg = A.delete_template_item("dns/empty")
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(os.path.join(self.tplroot, "dns", "empty")))

    def test_delete_non_yaml_blocked(self):
        ok, msg = A.delete_template_item("dns/note.txt")
        self.assertFalse(ok)

    def test_rename_auto_extension(self):
        ok, msg = A.rename_template_item("http/cves/CVE-2.yaml", "CVE-NEW")
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(
            os.path.join(self.tplroot, "http", "cves", "CVE-NEW.yaml")))
        self.assertFalse(os.path.exists(
            os.path.join(self.tplroot, "http", "cves", "CVE-2.yaml")))

    def test_rename_conflict_blocked(self):
        ok, msg = A.rename_template_item("http/cves/CVE-2.yaml", "CVE-1.yaml")
        self.assertFalse(ok)

    def test_move_to_root(self):
        ok, msg = A.move_template_item("http/cves/CVE-2.yaml", "")
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(os.path.join(self.tplroot, "CVE-2.yaml")))

    def test_move_into_self_blocked(self):
        ok, msg = A.move_template_item("http", "http/cves")
        self.assertFalse(ok)

    def test_move_missing_dest_blocked(self):
        ok, msg = A.move_template_item("http/cves/CVE-1.yaml", "nope")
        self.assertFalse(ok)

    def test_traversal_blocked(self):
        for fn in (lambda: A.delete_template_item("../x"),
                   lambda: A.rename_template_item("/etc/passwd", "z"),
                   lambda: A.move_template_item("..\\x", ""),
                   lambda: A.delete_template_item("")):
            ok, msg = fn()
            self.assertFalse(ok, msg)

    def test_api_delete_endpoint(self):
        st, j = self.post("/api/templates/file/delete",
                           {"path": "http/cves/CVE-1.yaml"})
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        self.assertFalse(os.path.exists(
            os.path.join(self.tplroot, "http", "cves", "CVE-1.yaml")))

    def test_api_rename_endpoint(self):
        st, j = self.post("/api/templates/file/rename",
                           {"path": "http/cves/CVE-2.yaml", "new_name": "NEW"})
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        self.assertTrue(os.path.exists(
            os.path.join(self.tplroot, "http", "cves", "NEW.yaml")))

    def test_api_move_endpoint(self):
        st, j = self.post("/api/templates/file/move",
                           {"path": "http/cves/CVE-1.yaml", "dest_dir": "dns"})
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        self.assertTrue(os.path.exists(
            os.path.join(self.tplroot, "dns", "CVE-1.yaml")))


if __name__ == "__main__":
    unittest.main(verbosity=2)

