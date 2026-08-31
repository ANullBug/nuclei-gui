#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nuclei GUI — 基于 nuclei 命令功能的图形化漏洞扫描工具
======================================================
- 纯 Python 标准库实现，零第三方依赖，跨平台（Kali / Windows / macOS）
- Win11 风格 Web 界面，由浏览器访问
- 数据持久化在应用目录下的 data/ 中（将本目录放在 nuclei 同级，即数据保存在 nuclei 同级目录）
- 重启 / 关闭 / 刷新后，扫描历史、结果、配置均不丢失

运行方式:
    python3 app.py            # 默认端口 8333
    python3 app.py --port 9000
    python3 app.py --no-browser

依赖: nuclei 二进制（可在同目录 / PATH / 设置中指定）
"""

import argparse
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import base64
import uuid
import webbrowser
import zipfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# 路径与常量
# ---------------------------------------------------------------------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(APP_DIR, "web")
DATA_DIR = os.path.join(APP_DIR, "data")
RESULTS_DIR = os.path.join(DATA_DIR, "results")
LOGS_DIR = os.path.join(DATA_DIR, "logs")
TARGETS_DIR = os.path.join(DATA_DIR, "targets")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
SCANS_FILE = os.path.join(DATA_DIR, "scans.json")
BACKUPS_DIR = os.path.join(DATA_DIR, "backups")

SEVERITIES = ["info", "low", "medium", "high", "critical", "unknown"]
PROTOCOLS = ["dns", "file", "http", "headless", "network", "tcp", "ssl",
             "websocket", "whois", "code", "javascript", "workflow"]

DEFAULT_CONFIG = {
    "nuclei_path": "",            # 留空 = 自动检测（同目录 -> PATH）
    "data_dir": DATA_DIR,         # 数据目录（默认在应用目录下 = nuclei 同级）
    "theme": "dark",              # light / dark
    "port": 8333,
    "defaults": {
        "severity": [],
        "tags": "",
        "exclude_tags": "",
        "types": [],
        "rate_limit": 150,
        "concurrency": 25,
        "bulk_size": 25,
        "timeout": 10,
        "retries": 1,
        "follow_redirects": False,
        "headless": False,
        "silent": True,
        "verbose": False,
        "store_resp": False,
        "check_update": True,
        "proxy": "",
        "headers": "",
        "extra_args": "",
    }
}

# ---------------------------------------------------------------------------
# 镜像源（用于国内直连 GitHub 失败时的回退）
# ---------------------------------------------------------------------------
# GitHub 加速代理（依次尝试）
GH_MIRRORS = [
    "https://ghfast.top/",
    "https://ghproxy.net/",
    "https://gh-proxy.com/",
    "https://mirror.ghproxy.com/",
    "https://github.moeyy.xyz/",
]
GITHUB_API = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
GITHUB_TEMPLATES_ZIP = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
GITEE_TEMPLATES_REPO = "https://gitee.com/mirrors/nuclei-templates.git"
GITEE_TEMPLATES_ZIP = "https://gitee.com/mirrors/nuclei-templates/repository/archive/main.zip"
# 模板默认目录（nuclei 自动识别）
DEFAULT_TEMPLATES_DIR = os.path.join(os.path.expanduser("~"), ".local", "nuclei-templates")
# 自定义可复用模板目录（在应用目录下 = nuclei 同级目录）
CUSTOM_TEMPLATES_DIR = os.path.join(APP_DIR, "custom-templates")


def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (NucleiGUI)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def http_get_bounded(url, budget=6):
    """在预算时间内发起 HTTP 请求并返回内容。
    解决 DNS 解析挂起不受 urllib timeout 控制的问题：把请求放进守护线程，
    只等 budget 秒，超时即视为失败。"""
    result = {}

    def _run():
        try:
            result["data"] = http_get(url, timeout=budget)
            result["ok"] = True
        except Exception as e:
            result["err"] = str(e)
            result["ok"] = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=budget)
    if result.get("ok"):
        return result["data"]
    raise RuntimeError(result.get("err") or f"{url} 响应超时（{budget}s）")


def download_with_mirror(original_url, timeout=30):
    """依次尝试：GitHub 加速镜像 -> 直连。返回 (bytes, 实际使用地址)。"""
    urls = []
    if original_url.startswith("https://github.com/") or original_url.startswith("https://api.github.com/"):
        for m in GH_MIRRORS:
            urls.append(m + original_url)
        urls.append(original_url)
    else:
        urls.append(original_url)
    last_err = ""
    for u in urls:
        try:
            return http_get_bounded(u, budget=timeout), u
        except Exception as e:
            last_err = f"{u}: {e}"
    raise RuntimeError("所有下载源均失败。\n" + last_err)


def _run_cmd(cmd, timeout=120):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return -1, "命令不存在: " + " ".join(cmd)
    except subprocess.TimeoutExpired:
        return -2, "执行超时"


def _extract_zip(data, dest):
    """把 zip 字节流解压到 dest，去掉顶层目录。返回文件数。"""
    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        top = None
        for n in zf.namelist():
            parts = n.split("/", 1)
            if len(parts) == 2 and parts[0]:
                top = parts[0]
                break
        for n in zf.namelist():
            if n.endswith("/"):
                continue
            parts = n.split("/", 1)
            rel = parts[1] if (len(parts) == 2 and parts[0] == top) else n
            target = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(n) as srcf, open(target, "wb") as dstf:
                shutil.copyfileobj(srcf, dstf)
            count += 1
    return count


def _move_clone(src, dest):
    """把 git clone 产物移入 dest，清掉 .git（避免嵌套仓库）"""
    for name in os.listdir(src):
        s = os.path.join(src, name)
        d = os.path.join(dest, name)
        if name == ".git":
            shutil.rmtree(s, ignore_errors=True)
            continue
        if os.path.isdir(s):
            if os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)
            shutil.move(s, d)
        else:
            if os.path.exists(d):
                os.remove(d)
            shutil.move(s, d)


def update_templates_from_mirror(templates_dir=None):
    """从镜像下载 nuclei-templates 到本地目录。
    依次尝试：Gitee zip（无需 git，国内最快）-> Gitee git clone -> GitHub 加速代理 zip。
    返回 (ok, message)"""
    dest = templates_dir or DEFAULT_TEMPLATES_DIR
    os.makedirs(dest, exist_ok=True)

    # 方式一：Gitee 仓库 zip 直下（无需 git）
    try:
        data, src = download_with_mirror(GITEE_TEMPLATES_ZIP, timeout=120)
        _extract_zip(data, dest)
        return True, f"Gitee 镜像 zip 下载成功（{src}）"
    except Exception as e:
        gitee_zip_err = str(e)

    # 方式二：Gitee git clone（需要 git）
    if shutil.which("git"):
        tmp = dest + ".tmp-clone"
        try:
            shutil.rmtree(tmp, ignore_errors=True)
            code, out = _run_cmd(["git", "clone", "--depth", "1",
                                  GITEE_TEMPLATES_REPO, tmp], timeout=180)
            if code == 0 and os.path.isdir(tmp):
                _move_clone(tmp, dest)
                shutil.rmtree(tmp, ignore_errors=True)
                return True, "Gitee 镜像 git clone 成功"
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            shutil.rmtree(tmp, ignore_errors=True)

    # 方式三：GitHub 加速代理 zip
    try:
        data, src = download_with_mirror(GITHUB_TEMPLATES_ZIP, timeout=300)
        _extract_zip(data, dest)
        return True, f"GitHub 加速代理下载成功（{src}）"
    except Exception as e:
        return False, (f"镜像下载模板失败:\n  Gitee zip: {gitee_zip_err}\n  "
                       f"GitHub 代理: {e}")


def _platform_asset():
    """返回 nuclei release 资产后缀，如 linux_amd64 / windows_amd64 / darwin_arm64"""
    os_name = "linux"
    if sys.platform.startswith("win"):
        os_name = "windows"
    elif sys.platform == "darwin":
        os_name = "darwin"
    mach = (platform.machine() or "").lower()
    if mach in ("amd64", "x86_64"):
        arch = "amd64"
    elif mach in ("aarch64", "arm64"):
        arch = "arm64"
    elif mach in ("i386", "i686", "x86"):
        arch = "386"
    else:
        arch = "amd64"
    return f"{os_name}_{arch}"


def download_nuclei_from_mirror():
    """从镜像下载最新 nuclei 二进制到应用目录。返回 (ok, message)"""
    suffix = _platform_asset()
    exe_name = "nuclei.exe" if suffix.startswith("windows") else "nuclei"
    try:
        api_data, api_src = download_with_mirror(GITHUB_API, timeout=30)
        latest = json.loads(api_data)
        ver = str(latest.get("tag_name", "v3.0.0")).lstrip("v")
        # 在资产列表中找对应平台资产
        asset_name = None
        for a in latest.get("assets") or []:
            n = a.get("name", "")
            if suffix in n and n.endswith(".zip"):
                asset_name = n
                break
        if not asset_name:
            asset_name = f"nuclei_{ver}_{suffix}.zip"
        url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{ver}/{asset_name}"
        zdata, src = download_with_mirror(url, timeout=300)
        with zipfile.ZipFile(io.BytesIO(zdata)) as zf:
            found = False
            for n in zf.namelist():
                base = os.path.basename(n)
                if base == exe_name:
                    target = os.path.join(APP_DIR, exe_name)
                    with zf.open(n) as srcf, open(target, "wb") as dstf:
                        shutil.copyfileobj(srcf, dstf)
                    if os.name != "nt":
                        os.chmod(target, 0o755)
                    found = True
                    break
            if not found:
                return False, f"压缩包中未找到 {exe_name}"
        return True, f"已从镜像下载 nuclei v{ver} 到 {APP_DIR}"
    except Exception as e:
        return False, f"镜像下载 nuclei 失败: {e}"


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# 数据持久化（线程安全）
# ---------------------------------------------------------------------------
_lock = threading.Lock()


def ensure_dirs():
    for d in (DATA_DIR, RESULTS_DIR, LOGS_DIR, TARGETS_DIR, BACKUPS_DIR):
        os.makedirs(d, exist_ok=True)


def load_json(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default


def save_json(path, data):
    ensure_dirs()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def get_config():
    cfg = load_json(CONFIG_FILE, None)
    if cfg is None:
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))
        save_config(cfg)
    # 合并默认值，防止缺字段
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    for k, v in cfg.items():
        if k == "defaults" and isinstance(v, dict):
            merged["defaults"].update(v)
        else:
            merged[k] = v
    # data_dir 跟随应用目录
    merged["data_dir"] = DATA_DIR
    return merged


def save_config(cfg):
    save_json(CONFIG_FILE, cfg)


def load_scans():
    return load_json(SCANS_FILE, [])


def save_scans(scans):
    save_json(SCANS_FILE, scans)


# ---------------------------------------------------------------------------
# 数据备份与恢复
# ---------------------------------------------------------------------------
def build_backup_bytes():
    """把 data/（排除 backups 自身）与 custom-templates/ 打包为内存 zip bytes。"""
    ensure_dirs()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for root_dir, arc_prefix in ((DATA_DIR, "data"),
                                     (CUSTOM_TEMPLATES_DIR, "custom-templates")):
            if not os.path.isdir(root_dir):
                continue
            for dirpath, dirnames, filenames in os.walk(root_dir):
                if os.path.abspath(dirpath).startswith(os.path.abspath(BACKUPS_DIR)):
                    dirnames[:] = []
                    continue
                for fn in sorted(filenames):
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, root_dir)
                    arc = f"{arc_prefix}/{rel}".replace("\\", "/")
                    z.write(full, arc)
    return buf.getvalue()


def _safe_zip_target(arc, dest_root):
    """把 zip 成员名安全映射到 dest_root 下的绝对路径；非法返回 None（防 zip-slip）。"""
    norm = os.path.normpath(arc.replace("\\", "/"))
    if norm.startswith("..") or os.path.isabs(norm):
        return None
    target = os.path.join(dest_root, norm)
    if not os.path.abspath(target).startswith(os.path.abspath(dest_root)):
        return None
    return target


def restore_from_zip_bytes(data):
    """恢复数据：校验 zip 结构 -> 先备份当前数据 -> 安全解压覆盖。
    返回 (ok, message, restored_summary)。"""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        return False, f"不是有效的 zip 文件: {e}", {}

    names = zf.namelist()
    allowed_prefixes = ("data/", "custom-templates/")
    valid_members = [n for n in names
                     if not n.endswith("/") and n.startswith(allowed_prefixes)]
    # 至少要有 data/scans.json 或 data/config.json 或 custom-templates 下内容
    has_key = any(n in ("data/scans.json", "data/config.json") for n in names)
    has_custom = any(n.startswith("custom-templates/") and not n.endswith("/")
                     for n in names)
    if not valid_members or (not has_key and not has_custom):
        return False, "备份文件缺少可识别的数据（无 data/ 或 custom-templates/）", {}

    # 1) 先备份当前数据，防止恢复失败导致数据丢失
    ensure_dirs()
    pre = os.path.join(BACKUPS_DIR, f"pre-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip")
    try:
        with open(pre, "wb") as f:
            f.write(build_backup_bytes())
    except Exception:
        pre = ""

    # 2) 安全解压覆盖
    restored_files, skipped = 0, []
    for n in valid_members:
        # data/* -> DATA_DIR, custom-templates/* -> CUSTOM_TEMPLATES_DIR
        prefix, rel = n.split("/", 1)
        dest_root = DATA_DIR if prefix == "data" else CUSTOM_TEMPLATES_DIR
        target = _safe_zip_target(rel, dest_root)
        if target is None:
            skipped.append(n)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(n) as srcf, open(target, "wb") as dstf:
            shutil.copyfileobj(srcf, dstf)
        restored_files += 1
    return True, "恢复完成", {"restored_files": restored_files,
                              "skipped": skipped, "pre_backup": pre}


def scan_record(scan_id):
    for s in load_scans():
        if s.get("id") == scan_id:
            return s
    return None


def update_scan(scan_id, **fields):
    with _lock:
        scans = load_scans()
        for s in scans:
            if s.get("id") == scan_id:
                s.update(fields)
                s["updated_at"] = now_str()
                break
        save_scans(scans)


def start_scan(params):
    """创建扫描记录并启动线程，返回 scan_id。params 会整体存入记录以便重扫复用。"""
    scan_id = uuid.uuid4().hex[:12]
    rec = {
        "id": scan_id,
        "status": "queued",
        "targets": params.get("targets") or [],
        "created_at": now_str(),
        "updated_at": now_str(),
        "started_at": "",
        "finished_at": "",
        "result_count": 0,
        "command": "",
        "error": "",
        "filters": {
            "severity": params.get("severity") or [],
            "tags": params.get("tags") or "",
            "types": params.get("types") or [],
        },
        "params": params,
    }
    with _lock:
        scans = load_scans()
        scans.insert(0, rec)
        save_scans(scans)
    runner = ScanRunner(scan_id, params)
    MANAGER.add(runner)
    runner.start()
    return scan_id


# ---------------------------------------------------------------------------
# nuclei 定位与探测
# ---------------------------------------------------------------------------
def resolve_nuclei():
    """按优先级查找 nuclei：配置路径 -> 应用同目录 -> PATH"""
    cfg = get_config()
    candidates = []
    p = (cfg.get("nuclei_path") or "").strip()
    if p:
        candidates.append(p)
    candidates.append(os.path.join(APP_DIR, "nuclei"))
    candidates.append(os.path.join(APP_DIR, "nuclei.exe"))
    # PATH
    found = shutil.which("nuclei")
    if found:
        candidates.append(found)
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def run_cli(args, timeout=None, merge_stderr=True):
    """运行 nuclei 命令，返回 (returncode, stdout_text)。
    merge_stderr=True（默认）合并 stdout+stderr（用于日志/校验等看全貌）；
    列表类命令（-tl/-tgl 等）传 False，只取 stdout，避免 banner/日志混入。"""
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        out = proc.stdout or ""
        if merge_stderr:
            out += proc.stderr or ""
        return proc.returncode, out
    except FileNotFoundError:
        return -1, "未找到 nuclei，请检查路径设置"
    except subprocess.TimeoutExpired:
        return -2, "命令执行超时"


def clean_nuclei_list_output(out):
    """从 nuclei 列表类命令（-tl / -tgl）输出中提取干净条目：
    过滤 banner（ASCII art）、"Listing available..." 标题、[INF] 日志行。"""
    items = []
    for ln in (out or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        low = s.lower()
        if low.startswith("["):
            continue  # [INF] 等日志
        if "listing available" in low:
            continue  # "Listing available nuclei templates for ..." 标题
        if "projectdiscovery.io" in low:
            continue  # banner 底部
        if "nuclei engine version" in low or low.startswith("version:"):
            continue
        # ASCII art banner 行：去掉字母/数字/常见路径符号后，剩余符号占比过高
        solid = re.sub(r"[A-Za-z0-9./\\\-]", "", s)
        if len(s) > 0 and len(solid) / len(s) > 0.5:
            continue
        items.append(s)
    return items


_templates_root_cache = {"root": None, "ts": 0.0}


def _resolve_templates_root_uncached():
    """解析 nuclei 模板根目录（不缓存）：
    1) 优先用 nuclei 真实模板根：`nuclei -tl` 输出的 "Listing available
       nuclei templates for <dir>"（注意：不能加 -silent，否则标题被抑制）
    2) 默认目录 ~/.local/nuclei-templates
    3) 其他常见候选路径（root 环境、Kali 等）
    返回一个已存在的目录；都不可用时回退默认目录。"""
    exe = resolve_nuclei()
    candidates = []
    # 1) nuclei 报告的真实模板根（最权威）
    if exe:
        try:
            code, out = run_cli([exe, "-tl", "-nc", "-duc"],
                                timeout=60, merge_stderr=False)
            if code == 0:
                for ln in (out or "").splitlines():
                    m = re.search(
                        r"Listing available nuclei templates for\s+(.+)", ln, re.I)
                    if m:
                        # 标题形如 "... for <目录>:"，去掉尾部冒号/空白
                        d = m.group(1).strip().rstrip(": \t")
                        if d and os.path.isdir(d):
                            candidates.append(d)
                            break
        except Exception:  # noqa: BLE001
            pass
    # 2) 默认目录
    candidates.append(DEFAULT_TEMPLATES_DIR)
    # 3) 其他常见候选
    candidates += [
        os.path.join(os.path.expanduser("~"), "nuclei-templates"),
        os.path.join(os.path.expanduser("~"), "local", "nuclei-templates"),
        "/root/.local/nuclei-templates",
        "/root/local/nuclei-templates",
        "/root/nuclei-templates",
        "/usr/share/nuclei-templates",
    ]
    seen = set()
    for c in candidates:
        if not c or c in seen:
            continue
        seen.add(c)
        if os.path.isdir(c):
            return c
    return DEFAULT_TEMPLATES_DIR


def resolve_templates_root(use_cache=True):
    """确定 nuclei 模板根目录（带 60s 缓存，避免每次请求都执行 nuclei）。"""
    now = time.time()
    if use_cache and _templates_root_cache["root"] and \
            now - _templates_root_cache["ts"] < 60:
        return _templates_root_cache["root"]
    root = _resolve_templates_root_uncached()
    if use_cache:
        _templates_root_cache["root"] = root
        _templates_root_cache["ts"] = now
    return root


def list_templates_tree(root, rel):
    """列出模板根目录下 rel 相对路径的直接子节点（目录 + yaml 文件）。
    返回 (base_root, rel, items)；rel 非法时返回 (None, None, None)。"""
    base = os.path.realpath(root)
    if rel:
        # 路径安全校验：拒绝绝对路径、..、以及跳出 base 的路径
        if os.path.isabs(rel) or ".." in rel.split("/") or ".." in rel.split("\\"):
            return None, None, None
        target = os.path.realpath(os.path.join(base, rel))
        if not target.startswith(base + os.sep):
            return None, None, None
    else:
        target = base
    if not os.path.isdir(target):
        return base, rel, []
    items = []
    try:
        names = sorted(os.listdir(target))
    except OSError:
        return base, rel, []
    for name in names:
        p = os.path.join(target, name)
        child_rel = (rel + "/" + name) if rel else name
        if os.path.isdir(p):
            items.append({"name": name, "type": "dir", "path": child_rel})
        elif name.lower().endswith((".yaml", ".yml")):
            items.append({"name": name, "type": "file", "path": child_rel})
    return base, rel, items


def safe_template_path(rel):
    """把相对路径映射到模板根下并做穿越校验；非法返回 (None, None)。"""
    root = os.path.realpath(resolve_templates_root())
    if not rel:
        return None, None
    if os.path.isabs(rel) or ".." in rel.split("/") or ".." in rel.split("\\"):
        return None, None
    full = os.path.realpath(os.path.join(root, rel))
    if not full.startswith(root + os.sep):
        return None, None
    return root, full


def delete_template_item(rel):
    """删除模板根下的文件（.yaml/.yml）或空目录。返回 (ok, message)。"""
    root, full = safe_template_path(rel)
    if full is None:
        return False, "非法路径"
    if full == root:
        return False, "不能删除模板根目录"
    if os.path.isdir(full):
        if os.listdir(full):
            return False, "目录非空，请先移出或删除其中内容"
        try:
            os.rmdir(full)
            return True, "已删除目录 " + rel
        except OSError as e:
            return False, "删除失败: " + str(e)
    if os.path.isfile(full):
        if not full.lower().endswith((".yaml", ".yml")):
            return False, "仅允许删除 yaml/yml 模板文件"
        try:
            os.remove(full)
            return True, "已删除 " + rel
        except OSError as e:
            return False, "删除失败: " + str(e)
    return False, "路径不存在"


def rename_template_item(rel, new_name):
    """重命名模板根下的文件/目录（同目录）。返回 (ok, message)。"""
    root, full = safe_template_path(rel)
    if full is None or full == root:
        return False, "非法路径"
    new_name = (new_name or "").strip()
    if not new_name or new_name in (".", "..") or \
            "/" in new_name or "\\" in new_name or "\x00" in new_name:
        return False, "新名称非法（不能含路径分隔符）"
    # 文件自动补 .yaml 扩展名
    if os.path.isfile(full) and not new_name.lower().endswith((".yaml", ".yml")):
        new_name += ".yaml"
    target = os.path.join(os.path.dirname(full), new_name)
    if os.path.exists(target):
        return False, "目标已存在同名项"
    try:
        os.rename(full, target)
        return True, "已重命名为 " + new_name
    except OSError as e:
        return False, "重命名失败: " + str(e)


def move_template_item(rel, dest_dir):
    """把模板根下的文件/目录移动到目标相对目录（空 = 根目录）。返回 (ok, message)。"""
    root, full = safe_template_path(rel)
    if full is None or full == root:
        return False, "非法路径"
    dest_dir = (dest_dir or "").strip()
    if dest_dir:
        _, dest = safe_template_path(dest_dir)
        if dest is None:
            return False, "目标目录非法"
    else:
        dest = root
    if not os.path.isdir(dest):
        return False, "目标目录不存在"
    dest = os.path.realpath(dest)
    if dest == full or dest.startswith(full + os.sep):
        return False, "不能移动到自身或其子目录"
    newp = os.path.join(dest, os.path.basename(full))
    if os.path.exists(newp):
        return False, "目标位置已存在同名项"
    try:
        os.rename(full, newp)
        return True, "已移动到 " + (dest_dir or "根目录")
    except OSError as e:
        return False, "移动失败: " + str(e)


def get_nuclei_status():
    exe = resolve_nuclei()
    if not exe:
        return {"ok": False, "path": "", "version": "", "templates": "",
                "templates_dir": DEFAULT_TEMPLATES_DIR,
                "custom_templates_dir": CUSTOM_TEMPLATES_DIR,
                "error": "未找到 nuclei。请将 nuclei 放到本目录，或安装到 PATH，或在「设置」中指定路径。"
                          "\nKali 安装: sudo apt install nuclei  或  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}
    code, out = run_cli([exe, "-version"])
    version = ""
    templates = ""
    if code == 0:
        for line in out.splitlines():
            m = re.search(r"\[nuclei\]\s*v?([\d.]+)", line)
            if m and not version:
                version = m.group(1)
            m2 = re.search(r"(?:nuclei-templates|templates)\s*[:\-]?\s*v?([\d.]+)", line, re.I)
            if m2 and not templates:
                templates = m2.group(1)
    # 模板版本
    tc, tout = run_cli([exe, "-templates-version"])
    if tc == 0 and not templates:
        templates = tout.strip()
    return {"ok": True, "path": exe, "version": version, "templates": templates,
            "templates_dir": DEFAULT_TEMPLATES_DIR,
            "custom_templates_dir": CUSTOM_TEMPLATES_DIR, "error": ""}


# ---------------------------------------------------------------------------
# 扫描管理
# ---------------------------------------------------------------------------
class ScanManager:
    def __init__(self):
        self._runners = {}      # scan_id -> ScanRunner
        self._lock = threading.Lock()

    def add(self, runner):
        with self._lock:
            self._runners[runner.scan_id] = runner

    def get(self, scan_id):
        with self._lock:
            return self._runners.get(scan_id)

    def remove(self, scan_id):
        with self._lock:
            self._runners.pop(scan_id, None)

    def stop(self, scan_id):
        runner = self.get(scan_id)
        if runner:
            return runner.stop()
        return False


MANAGER = ScanManager()


class ScanRunner(threading.Thread):
    """负责一次 nuclei 扫描：构造命令、启动进程、实时收集输出、解析结果。"""

    def __init__(self, scan_id, params):
        super().__init__(daemon=True)
        self.scan_id = scan_id
        self.params = params
        self.proc = None
        self.stop_flag = threading.Event()
        self.log_path = os.path.join(LOGS_DIR, scan_id + ".log")
        self.result_path = os.path.join(RESULTS_DIR, scan_id + ".jsonl")
        self.target_file = os.path.join(TARGETS_DIR, scan_id + ".txt")
        self.text_out = os.path.join(RESULTS_DIR, scan_id + ".txt")
        self.offset = 0
        self._buf = []          # 日志行缓冲（供实时读取）
        self._buf_lock = threading.Lock()
        self.exit_code = None
        self.error = ""

    # -- 命令构造 ----------------------------------------------------------
    def build_command(self, exe):
        p = self.params
        args = [exe]
        targets = [t.strip() for t in (p.get("targets") or []) if t.strip()]

        # 目标
        if len(targets) == 1:
            args += ["-u", targets[0]]
        elif len(targets) > 1:
            with open(self.target_file, "w", encoding="utf-8") as f:
                f.write("\n".join(targets) + "\n")
            args += ["-l", self.target_file]

        # 模板选择 / 过滤
        sev = [s for s in (p.get("severity") or []) if s]
        if sev:
            args += ["-s", ",".join(sev)]
        esev = [s for s in (p.get("exclude_severity") or []) if s]
        if esev:
            args += ["-es", ",".join(esev)]
        tags = (p.get("tags") or "").strip()
        if tags:
            args += ["-tags", tags]
        etags = (p.get("exclude_tags") or "").strip()
        if etags:
            args += ["-etags", etags]
        types = [t for t in (p.get("types") or []) if t]
        if types:
            args += ["-pt", ",".join(types)]
        templates = [t for t in (p.get("templates") or []) if t.strip()]
        if templates:
            args += ["-t", ",".join(templates)]
        etpl = (p.get("exclude_templates") or "").strip()
        if etpl:
            args += ["-et", etpl]

        # 速率 / 优化
        rl = int(p.get("rate_limit") or 0)
        if rl > 0:
            args += ["-rl", str(rl)]
        cc = int(p.get("concurrency") or 0)
        if cc > 0:
            args += ["-c", str(cc)]
        bs = int(p.get("bulk_size") or 0)
        if bs > 0:
            args += ["-bs", str(bs)]
        to = int(p.get("timeout") or 0)
        if to > 0:
            args += ["-timeout", str(to)]
        rt = int(p.get("retries") or 0)
        if rt >= 0:
            args += ["-retries", str(rt)]
        if p.get("follow_redirects"):
            args += ["-fr"]
        if p.get("headless"):
            args += ["-headless"]
        if p.get("passive"):
            args += ["-passive"]
        proxy = (p.get("proxy") or "").strip()
        if proxy:
            args += ["-proxy", proxy]
        headers = (p.get("headers") or "").strip()
        if headers:
            for h in re.split(r"[\r\n,]", headers):
                h = h.strip()
                if h:
                    args += ["-H", h]

        # 输出
        if not p.get("check_update", True):
            args += ["-duc"]
        args += ["-jle", self.result_path]      # JSONL 结构结果
        args += ["-o", self.text_out]           # 文本结果
        args += ["-nc"]                          # 无 ANSI 颜色
        if p.get("silent"):
            args += ["-silent"]
        if p.get("verbose"):
            args += ["-v"]
        if p.get("store_resp"):
            args += ["-sresp"]

        # 附加原始参数（高级用户）
        extra = (p.get("extra_args") or "").strip()
        if extra:
            args += extra.split()

        return args

    # -- 生命周期 ----------------------------------------------------------
    def run(self):
        exe = resolve_nuclei()
        if not exe:
            self.error = "未找到 nuclei"
            update_scan(self.scan_id, status="failed", error=self.error,
                        finished_at=now_str())
            MANAGER.remove(self.scan_id)
            return
        args = self.build_command(exe)
        cmd_line = " ".join(args)
        update_scan(self.scan_id, status="running", command=cmd_line,
                    started_at=now_str(), result_count=0)
        self._log("$ " + cmd_line)
        try:
            self.proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, encoding="utf-8", errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except Exception as e:
            self.error = f"启动失败: {e}"
            update_scan(self.scan_id, status="failed", error=self.error,
                        finished_at=now_str())
            MANAGER.remove(self.scan_id)
            return

        # 实时读取输出
        assert self.proc.stdout is not None
        lines_since = 0
        for line in iter(self.proc.stdout.readline, ""):
            line = line.rstrip("\n")
            self._log(line)
            lines_since += 1
            # 每 20 行刷新一次实时结果计数（供前端实时显示）
            if lines_since >= 20:
                lines_since = 0
                try:
                    cnt = 0
                    if os.path.exists(self.result_path):
                        with open(self.result_path, "r", encoding="utf-8") as f:
                            cnt = sum(1 for ln in f if ln.strip())
                    update_scan(self.scan_id, result_count=cnt)
                except Exception:
                    pass
            if self.stop_flag.is_set():
                try:
                    self.proc.terminate()
                except Exception:
                    pass
        try:
            self.proc.stdout.close()
        except Exception:
            pass
        self.proc.wait()
        self.exit_code = self.proc.returncode
        self._log(f"[nuclei-gui] 进程退出，返回码: {self.exit_code}")
        if self.stop_flag.is_set():
            status = "stopped"
        elif self.exit_code == 0:
            status = "completed"
        else:
            status = "failed"
            self.error = f"nuclei 退出码 {self.exit_code}，请查看日志"
        # 统计结果
        count = 0
        if os.path.exists(self.result_path):
            try:
                with open(self.result_path, "r", encoding="utf-8") as f:
                    count = sum(1 for ln in f if ln.strip())
            except Exception:
                count = 0
        update_scan(self.scan_id, status=status, result_count=count,
                    error=self.error, finished_at=now_str())
        MANAGER.remove(self.scan_id)

    def _log(self, line):
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        with self._buf_lock:
            self._buf.append(line)
            if len(self._buf) > 20000:
                self._buf = self._buf[-20000:]

    def read_log(self, offset=0):
        with self._buf_lock:
            lines = self._buf[offset:]
            new_offset = offset + len(lines)
        # 若进程刚启动、缓冲未填充，则从文件补齐
        if not lines:
            if os.path.exists(self.log_path):
                try:
                    with open(self.log_path, "r", encoding="utf-8") as f:
                        all_lines = f.read().splitlines()
                    if offset < len(all_lines):
                        lines = all_lines[offset:]
                        new_offset = len(all_lines)
                except Exception:
                    pass
        return lines, new_offset

    def stop(self):
        self.stop_flag.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                # 等待 3 秒，不行再 kill
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            return True
        return False


def parse_jsonl_results(path):
    """把 nuclei JSONL 输出解析成前端表格数据"""
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            info = obj.get("info") or {}
            severity = str(info.get("severity") or "info").lower()
            rows.append({
                "template_id": obj.get("template-id", ""),
                "name": info.get("name", obj.get("template-id", "")),
                "severity": severity,
                "author": ",".join(info.get("author") or []) or "",
                "tags": ",".join(info.get("tags") or []) or "",
                "type": obj.get("type", ""),
                "host": obj.get("host", obj.get("matched-at", "")),
                "matched_at": obj.get("matched-at", ""),
                "matcher": obj.get("matcher-name", ""),
                "timestamp": obj.get("timestamp", ""),
                "extracted": (obj.get("extracted-results") or [])[:3],
                "raw": json.dumps(obj, ensure_ascii=False),
            })
    return rows


SEV_RANK = {"critical": 6, "high": 5, "medium": 4, "low": 3,
            "info": 2, "unknown": 1}


def severity_stats(rows):
    """按严重程度统计结果数量，返回 {severity: count, total: n}。"""
    stats = {sev: 0 for sev in SEV_ORDER}
    for r in rows:
        sev = r.get("severity") or "unknown"
        stats[sev] = stats.get(sev, 0) + 1
    stats["total"] = len(rows)
    return stats


def dedupe_results(rows):
    """按 (template_id, matched_at) 去重，同一漏洞保留严重程度最高的一条。"""
    best = {}
    for r in rows:
        key = (r.get("template_id") or "", r.get("matched_at") or "")
        sev = r.get("severity") or "unknown"
        cur = best.get(key)
        cur_sev = (cur.get("severity") if cur else "") or "unknown"
        if cur is None or SEV_RANK.get(sev, 0) > SEV_RANK.get(cur_sev, 0):
            best[key] = r
    return list(best.values())


SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def build_markdown_report(scan_id):
    """把扫描记录 + 结果转为 Markdown 报告文本。"""
    rec = scan_record(scan_id) or {}
    rows = parse_jsonl_results(os.path.join(RESULTS_DIR, scan_id + ".jsonl"))
    targets = rec.get("targets") or []
    lines = []
    lines.append("# Nuclei 扫描报告")
    lines.append("")
    lines.append(f"- **扫描 ID**: {scan_id}")
    lines.append(f"- **状态**: {rec.get('status', '')}")
    lines.append(f"- **目标**: {', '.join(targets) if targets else '-'}")
    lines.append(f"- **开始时间**: {rec.get('started_at', '')}")
    lines.append(f"- **结束时间**: {rec.get('finished_at', '')}")
    lines.append(f"- **结果总数**: {len(rows)}")
    lines.append("")
    lines.append("## 严重程度统计")
    lines.append("")
    lines.append("| 严重程度 | 数量 |")
    lines.append("| --- | --- |")
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    if not counts:
        lines.append("| （无结果） | 0 |")
    else:
        for sev in SEV_ORDER:
            if counts.get(sev):
                lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")
    lines.append("## 漏洞详情")
    lines.append("")
    if not rows:
        lines.append("未发现漏洞。")
    else:
        for sev in SEV_ORDER:
            group = [r for r in rows if r["severity"] == sev]
            if not group:
                continue
            lines.append(f"### {sev}（{len(group)}）")
            lines.append("")
            lines.append("| # | 模板 | 名称 | 目标 | 匹配器 |")
            lines.append("| --- | --- | --- | --- | --- |")
            for i, r in enumerate(group, 1):
                name = (r["name"] or "").replace("|", "\\|")
                lines.append(f"| {i} | {r['template_id']} | {name} "
                             f"| {r['matched_at']} | {r['matcher']} |")
            lines.append("")
    cmd = rec.get("command") or ""
    if cmd:
        lines.append("## 执行的命令")
        lines.append("")
        lines.append("```bash")
        lines.append(cmd)
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# YAML 模板：从漏洞结果生成 / 自定义模板管理
# ---------------------------------------------------------------------------
TEMPLATE_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def find_builtin_template(template_id):
    """在已安装模板目录中按 template-id 查找原始 YAML。找不到返回 None。"""
    if not template_id:
        return None
    root = DEFAULT_TEMPLATES_DIR
    if not os.path.isdir(root):
        return None
    # 1) 文件名快速匹配：<id>.yaml / <id>.yml
    for dirpath, _, files in os.walk(root):
        for fn in files:
            base = fn.lower()
            if base in (template_id.lower() + ".yaml", template_id.lower() + ".yml"):
                try:
                    with open(os.path.join(dirpath, fn), "r", encoding="utf-8",
                              errors="replace") as f:
                        return f.read()
                except Exception:
                    continue
    # 2) 内容匹配 id 字段（限制读取范围，控制开销）
    pattern = re.compile(r"(?im)^id\s*:\s*['\"]?" + re.escape(template_id) + r"['\"]?\s*$")
    scanned = 0
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.lower().endswith((".yaml", ".yml")):
                continue
            scanned += 1
            if scanned > 10000:
                return None
            p = os.path.join(dirpath, fn)
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    head = f.read(2048)
                if pattern.search(head):
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        return f.read()
            except Exception:
                continue
    return None


def _safe_template_name(name):
    name = (name or "").strip()
    # 拒绝路径分隔符与 ..，防止路径穿越
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        return None
    if not name.lower().endswith((".yaml", ".yml")):
        name += ".yaml"
    base = os.path.splitext(name)[0]
    if not TEMPLATE_NAME_RE.match(base):
        return None
    return base + ".yaml"


def generate_yaml_from_result(result):
    """根据一条漏洞结果生成 YAML 模板。
    返回 (content, source, name)，source 为 builtin（取自内置模板）或 generated（自动生成骨架）。"""
    result = result or {}
    tid = str(result.get("template_id") or "").strip() or "custom-template"
    # 优先：若本地有该内置模板，直接拿来可编辑
    src = find_builtin_template(tid)
    if src:
        return src, "builtin", tid + ".yaml"
    # 否则生成骨架
    name = str(result.get("name") or tid).strip()
    sev = str(result.get("severity") or "info").strip().lower()
    tags = str(result.get("tags") or "").strip()
    matched = str(result.get("matched_at") or "").strip()
    path = "/"
    if matched:
        try:
            u = urllib.parse.urlsplit(matched if matched.startswith("http") else "http://" + matched)
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
        except Exception:
            path = "/"
    safe_tid = re.sub(r"[^A-Za-z0-9_-]", "-", tid)
    content = (
        "# 由 Nuclei GUI 从历史扫描结果生成\n"
        f"# 来源目标: {matched or '未知'}\n"
        "# 说明: 已生成基础 HTTP 请求骨架，请根据漏洞特征补全 matchers 后再复用。\n\n"
        f"id: {safe_tid}-custom\n\n"
        "info:\n"
        f"  name: {name}\n"
        "  author: nuclei-gui\n"
        f"  severity: {sev}\n"
        "  description: |\n"
        "    由 Nuclei GUI 生成，请补充检测逻辑。\n"
        f"  tags: {tags}\n\n"
        "http:\n"
        "  - method: GET\n"
        "    path:\n"
        f"      - \"{{{{BaseURL}}}}{path}\"\n"
        "    matchers-condition: and\n"
        "    matchers:\n"
        "      - type: status\n"
        "        status:\n"
        "          - 200\n"
        "      # - type: word\n"
        "      #   words:\n"
        "      #     - \"请填写漏洞特征关键字\"\n"
        "      #   part: body\n"
    )
    return content, "generated", safe_tid + "-custom.yaml"


def save_custom_template(name, content):
    """保存自定义模板。name 只允许字母/数字/下划线/中划线，防止路径穿越。"""
    fn = _safe_template_name(name)
    if fn is None:
        return False, "文件名只能包含字母、数字、下划线、中划线"
    os.makedirs(CUSTOM_TEMPLATES_DIR, exist_ok=True)
    target = os.path.join(CUSTOM_TEMPLATES_DIR, fn)
    try:
        tmp = target + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, target)
        return True, target
    except Exception as e:
        return False, f"保存失败: {e}"


def list_custom_templates():
    if not os.path.isdir(CUSTOM_TEMPLATES_DIR):
        return []
    out = []
    for fn in sorted(os.listdir(CUSTOM_TEMPLATES_DIR)):
        if not fn.lower().endswith((".yaml", ".yml")):
            continue
        p = os.path.join(CUSTOM_TEMPLATES_DIR, fn)
        try:
            st = os.stat(p)
            out.append({"name": fn, "path": p, "size": st.st_size,
                        "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                               time.localtime(st.st_mtime))})
        except Exception:
            continue
    return out


def read_custom_template(name):
    fn = _safe_template_name(name)
    if fn is None:
        return None
    p = os.path.join(CUSTOM_TEMPLATES_DIR, fn)
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def delete_custom_template(name):
    fn = _safe_template_name(name)
    if fn is None:
        return False
    p = os.path.join(CUSTOM_TEMPLATES_DIR, fn)
    if os.path.isfile(p):
        try:
            os.remove(p)
            return True
        except Exception:
            return False
    return False


def validate_template_content(content):
    """用 nuclei -validate 校验 YAML 模板。返回 {ok, valid, output}。
    ok=False 表示无法执行校验（如未找到 nuclei）；valid 表示语法是否通过。"""
    exe = resolve_nuclei()
    if not exe:
        return {"ok": False, "valid": False,
                "output": "未找到 nuclei，无法执行校验。请在「设置」中配置 nuclei 路径后重试。"}
    tmp = os.path.join(tempfile.gettempdir(),
                       "ngui_validate_" + uuid.uuid4().hex[:8] + ".yaml")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content or "")
        code, out = run_cli([exe, "-validate", "-t", tmp, "-duc"], timeout=60)
        return {"ok": True, "valid": code == 0,
                "output": (out or "").strip()[:3000]}
    except Exception as e:
        return {"ok": False, "valid": False, "output": f"校验执行失败: {e}"}
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# HTTP 服务
# ---------------------------------------------------------------------------
MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}


def json_resp(handler, data, code=200):
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def read_body(handler):
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


class Handler(BaseHTTPRequestHandler):
    server_version = "NucleiGUI/1.0"

    # 关闭默认日志
    def log_message(self, fmt, *args):
        pass

    # -- 工具 --------------------------------------------------------------
    def send_file(self, path):
        ext = os.path.splitext(path)[1].lower()
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    # -- 路由 --------------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self.send_file(os.path.join(WEB_DIR, "index.html"))
            return
        if path.startswith("/css/") or path.startswith("/js/") or path.startswith("/assets/"):
            fp = os.path.normpath(os.path.join(WEB_DIR, path.lstrip("/")))
            if fp.startswith(WEB_DIR) and os.path.isfile(fp):
                self.send_file(fp)
                return

        # ---- API ----
        if path == "/api/status":
            json_resp(self, get_nuclei_status())
            return
        if path == "/api/config":
            json_resp(self, get_config())
            return
        if path == "/api/scans":
            scans = load_scans()
            # 最新在前
            scans = sorted(scans, key=lambda s: s.get("created_at", ""), reverse=True)
            json_resp(self, {"scans": scans})
            return

        m = re.match(r"^/api/scans/([0-9a-zA-Z_\-]+)/output$", path)
        if m:
            sid = m.group(1)
            offset = int(qs.get("offset", ["0"])[0])
            runner = MANAGER.get(sid)
            if runner:
                lines, new_off = runner.read_log(offset)
                rec = scan_record(sid) or {}
                return json_resp(self, {"lines": lines, "offset": new_off,
                                        "running": True,
                                        "result_count": rec.get("result_count", 0)})
            rec = scan_record(sid)
            if not rec:
                return json_resp(self, {"error": "not found"}, 404)
            # 已结束，读文件
            logp = os.path.join(LOGS_DIR, sid + ".log")
            all_lines = []
            if os.path.exists(logp):
                with open(logp, "r", encoding="utf-8") as f:
                    all_lines = f.read().splitlines()
            lines = all_lines[offset:]
            return json_resp(self, {"lines": lines, "offset": len(all_lines),
                                    "running": False,
                                    "result_count": rec.get("result_count", 0)})

        m = re.match(r"^/api/scans/([0-9a-zA-Z_\-]+)/results$", path)
        if m:
            sid = m.group(1)
            rows = parse_jsonl_results(os.path.join(RESULTS_DIR, sid + ".jsonl"))
            dedupe = qs.get("dedupe", ["0"])[0] in ("1", "true", "yes")
            if dedupe:
                rows = dedupe_results(rows)
            stats = severity_stats(rows)
            return json_resp(self, {"results": rows, "stats": stats,
                                    "deduped": dedupe, "total": len(rows)})

        m = re.match(r"^/api/scans/([0-9a-zA-Z_\-]+)/report$", path)
        if m:
            sid = m.group(1)
            fmt = qs.get("format", ["jsonl"])[0]
            if fmt == "md":
                body = build_markdown_report(sid).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{sid}.md"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            target = os.path.join(RESULTS_DIR, sid + ".jsonl")
            if fmt == "txt":
                target = os.path.join(RESULTS_DIR, sid + ".txt")
            if os.path.exists(target):
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    data = f.read()
                body = data.encode("utf-8")
                self.send_response(200)
                ctype = "application/json" if fmt == "jsonl" else "text/plain; charset=utf-8"
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{sid}.{fmt}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            return json_resp(self, {"error": "no report"}, 404)

        # 模板与标签
        if path == "/api/tags":
            exe = resolve_nuclei()
            if not exe:
                return json_resp(self, {"tags": [], "error": "未找到 nuclei"})
            code, out = run_cli([exe, "-tgl", "-nc", "-silent", "-duc"],
                                timeout=300, merge_stderr=False)
            # 标签行以字母开头；banner/标题/日志被 clean 过滤
            tags = [t for t in clean_nuclei_list_output(out) if t and t[0].isalpha()]
            # 若输出带说明则过滤
            return json_resp(self, {"tags": tags, "error": "" if code == 0 else out[:500]})

        if path == "/api/templates":
            exe = resolve_nuclei()
            if not exe:
                return json_resp(self, {"templates": [], "error": "未找到 nuclei"})
            args = [exe, "-tl", "-nc", "-duc", "-silent"]
            sev = qs.get("severity", [None])[0]
            tags = qs.get("tags", [None])[0]
            ttype = qs.get("type", [None])[0]
            if sev:
                args += ["-s", sev]
            if tags:
                args += ["-tags", tags]
            if ttype:
                args += ["-pt", ttype]
            code, out = run_cli(args, timeout=300, merge_stderr=False)
            # 模板行以 .yaml/.yml 结尾（banner 等非模板行全部排除）
            tpls = [t for t in clean_nuclei_list_output(out)
                    if t.lower().endswith((".yaml", ".yml"))]
            return json_resp(self, {"templates": tpls, "count": len(tpls),
                                    "error": "" if code == 0 else out[:500]})

        if path == "/api/templates/tree":
            # 模板目录树（懒加载）：?dir=<相对路径> 返回该目录的直接子节点
            rel = (qs.get("dir", [None])[0] or "").strip()
            root = resolve_templates_root()
            base, rel_out, items = list_templates_tree(root, rel)
            if base is None:
                return json_resp(self, {"error": "非法路径"}, 400)
            return json_resp(self, {"root": base, "dir": rel_out, "items": items})

        if path == "/api/templates/all":
            # 模板根下全部目录与 yaml 文件（供树内搜索）
            root = resolve_templates_root()
            out = []
            def _walk(root_, rel_):
                base, rel_out, items = list_templates_tree(root_, rel_)
                if base is None:
                    return
                for it in items:
                    out.append(it)
                    if it["type"] == "dir":
                        _walk(root_, it["path"])
            _walk(root, "")
            return json_resp(self, {"root": root, "items": out})

        if path == "/api/templates/custom":
            name = qs.get("name", [None])[0]
            if name:
                content = read_custom_template(name)
                if content is None:
                    return json_resp(self, {"error": "模板不存在"}, 404)
                return json_resp(self, {"name": name, "content": content})
            return json_resp(self, {"templates": list_custom_templates()})

        if path == "/api/backup":
            # 一键备份：data/ + custom-templates/ 打包为 zip 下载
            try:
                body = build_backup_bytes()
            except Exception as e:
                return json_resp(self, {"error": f"备份失败: {e}"}, 500)
            fname = "nuclei-gui-backup-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".zip"
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/netcheck":
            # 网络连通性检查：并行快速探测 GitHub 官方与镜像源（带预算上限）
            result = {"github": False, "mirror": False, "detail": []}
            probes = {}

            def probe(name, url):
                try:
                    http_get_bounded(url, budget=5)
                    probes[name] = True
                except Exception:
                    probes[name] = False

            threads = [threading.Thread(target=probe, args=("github", "https://github.com"))]
            for m in GH_MIRRORS:
                threads.append(threading.Thread(target=probe, args=(m, m)))
            threads.append(threading.Thread(target=probe, args=("jsdelivr", "https://cdn.jsdelivr.net/")))
            threads.append(threading.Thread(target=probe, args=("gitee", "https://gitee.com")))
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=6)

            if probes.get("github"):
                result["github"] = True
                result["detail"].append("GitHub 官方：可达")
            else:
                result["detail"].append("GitHub 官方：不可达（将自动使用镜像）")
            for m in GH_MIRRORS:
                if probes.get(m):
                    result["mirror"] = True
                    result["detail"].append(f"镜像 {m}：可达")
                    break
            if probes.get("jsdelivr"):
                result["detail"].append("jsDelivr CDN：可达")
            if probes.get("gitee"):
                result["detail"].append("Gitee：可达（模板 git 镜像可用）")
            if not result["mirror"]:
                result["detail"].append("所有 GitHub 加速镜像：不可达")
            return json_resp(self, result)

        self.send_error(404)

    # -- POST --------------------------------------------------------------
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/config":
            cfg = read_body(self)
            cur = get_config()
            if "nuclei_path" in cfg:
                cur["nuclei_path"] = cfg["nuclei_path"].strip()
            if "theme" in cfg:
                cur["theme"] = cfg["theme"]
            if "port" in cfg:
                cur["port"] = int(cfg["port"] or cur["port"])
            if isinstance(cfg.get("defaults"), dict):
                cur["defaults"].update(cfg["defaults"])
            save_config(cur)
            json_resp(self, {"ok": True, "config": get_config()})
            return

        if path == "/api/templates/from-result":
            body = read_body(self)
            content, source, name = generate_yaml_from_result(body.get("result") or {})
            json_resp(self, {"content": content, "source": source, "name": name})
            return

        if path == "/api/templates/validate":
            body = read_body(self)
            content = body.get("content") or ""
            if not content.strip():
                return json_resp(self, {"ok": False, "valid": False,
                                        "output": "模板内容为空，无法校验"})
            json_resp(self, validate_template_content(content))
            return

        if path == "/api/templates/custom":
            body = read_body(self)
            name = (body.get("name") or "").strip()
            content = body.get("content") or ""
            ok, msg = save_custom_template(name, content)
            if not ok:
                return json_resp(self, {"ok": False, "error": msg})
            return json_resp(self, {"ok": True, "name": os.path.basename(msg), "path": msg})

        if path == "/api/templates/file/delete":
            body = read_body(self)
            rel = (body.get("path") or "").strip()
            if not rel:
                return json_resp(self, {"ok": False, "error": "缺少 path"})
            ok, msg = delete_template_item(rel)
            return json_resp(self, {"ok": ok, "message": msg,
                                    "error": "" if ok else msg})

        if path == "/api/templates/file/rename":
            body = read_body(self)
            rel = (body.get("path") or "").strip()
            new_name = (body.get("new_name") or "").strip()
            if not rel or not new_name:
                return json_resp(self, {"ok": False, "error": "缺少 path 或 new_name"})
            ok, msg = rename_template_item(rel, new_name)
            return json_resp(self, {"ok": ok, "message": msg,
                                    "error": "" if ok else msg})

        if path == "/api/templates/file/move":
            body = read_body(self)
            rel = (body.get("path") or "").strip()
            dest_dir = (body.get("dest_dir") or "").strip()
            if not rel:
                return json_resp(self, {"ok": False, "error": "缺少 path"})
            ok, msg = move_template_item(rel, dest_dir)
            return json_resp(self, {"ok": ok, "message": msg,
                                    "error": "" if ok else msg})

        if path == "/api/scan":
            params = read_body(self)
            scan_id = start_scan(params)
            json_resp(self, {"ok": True, "id": scan_id})
            return

        m = re.match(r"^/api/scans/([0-9a-zA-Z_\-]+)/rescan$", path)
        if m:
            sid = m.group(1)
            rec = scan_record(sid)
            if not rec:
                return json_resp(self, {"ok": False, "error": "记录不存在"})
            params = dict(rec.get("params") or {})
            if not (params.get("targets") or []):
                params["targets"] = rec.get("targets") or []
            new_id = start_scan(params)
            json_resp(self, {"ok": True, "id": new_id, "rescan_of": sid})
            return

        if path == "/api/update":
            body = read_body(self)
            target = body.get("target", "templates")
            force_mirror = bool(body.get("force_mirror"))
            exe = resolve_nuclei()
            # 模板更新：官方优先，失败回退镜像
            if target == "templates":
                if not force_mirror and exe:
                    code, out = run_cli([exe, "-update-templates", "-duc"], timeout=120)
                    if code == 0:
                        return json_resp(self, {"ok": True, "source": "official",
                                                "output": out[:2000]})
                ok, msg = update_templates_from_mirror()
                return json_resp(self, {"ok": ok, "source": "mirror", "output": msg,
                                        "dir": DEFAULT_TEMPLATES_DIR})
            # 引擎更新：官方优先，失败回退镜像二进制
            if target == "nuclei":
                if not force_mirror and exe:
                    code, out = run_cli([exe, "-update", "-duc"], timeout=120)
                    if code == 0:
                        return json_resp(self, {"ok": True, "source": "official",
                                                "output": out[:2000]})
                ok, msg = download_nuclei_from_mirror()
                return json_resp(self, {"ok": ok, "source": "mirror", "output": msg})
            return json_resp(self, {"ok": False, "error": "未知更新目标"})

        # 扫描控制
        m = re.match(r"^/api/scans/([0-9a-zA-Z_\-]+)/(stop|delete)$", path)
        if m:
            sid, action = m.group(1), m.group(2)
            if action == "stop":
                ok = MANAGER.stop(sid)
                if ok:
                    update_scan(sid, status="stopping")
                return json_resp(self, {"ok": ok})
            if action == "delete":
                MANAGER.stop(sid)
                with _lock:
                    scans = load_scans()
                    scans = [s for s in scans if s.get("id") != sid]
                    save_scans(scans)
                for f in (os.path.join(LOGS_DIR, sid + ".log"),
                          os.path.join(RESULTS_DIR, sid + ".jsonl"),
                          os.path.join(RESULTS_DIR, sid + ".txt"),
                          os.path.join(TARGETS_DIR, sid + ".txt")):
                    if os.path.exists(f):
                        try:
                            os.remove(f)
                        except Exception:
                            pass
                return json_resp(self, {"ok": True})

        if path == "/api/restore":
            # 恢复数据：上传 zip（base64 编码），先备份当前数据再覆盖
            body = read_body(self)
            b64 = body.get("zip_b64") or ""
            if not b64:
                return json_resp(self, {"ok": False, "error": "缺少备份文件内容"})
            try:
                data = base64.b64decode(b64)
            except Exception as e:
                return json_resp(self, {"ok": False, "error": f"base64 解码失败: {e}"})
            with _lock:
                ok, msg, summary = restore_from_zip_bytes(data)
            if not ok:
                return json_resp(self, {"ok": False, "error": msg})
            return json_resp(self, {"ok": True, "message": msg, "summary": summary})

        self.send_error(404)

    # DELETE
    def do_DELETE(self):
        parsed = urlparse(self.path)
        m = re.match(r"^/api/scans/([0-9a-zA-Z_\-]+)$", parsed.path)
        if m:
            sid = m.group(1)
            MANAGER.stop(sid)
            with _lock:
                scans = load_scans()
                scans = [s for s in scans if s.get("id") != sid]
                save_scans(scans)
            for f in (os.path.join(LOGS_DIR, sid + ".log"),
                      os.path.join(RESULTS_DIR, sid + ".jsonl"),
                      os.path.join(RESULTS_DIR, sid + ".txt"),
                      os.path.join(TARGETS_DIR, sid + ".txt")):
                if os.path.exists(f):
                    try:
                        os.remove(f)
                    except Exception:
                        pass
            return json_resp(self, {"ok": True})
        # 删除自定义模板
        if parsed.path == "/api/templates/custom":
            qs = parse_qs(parsed.query)
            name = qs.get("name", [None])[0]
            if not name:
                return json_resp(self, {"ok": False, "error": "缺少 name"})
            ok = delete_custom_template(name)
            return json_resp(self, {"ok": ok})
        self.send_error(404)


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
def open_browser(url):
    """打开浏览器。若以 sudo 运行（Kali 常见），则切回原用户再打开。"""
    try:
        sudo_user = os.environ.get("SUDO_USER")
        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0 and sudo_user:
            subprocess.Popen(["sudo", "-u", sudo_user, "xdg-open", url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
    except Exception:
        pass
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Nuclei GUI - 漏洞扫描图形化工具")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=None, help="监听端口（默认 8333）")
    parser.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    args = parser.parse_args()

    ensure_dirs()
    cfg = get_config()
    port = args.port or int(cfg.get("port") or 8333)
    host = args.host

    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print("=" * 58)
    print("  Nuclei GUI  漏洞扫描图形化工具")
    print("=" * 58)
    status = get_nuclei_status()
    if status["ok"]:
        print(f"  nuclei: {status['path']}  v{status['version']}")
        print(f"  模板:   v{status['templates'] or '未知'}")
    else:
        print(f"  [!] {status['error']}")
    print(f"  数据目录: {DATA_DIR}")
    print(f"  模板目录: {DEFAULT_TEMPLATES_DIR}")
    print(f"  访问地址: {url}")
    print("  Ctrl+C 退出")
    print("=" * 58)

    if not args.no_browser:
        threading.Timer(1.0, lambda: open_browser(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n正在退出...")
        httpd.server_close()


if __name__ == "__main__":
    main()
