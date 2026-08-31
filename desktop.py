# -*- coding: utf-8 -*-
"""
Nuclei GUI 桌面启动器（Windows）
================================
双击桌面图标后以独立窗口（WebView2）打开界面，无需手动打开浏览器。

行为：
- 读取 data/config.json 中配置的端口（默认 8333）
- 若后端服务未在监听，则自动启动（隐藏控制台窗口）；已运行则直接复用
- 等待后端就绪后，用 pywebview 打开独立桌面窗口加载界面
- 窗口关闭后：若后端是本启动器拉起的，则一并关闭，避免残留进程
- 所有运行日志写入 data/logs/desktop.log（pythonw 无控制台时用于排查）

用法：
    python desktop.py            # 正常启动
    python desktop.py --probe    # 自检模式：窗口打开约 6 秒后自动关闭（用于验证）
"""
import argparse
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time

APP_DIR = os.path.dirname(os.path.abspath(__file__))
HOST = "127.0.0.1"
LOG_FILE = os.path.join(APP_DIR, "data", "logs", "desktop.log")


def setup_logging():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        encoding="utf-8",
    )


def read_port():
    """从 config.json 读取端口，失败回退 8333。"""
    try:
        cfg_path = os.path.join(APP_DIR, "data", "config.json")
        if os.path.exists(cfg_path):
            with open(cfg_path, encoding="utf-8") as f:
                cfg = json.load(f)
            return int(cfg.get("port") or 8333)
    except Exception as e:  # noqa: BLE001
        logging.warning("读取端口配置失败，使用默认 8333: %s", e)
    return 8333


def port_listening(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_port(host, port, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_listening(host, port):
            return True
        time.sleep(0.3)
    return False


def start_backend():
    """以隐藏控制台窗口的方式启动后端，返回 Popen。"""
    exe = sys.executable
    if exe.lower().endswith("pythonw.exe"):
        exe = os.path.join(os.path.dirname(exe), "python.exe")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.Popen(
            [exe, os.path.join(APP_DIR, "app.py"),
             "--host", HOST, "--port", str(PORT), "--no-browser"],
            cwd=APP_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )
        logging.info("后端已启动 pid=%s port=%s", proc.pid, PORT)
        return proc
    except Exception as e:  # noqa: BLE001
        logging.error("后端启动失败: %s", e)
        return None


def _prepare_gui_env():
    """Linux 下以 root 运行时规避 WebKit2GTK 沙箱限制（Kali sudo 场景）。"""
    if sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0:
        os.environ.setdefault("WEBKIT_FORCE_SANDBOX", "0")
        os.environ.setdefault("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "1")


def open_desktop_window(probe=False):
    """打开独立桌面窗口（必须在主线程调用）。返回是否成功。"""
    _prepare_gui_env()
    import webview

    url = f"http://{HOST}:{PORT}/"
    logging.info("打开桌面窗口: %s", url)
    window = webview.create_window(
        "Nuclei GUI - 漏洞扫描图形化工具",
        url,
        width=1280,
        height=840,
        min_size=(1024, 700),
        background_color="#1B1B1F",
        text_select=True,
    )
    if probe:
        threading.Timer(6.0, window.destroy).start()
    webview.start()
    logging.info("桌面窗口已关闭")


def main():
    global PORT
    setup_logging()
    parser = argparse.ArgumentParser(description="Nuclei GUI 桌面启动器")
    parser.add_argument("--probe", action="store_true",
                        help="自检模式：打开窗口约 6 秒后自动关闭")
    args = parser.parse_args()

    PORT = read_port()
    logging.info("Nuclei GUI 桌面启动器开始运行，端口=%s probe=%s", PORT, args.probe)

    started = False
    proc = None
    if not port_listening(HOST, PORT):
        proc = start_backend()
        if proc is None:
            logging.error("无法启动后端")
            return
        started = True
    else:
        logging.info("检测到后端已在运行，直接打开窗口")

    if not wait_port(HOST, PORT):
        logging.error("后端 %s:%s 未就绪", HOST, PORT)
        if started and proc:
            try:
                proc.terminate()
            except Exception:  # noqa: BLE001
                pass
        return

    try:
        open_desktop_window(probe=args.probe)
    except Exception as e:  # noqa: BLE001
        logging.error("打开桌面窗口失败: %s", e)
        raise

    # 窗口关闭后，关闭由本启动器拉起的后端
    if started and proc:
        try:
            proc.terminate()
            logging.info("已关闭本启动器拉起的后端 pid=%s", proc.pid)
        except Exception as e:  # noqa: BLE001
            logging.warning("关闭后端失败: %s", e)


if __name__ == "__main__":
    main()
