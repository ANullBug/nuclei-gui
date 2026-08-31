#!/usr/bin/env bash
# ==========================================================================
#  Nuclei GUI  一键启动脚本（Kali / Debian 系）
# ==========================================================================
#  用法:
#     sudo ./start.sh          # 推荐：root 权限启动（网络扫描需要）
#     ./start.sh               # 非 root 时自动用 sudo 提升
#
#  功能:
#     - 自动检测 python3 与 nuclei
#     - nuclei 缺失时尝试用 apt 安装
#     - 免登录，启动后自动打开浏览器访问界面
# ==========================================================================
set -e
cd "$(dirname "$0")"

echo "============================================================"
echo "  Nuclei GUI  漏洞扫描图形化工具  (Kali)"
echo "============================================================"

# 1. python3
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] 未找到 python3，请先安装:"
    echo "    sudo apt update && sudo apt install -y python3"
    exit 1
fi
echo "[*] python3: $(python3 --version 2>&1)"

# 2. nuclei
if ! command -v nuclei >/dev/null 2>&1 && [ ! -x "./nuclei" ]; then
    echo "[*] 未检测到 nuclei，尝试用 apt 安装..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq 2>/dev/null || true
        apt-get install -y nuclei 2>/dev/null || true
    fi
fi
if command -v nuclei >/dev/null 2>&1; then
    echo "[*] nuclei: $(nuclei -version 2>&1 | head -1)"
elif [ -x "./nuclei" ]; then
    echo "[*] nuclei: 使用本目录下二进制 ./nuclei"
else
    echo "[!] 未安装 nuclei。"
    echo "    可在界面「设置 → 网络与更新 → 镜像下载 nuclei」自动获取（无需科学上网）。"
fi

# 3. 可执行权限
chmod +x app.py 2>/dev/null || true

# 4. 启动（支持 sudo 一键启动；非 root 自动提升）
if [ "$(id -u)" != "0" ]; then
    echo "[*] 正在以 sudo 启动..."
    exec sudo python3 app.py "$@"
else
    echo "[*] 正在启动..."
    exec python3 app.py "$@"
fi
