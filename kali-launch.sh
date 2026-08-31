#!/usr/bin/env bash
# ==========================================================================
#  Nuclei GUI  Kali 桌面双击启动入口
#  双击桌面图标后，在终端内以 sudo 启动：
#    - 已安装 pywebview（GTK/WebKit）→ 弹出独立桌面窗口（免浏览器）
#    - 未安装 / 无桌面环境        → 回退浏览器模式（sudo ./start.sh 自动打开浏览器）
# ==========================================================================
cd "$(dirname "$0")"

echo "============================================================"
echo "  Nuclei GUI  漏洞扫描图形化工具  (Kali)"
echo "============================================================"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] 未找到 python3，请先安装: sudo apt install -y python3"
    read -r -p "按回车退出..." _
    exit 1
fi

if python3 -c "import webview" >/dev/null 2>&1 && [ -n "$DISPLAY" ]; then
    echo "[*] 使用独立窗口模式（sudo 启动后端 + 桌面窗口）..."
    exec sudo python3 desktop.py
else
    echo "[*] 使用浏览器模式（sudo 启动后端并自动打开浏览器）..."
    exec sudo ./start.sh
fi
