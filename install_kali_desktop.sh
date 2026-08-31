#!/usr/bin/env bash
# ==========================================================================
#  Nuclei GUI  Kali 桌面图标一键安装脚本
#
#  用法:  bash install_kali_desktop.sh
#
#  效果:
#    - 可选安装 pywebview 依赖（独立窗口模式；失败不影响浏览器模式）
#    - 在桌面创建「Nuclei GUI」图标
#    - 双击图标 -> 终端输入密码(sudo) -> 自动启动并打开界面
# ==========================================================================
set -e
cd "$(dirname "$0")"
APP="$(pwd)"

echo "============================================================"
echo "  Nuclei GUI - Kali 桌面图标安装"
echo "============================================================"

# ---- 1. 可选依赖：独立窗口模式（pywebview + WebKit2GTK）----
if ! python3 -c "import webview" >/dev/null 2>&1; then
    echo "[*] 未检测到 pywebview，尝试安装（独立窗口用，失败则回退浏览器模式）..."
    sudo apt-get update -qq 2>/dev/null || true
    sudo apt-get install -y python3-webview python3-gi python3-gi-cairo gir1.2-gtk-3.0 >/dev/null 2>&1 || true
    sudo apt-get install -y gir1.2-webkit2-4.1 >/dev/null 2>&1 || sudo apt-get install -y gir1.2-webkit2-4.0 >/dev/null 2>&1 || true
fi
if ! python3 -c "import PIL" >/dev/null 2>&1; then
    sudo apt-get install -y python3-pil >/dev/null 2>&1 || true
fi

# ---- 2. 图标（缺省时用 Pillow 生成）----
if [ ! -f icons/app.png ] || [ ! -f icons/app.ico ]; then
    python3 make_icon.py 2>/dev/null || echo "[!] 图标生成失败，将使用系统默认图标"
fi

# ---- 3. 桌面目录 ----
DESKTOP="${XDG_DESKTOP_DIR:-$HOME/Desktop}"
[ -d "$DESKTOP" ] || DESKTOP="$HOME/桌面"
mkdir -p "$DESKTOP"

# ---- 4. 生成 .desktop 桌面启动器 ----
chmod +x kali-launch.sh
DESKTOP_FILE="$DESKTOP/Nuclei GUI.desktop"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Nuclei GUI
Name[zh_CN]=Nuclei GUI
Comment=漏洞扫描图形化工具（nuclei）
Comment[zh_CN]=漏洞扫描图形化工具
Exec=$APP/kali-launch.sh
Icon=$APP/icons/app.png
Path=$APP
Terminal=true
Categories=Utility;Security;Network;
StartupNotify=false
EOF
chmod +x "$DESKTOP_FILE"
gio set "$DESKTOP_FILE" metadata::trusted true 2>/dev/null || true

echo
echo "[OK] 已创建桌面图标: $DESKTOP_FILE"
echo
echo "  双击图标 -> 终端输入密码 -> 自动启动并打开界面"
echo "  （已装 pywebview 则弹独立窗口免浏览器；否则自动打开浏览器）"
echo
echo "提示:"
echo "  · 桌面不显示图标 -> 右键桌面「刷新」；提示不受信任 -> 右键图标勾选「允许启动」"
echo "  · 只保留浏览器模式 -> 删除 icons/ 依赖即可，无需装 pywebview"
echo "  · 卸载: rm \"$DESKTOP_FILE\""
