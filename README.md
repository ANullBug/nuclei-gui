# Nuclei GUI — 漏洞扫描图形化工具

基于 [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) 命令功能的
**Win11 风格**图形化扫描工具。纯 Python 标准库实现（**零第三方依赖**），跨平台，
专门适配 **Kali Linux**，也支持 Windows / macOS。

界面为 Win11 Fluent 风格：亚克力毛玻璃、圆角卡片、深浅主题、左侧导航。

---

## 特性

- **图形化配置 nuclei 命令**：目标、速率、并发、超时、重试、代理、自定义请求头、
  高级原始参数，全部映射到真实 nuclei CLI 参数；「速率与优化」「高级参数」均可
  **展开 / 收缩**；扫描范围通过**模板树点选**直接指定。
- **扫描全程可视化**：「正在扫描」代码块带**进度条**，实时显示 nuclei 返回的代码与
  **结果计数**，一键停止；扫描结束后进度条置满。
- **历史与结果持久化**：扫描记录、JSONL 结构结果、原始日志、文本报告全部保存在
  `data/` 目录（把本应用放在 nuclei 同级即满足「数据保存在 nuclei 同级目录」）。
  **重启 / 关闭 / 刷新都不会丢失**。
- **扫描页内嵌模板树**：扫描页「模板选择」直接嵌入**模板树**，点击目录或 `.yaml` 文件
  即**指定该模板/目录为扫描范围**（目录与文件均支持**精确扫描**，默认扫描全部模板）；
  **搜索栏**可搜索**模板根目录下的所有目录与文件**（如 `cve`、`http/cves`、根目录直接文件）
  并一键指定；选中后显示「当前模板」提示条，可一键清除；另有「我的模板」页签复用自定义模板，
  无需跳转模板库。
- **模板库（文件管理）**：查看本机所有模板的目录树；每个文件可
  **重命名、移动、删除**（目录支持移动 / 删除），移动目标填相对目录（如 `http/cves`，留空 = 根目录），
  便于整理模板库。
- **目标文件导入**：扫描页「多目标」支持导入本地文本文件（每行一个 IP / URL / CIDR），
  自动去重、过滤 `#` 注释行，一次批量扫描多个目标。
- **历史漏洞 → YAML 模板**：在历史记录详情中，任一漏洞结果可一键生成 nuclei YAML 模板
  （若本地模板库含该内置模板则直接读取原件），支持**查看、修改、保存**，保存后进入
  「模板库 → 我的模板」，可反复复用；也可手工新建模板。
- **我的模板**：自定义模板保存在应用目录（nuclei 同级）的 `custom-templates/` 下，
  支持查看 / 编辑 / 删除 / 一键填入扫描。
- **联网更新 + 镜像回退**：
  - 更新模板库 / nuclei 引擎：**官方源优先**；
  - 官方源连不上（国内直连 GitHub 常被墙）时，**自动回退镜像站**下载：
    - 模板：Gitee 镜像 `git clone` → GitHub 加速代理（ghfast.top / gh-proxy.com 等）zip
    - nuclei 二进制：GitHub 加速代理下载对应平台 Release
  - 「设置 → 网络与更新」可一键检测各源连通性。
- **免登录**：本地回环地址访问，无账号体系。
- **Kali `sudo` 一键启动**：`sudo ./start.sh`，自动检测/安装 nuclei 并打开浏览器。
- **数据备份与恢复**：设置页一键把「配置 + 历史 + 结果 + 日志 + 自定义模板」打包为 zip
  下载；恢复时先自动备份当前数据再覆盖导入（含 zip-slip 防护与结构校验）。
- **模板校验**：YAML 模板编辑器中一键调用 `nuclei -validate` 校验语法，即时反馈通过/失败详情。
- **报告导出增强**：历史详情支持导出 **JSONL / TXT / Markdown** 报告（MD 按严重程度分组统计）。
- **一键重新扫描**：历史详情「重新扫描」用相同目标与参数发起新扫描。
- **结果去重与统计**：详情页显示各严重程度数量徽章，可一键按漏洞去重（保留最高严重度）。

---

## 快速开始（Kali）

### 1. 放置

把整个 `nuclei-gui` 目录放到 **nuclei 二进制所在目录**（这样数据就保存在 nuclei 同级目录）：

```bash
# 例如 nuclei 在 /usr/bin 或 ~/tools/nuclei
mkdir -p ~/tools && cp -r nuclei-gui ~/tools/nuclei-gui
cd ~/tools/nuclei-gui
```

### 2. 一键启动（sudo）

```bash
sudo ./start.sh
```

脚本会自动：
1. 检查 `python3`（缺失会提示安装）；
2. 检查 `nuclei`（缺失会用 `apt install nuclei` 尝试安装）；
3. 以 root 权限启动后端，并自动打开浏览器访问 `http://127.0.0.1:8333/`。

> 首次使用且未安装 nuclei 时，可在界面 **设置 → 网络与更新 → 镜像下载 nuclei**
> 一键获取二进制，无需科学上网。

### 3. 桌面双击启动（推荐，与 Windows 图标体验一致）

在 Kali 桌面创建「Nuclei GUI」图标，**双击即可 sudo 一键启动**：

```bash
bash install_kali_desktop.sh
```

脚本会自动：
1. （可选）安装 pywebview 依赖（`python3-webview` + WebKit2GTK），用于**独立窗口模式**；
2. 在桌面生成 `Nuclei GUI.desktop` 图标（使用 `icons/app.png`）；
3. 双击图标 → 终端输入密码 → 自动启动：
   - 已装 pywebview → 弹出**独立桌面窗口**（免浏览器，与 Windows 一致）；
   - 未装 / 无桌面 → 自动回退 `sudo ./start.sh` 打开浏览器。

> 说明：首次双击若提示「不受信任」，右键图标勾选「允许启动」；桌面不显示时右键桌面「刷新」。

### 4. 手动启动

```bash
sudo python3 app.py            # root 权限（网络扫描需要）
python3 app.py --port 9000     # 自定义端口
python3 app.py --no-browser    # 不自动打开浏览器
```

---

## Windows / 本地开发

**方式一：桌面图标（推荐，独立窗口、不经过浏览器）**

桌面上已创建 **Nuclei GUI** 快捷方式（蓝色靶心图标），双击即可：

1. 自动启动后端（若未运行）；
2. 弹出独立桌面窗口（WebView2 内核）加载界面；
3. 关闭窗口后自动回收本次启动的后端进程。

> 桌面启动器依赖两个可选包（仅窗口模式需要，核心 `app.py` 仍零依赖）：
> `pip install pywebview pillow`
> 手动重装：右键桌面图标 → 属性 → 目标改为 `pythonw.exe desktop.py` 所在环境。

**方式二：命令行**

```bat
start.bat
```

或 `python app.py`，然后浏览器访问 `http://127.0.0.1:8333/`。

---

## 数据与持久化

| 内容 | 位置 |
|---|---|
| 配置（引擎路径、默认参数、主题） | `data/config.json` |
| 扫描历史 | `data/scans.json` |
| 结构化结果（JSONL） | `data/results/<scan_id>.jsonl` |
| 文本报告 | `data/results/<scan_id>.txt` |
| 原始日志 | `data/logs/<scan_id>.log` |
| 多目标列表 | `data/targets/<scan_id>.txt` |
| 自定义模板 | `custom-templates/*.yaml` |
| 备份 zip | `data/backups/*.zip`（含恢复前自动备份） |

应用定位 nuclei 的优先级：**设置中指定路径 → 应用同目录 → PATH**。

---

## 命令映射（界面 → nuclei）

| 界面项 | nuclei 参数 |
|---|---|
| 单目标 | `-u <target>` |
| 多目标 | `-l <file>` |
| 严重程度 | `-s info,low,medium,high,critical` |
| 排除严重程度 | `-es ...` |
| 标签 | `-tags cve,tech` |
| 排除标签 | `-etags ...` |
| 指定模板/目录 | `-t http/cves/` |
| 协议类型 | `-pt http,dns,...` |
| 速率限制 | `-rl <n>` |
| 并发模板 | `-c <n>` |
| 批量主机 | `-bs <n>` |
| 超时 | `-timeout <n>` |
| 重试 | `-retries <n>` |
| 跟随重定向 | `-fr` |
| Headless | `-headless` |
| 代理 | `-proxy <url>` |
| 自定义请求头 | `-H "K: v"` |
| 仅输出结果 | `-silent` |
| 详细输出 | `-v` |
| 保存请求/响应 | `-sresp` |
| 无颜色 | `-nc` |
| JSONL 结构结果 | `-jle <file>` |
| 禁用更新检查 | `-duc` |

---

## 目录结构

```
nuclei-gui/
├── app.py              # 后端（零依赖，nuclei 调度 + API + 持久化 + 镜像下载）
├── desktop.py          # 桌面窗口启动器（pywebview，独立窗口免浏览器）
├── make_icon.py        # 生成应用图标 icons/app.ico
├── icons/app.ico       # 桌面快捷方式使用的应用图标
├── start.sh            # Kali 一键启动（sudo）
├── start.bat           # Windows 命令行启动
├── kali-launch.sh      # Kali 桌面双击统一入口（独立窗口/浏览器自动切换）
├── install_kali_desktop.sh # Kali 桌面图标一键安装脚本
├── prd.md              # 产品需求文档（开发依据）
├── DEVELOPMENT_PLAN.md # 开发计划与阶段
├── web/                # Win11 风格前端
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js
├── custom-templates/   # 自定义可复用 YAML 模板
├── tests/              # 自动化测试套件（python -m unittest discover -s tests）
├── data/               # 自动创建：配置 / 历史 / 结果 / 日志 / 备份（持久化）
└── README.md
```

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖：命令构造、JSONL 解析、端到端扫描（stub nuclei）、HTTP API、自定义模板 CRUD 与防穿越、
数据备份恢复、模板校验、Markdown 报告、一键重扫、结果去重与统计、多请求头 / 排除严重度等。

---

## 说明与免责

- 请仅在**已获授权**的目标上使用漏洞扫描。
- 将 nuclei 作为本地服务运行存在一定风险，本工具仅监听 `127.0.0.1`，请勿暴露到公网。
- 镜像站点列表随时间可能变化，若某个镜像失效可在「设置 → 网络与更新」检测后换用其他源。
