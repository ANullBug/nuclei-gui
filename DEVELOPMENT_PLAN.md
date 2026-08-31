# Nuclei GUI — 开发计划（DEVELOPMENT_PLAN）

> 依据：`prd.md` v1.0
> 原则：按阶段顺序连续完成；**每个阶段必须实现 + 测试**；测试失败必须定位、修复后继续；
> 禁止删除/跳过测试或降低验收标准来让测试通过；全部阶段完成后运行全部测试。

## 测试基础设施
- 测试框架：Python 标准库 `unittest`（零依赖，可被 CI/本地直接运行）。
- 测试隔离：所有测试使用**临时数据目录**与**临时自定义模板目录**，不污染真实 `data/`。
- nuclei 模拟：无真实 nuclei 时使用 **stub nuclei 脚本**（可执行行为与真实命令一致），
  通过 monkeypatch `app.resolve_nuclei` 注入；验证命令参数、JSONL 输出、退出码、-validate 等。

---

## 阶段 0：重建完整测试套件 + 基线回归（✅ 完成）
- 目标：为已实现功能建立可复现的完整测试基线，作为后续阶段的回归保护。
- 内容：
  1. 编写 `tests/` 测试套件（unittest）：命令构造、JSONL 解析、端到端扫描(stub)、
     HTTP API、自定义模板 CRUD、防穿越、镜像下载小文件、netcheck。
  2. 全量运行，基线必须 100% 通过。
- 通过标准：`python -m unittest discover -s tests` 全部通过。

## 阶段 1：数据备份与恢复（✅ 完成）
- 依据：prd 7.3
- 后端：
  - `backup_data()`：把 `data/` + `custom-templates/` 打包为带时间戳 zip（返回字节/路径）。
  - `POST /api/backup` → 生成 zip 并以下载形式返回。
  - `POST /api/restore`（multipart 或 base64 zip）→ 校验 zip 结构 → **先备份当前数据** → 解压覆盖。
- 前端：设置页新增「数据备份与恢复」卡片（备份下载按钮、恢复文件选择、结果提示）。
- 测试：备份 zip 内容断言；恢复后文件一致；非法 zip 被拒绝且数据不受损。

## 阶段 2：模板校验（✅ 完成）
- 依据：prd 9.2
- 后端：
  - `POST /api/templates/validate` {content} → 写入临时 yaml → `nuclei -validate -t <tmp>`
    收集输出；nuclei 不存在时返回可理解的提示。
- 前端：YAML 编辑器新增「校验模板」按钮，展示通过/失败详情。
- 测试：stub 校验成功与失败两种分支。

## 阶段 3：Markdown 报告导出 + 一键重新扫描（✅ 完成）
- 依据：prd 9.3
- 后端：
  - `/api/scans/<id>/report?format=md`：把结果转为 Markdown 报告（按严重度分组的表格）。
  - 前端历史行新增「重扫」按钮 → 用原目标+过滤条件发起新扫描（`POST /api/scan`）。
- 测试：MD 内容断言；重扫接口触发新扫描记录。

## 阶段 4：结果去重与严重度统计（✅ 完成）
- 依据：prd 9.4
- 后端：
  - `/api/scans/<id>/results` 增加 `stats`（各严重度计数）与 `deduped` 标志（按 template-id+matched-at 去重，保留最高严重度）。
  - 查询参数 `dedupe=1` 时返回去重后的结果。
- 前端：详情结果工具栏显示严重度统计徽章；「去重」开关。
- 测试：构造重复结果断言去重正确与统计正确。

## 阶段 5：多请求头输入 + 排除严重程度（✅ 完成）
- 依据：prd 9.5
- 前端：请求头改为多行 textarea（后端已按换行/逗号拆分，保持兼容）。
- 后端：扫描参数增加 `exclude_severity` → 映射 `-es`；前端扫描页新增「排除严重程度」选择。
- 测试：命令构造断言 `-es` 与多 `-H`。

## 阶段 6：全量回归 + 收尾（✅ 完成）
- 运行全部测试；回归修复；更新 README；交付说明。
- 通过标准：全部测试 0 失败。
