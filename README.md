# Loon 三源聚合去广告插件

这是一个基于 GitHub Actions + Python 自动构建的 Loon 聚合去广告插件仓库。

功能：

- 定时从多个上游规则源拉取最新内容
- 自动识别 Loon 插件结构
- 自动提取 `[URL Rewrite]` / `[Script]` / `[MITM]`
- 自动去重、合并、重建统一头部
- 自动生成最终插件文件
- 内容变化时自动提交到仓库

---

## 当前上游来源

1. https://yfamilys.com/plugin/adlite.plugin
2. https://yfamilys.com/plugin/AdBlock.plugin
3. https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rewrite/Loon/Advertising/Advertising.plugin

---

## 最终产物

默认输出到：

`dist/merged-adblock.plugin`

---

## 自动更新方式

本仓库使用 GitHub Actions 自动更新，支持：

- 手动运行：`workflow_dispatch`
- 定时运行：`schedule`

工作流文件：

`.github/workflows/update.yml`

---

## 本地手动运行

### 1. 安装依赖

```bash
pip install -r requirements.txt
