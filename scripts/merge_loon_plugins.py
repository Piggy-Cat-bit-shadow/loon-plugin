#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from html import unescape
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "sources.json"


logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
logger = logging.getLogger("loon-merge")


@dataclass
class ParsedPlugin:
    source_name: str
    source_url: str
    headers: Dict[str, str] = field(default_factory=dict)
    url_rewrite: List[str] = field(default_factory=list)
    script: List[str] = field(default_factory=list)
    mitm_hostnames: List[str] = field(default_factory=list)
    unknown_sections: List[str] = field(default_factory=list)


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        raise FileNotFoundError(f"配置文件不存在: {config_path}")
    with config_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def ensure_parent_dir(file_path: Path) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)


def extract_text_from_html(html: str) -> str:
    pre_match = re.search(r"<pre[^>]*>(.*?)</pre>", html, flags=re.I | re.S)
    if pre_match:
        text = pre_match.group(1)
    else:
        body_match = re.search(r"<body[^>]*>(.*?)</body>", html, flags=re.I | re.S)
        text = body_match.group(1) if body_match else html

    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"</p\s*>", "\n", text, flags=re.I)
    text = re.sub(r"</div\s*>", "\n", text, flags=re.I)
    text = re.sub(r"</li\s*>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    text = unescape(text)

    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    return "\n".join(lines).strip()


def looks_like_html(text: str) -> bool:
    s = text.lstrip().lower()
    return (
        s.startswith("<!doctype html")
        or s.startswith("<html")
        or "<body" in s
        or "<pre" in s
    )


def looks_like_plugin_text(text: str) -> bool:
    if not text or not text.strip():
        return False
    markers = [
        "#!name=",
        "[URL Rewrite]",
        "[Rewrite]",
        "[Script]",
        "[MITM]",
        "hostname ="
    ]
    return any(marker.lower() in text.lower() for marker in markers)


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def download_text_requests(url: str, timeout: int = 20) -> Optional[str]:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/123.0.0.0 Safari/537.36"
        ),
        "Accept": "text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": "https://yfamilys.com/",
    }

    try:
        with requests.Session() as session:
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            resp.raise_for_status()

            content_type = resp.headers.get("Content-Type", "").lower()
            text = normalize_newlines(resp.text)

            if not text:
                logger.warning("requests 下载成功但内容为空: %s", url)
                return None

            if "text/html" in content_type or looks_like_html(text):
                extracted = extract_text_from_html(text)
                if extracted.strip():
                    logger.info("requests 检测到 HTML，已提取正文: %s", url)
                    return extracted
                logger.warning("requests 命中 HTML，但未提取到有效正文: %s", url)
                return None

            return text
    except Exception as e:
        logger.warning("requests 下载失败: %s | %s", url, e)
        return None


def download_text_playwright(url: str, timeout_ms: int = 30000) -> Optional[str]:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/123.0.0.0 Safari/537.36"
                ),
                locale="zh-CN",
            )
            page = context.new_page()

            logger.info("Playwright 打开页面: %s", url)
            response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

            if response is not None:
                logger.info("Playwright HTTP 状态: %s -> %s", response.status, url)

            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightTimeoutError:
                logger.info("Playwright networkidle 等待超时，继续提取正文: %s", url)

            # 优先取 <pre>，其次 body.innerText
            text = ""
            pre_count = page.locator("pre").count()
            if pre_count > 0:
                chunks = []
                for i in range(pre_count):
                    item_text = page.locator("pre").nth(i).inner_text(timeout=3000).strip()
                    if item_text:
                        chunks.append(item_text)
                text = "\n".join(chunks).strip()

            if not text:
                try:
                    text = page.locator("body").inner_text(timeout=5000).strip()
                except Exception:
                    text = page.content()

            browser.close()

            text = normalize_newlines(text)
            if not text:
                logger.warning("Playwright 页面可访问但正文为空: %s", url)
                return None

            if looks_like_html(text):
                text = extract_text_from_html(text)

            if looks_like_plugin_text(text):
                logger.info("Playwright 成功提取插件文本: %s", url)
                return text

            logger.warning("Playwright 提取到正文，但不像标准插件文本: %s", url)
            return text or None

    except Exception as e:
        logger.warning("Playwright 抓取失败: %s | %s", url, e)
        return None


def load_cache_text(cache_path: Path) -> Optional[str]:
    if not cache_path.exists():
        return None
    try:
        text = normalize_newlines(cache_path.read_text(encoding="utf-8"))
        return text if text else None
    except Exception as e:
        logger.warning("读取缓存失败: %s | %s", cache_path, e)
        return None


def save_cache_text(cache_path: Path, text: str) -> None:
    try:
        ensure_parent_dir(cache_path)
        cache_path.write_text(normalize_newlines(text) + "\n", encoding="utf-8")
        logger.info("已更新缓存: %s", cache_path)
    except Exception as e:
        logger.warning("写入缓存失败: %s | %s", cache_path, e)


def get_source_text(source: dict) -> Optional[str]:
    url = source.get("url", "").strip()
    use_browser = bool(source.get("use_browser", False))
    cache_rel = source.get("cache", "").strip()
    cache_path = BASE_DIR / cache_rel if cache_rel else None

    text = None

    # 优先策略：
    # use_browser=true -> 先 playwright，再 requests
    # use_browser=false -> 先 requests，再 playwright（一般其实不会走到）
    if use_browser:
        logger.info("该源启用浏览器抓取优先策略。")
        text = download_text_playwright(url)
        if not text:
            logger.info("浏览器抓取失败，回退 requests: %s", url)
            text = download_text_requests(url)
    else:
        text = download_text_requests(url)

    if text:
        if cache_path:
            save_cache_text(cache_path, text)
        return text

    if cache_path:
        cached_text = load_cache_text(cache_path)
        if cached_text:
            logger.warning("远程拉取失败，改用本地缓存: %s", cache_path)
            return cached_text

    return None


def normalize_line(line: str) -> str:
    line = line.strip()
    line = re.sub(r"[ \t]+", " ", line)
    return line


def is_comment(line: str) -> bool:
    s = line.strip()
    return s.startswith("#") or s.startswith(";") or s.startswith("//")


def parse_header_line(line: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"^#!\s*([A-Za-z0-9_-]+)\s*=\s*(.*)$", line.strip())
    if m:
        return m.group(1).lower(), m.group(2).strip()
    return None


def split_mitm_hostnames(raw_value: str) -> List[str]:
    value = raw_value.strip()
    value = re.sub(r"^hostname\s*=\s*", "", value, flags=re.IGNORECASE).strip()
    value = re.sub(r"^%[A-Z_]+%\s*", "", value, flags=re.IGNORECASE).strip()

    items = []
    for part in value.split(","):
        host = part.strip()
        if host:
            items.append(host)
    return items


def canonicalize_hostname(host: str) -> str:
    return host.strip().lower()


def normalize_section_name(name: str) -> str:
    s = name.strip().lower()
    s = re.sub(r"\s+", " ", s)
    mapping = {
        "url rewrite": "url rewrite",
        "rewrite": "url rewrite",
        "script": "script",
        "mitm": "mitm",
        "host": "mitm",
    }
    return mapping.get(s, s)


def looks_like_script_rule(line: str) -> bool:
    s = line.strip().lower()
    return (
        "script-path=" in s
        or s.startswith("http-response ")
        or s.startswith("http-request ")
        or s.startswith("cron ")
    )


def looks_like_rewrite_rule(line: str) -> bool:
    s = line.strip()
    if not s or is_comment(s):
        return False

    if s.startswith("^http"):
        return True

    lowered = s.lower()
    rewrite_keywords = [
        " reject",
        " reject-200",
        " reject-dict",
        " reject-array",
        " reject-img",
        " reject-empty",
        " 302 ",
        " 307 ",
        " header-replace ",
        " body-replace ",
    ]
    return any(keyword in lowered for keyword in rewrite_keywords)


def parse_plugin_text(text: str, source_name: str, source_url: str) -> ParsedPlugin:
    parsed = ParsedPlugin(source_name=source_name, source_url=source_url)

    current_section: Optional[str] = None
    lines = text.split("\n")

    for raw_line in lines:
        line = raw_line.strip()

        if not line:
            continue

        header = parse_header_line(line)
        if header:
            k, v = header
            parsed.headers[k] = v
            continue

        section_match = re.match(r"^\[(.+?)\]$", line)
        if section_match:
            current_section = normalize_section_name(section_match.group(1))
            continue

        if is_comment(line):
            continue

        if re.match(r"^hostname\s*=", line, flags=re.IGNORECASE):
            parsed.mitm_hostnames.extend(split_mitm_hostnames(line))
            continue

        if current_section == "url rewrite":
            if looks_like_rewrite_rule(line):
                parsed.url_rewrite.append(line)
            else:
                parsed.unknown_sections.append(f"[URL Rewrite] {line}")
            continue

        if current_section == "script":
            if looks_like_script_rule(line):
                parsed.script.append(line)
            else:
                parsed.unknown_sections.append(f"[Script] {line}")
            continue

        if current_section == "mitm":
            parsed.unknown_sections.append(f"[MITM] {line}")
            continue

        if looks_like_script_rule(line):
            parsed.script.append(line)
        elif looks_like_rewrite_rule(line):
            parsed.url_rewrite.append(line)
        else:
            parsed.unknown_sections.append(line)

    return parsed


def canonicalize_rewrite_rule(rule: str) -> str:
    return normalize_line(rule)


def dedupe_url_rewrite(rules: List[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []

    for rule in rules:
        canon = canonicalize_rewrite_rule(rule)
        if canon in seen:
            continue
        seen.add(canon)
        result.append(canon)

    return result


def parse_script_identity(rule: str) -> str:
    canon = normalize_line(rule)

    pattern_match = re.search(r"^(.*?)\s+script-path=", canon, flags=re.IGNORECASE)
    path_match = re.search(r"script-path=([^\s,]+)", canon, flags=re.IGNORECASE)

    if pattern_match and path_match:
        pattern = pattern_match.group(1).strip()
        script_path = path_match.group(1).strip()
        return f"{pattern} | script-path={script_path}"

    return canon


def dedupe_script_rules(rules: List[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []

    for rule in rules:
        identity = parse_script_identity(rule)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(normalize_line(rule))

    return result


def dedupe_mitm_hostnames(hostnames: List[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []

    for host in hostnames:
        canon = canonicalize_hostname(host)
        if not canon:
            continue
        if canon in seen:
            continue
        seen.add(canon)
        result.append(canon)

    result.sort()
    return result


def build_plugin_text(
    config: dict,
    rewrite_rules: List[str],
    script_rules: List[str],
    mitm_hostnames: List[str],
) -> str:
    plugin_meta = config["plugin"]
    sources = config["sources"]

    lines: List[str] = []

    lines.append(f"#!name={plugin_meta['name']}")
    lines.append(f"#!desc={plugin_meta['desc']}")
    lines.append(f"#!author={plugin_meta['author']}")
    lines.append(f"#!homepage={plugin_meta['homepage']}")
    lines.append(f"#!icon={plugin_meta['icon_url']}")
    lines.append("")

    lines.append("# ============================================")
    lines.append("# 此文件由 GitHub Actions + Python 自动生成")
    lines.append("# 三源聚合、自动拉取、保守去重、自动更新")
    lines.append("# 上游来源：")
    for item in sources:
        lines.append(f"# - {item['name']}: {item['url']}")
    lines.append("# ============================================")
    lines.append("")

    lines.append("[URL Rewrite]")
    if rewrite_rules:
        lines.extend(rewrite_rules)
    else:
        lines.append("# 无可用 URL Rewrite 规则")
    lines.append("")

    lines.append("[Script]")
    if script_rules:
        lines.extend(script_rules)
    else:
        lines.append("# 无可用 Script 规则")
    lines.append("")

    lines.append("[MITM]")
    if mitm_hostnames:
        lines.append(f"hostname = %APPEND% {', '.join(mitm_hostnames)}")
    else:
        lines.append("# 无可用 MITM hostname")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_text_if_changed(path: Path, content: str) -> bool:
    old_content = None
    if path.exists():
        old_content = path.read_text(encoding="utf-8")

    if old_content == content:
        return False

    ensure_parent_dir(path)
    path.write_text(content, encoding="utf-8")
    return True


def main() -> int:
    try:
        config = load_config(CONFIG_PATH)
    except Exception as e:
        logger.error("读取配置失败: %s", e)
        return 1

    plugin_meta = config.get("plugin", {})
    output_path = BASE_DIR / plugin_meta.get("output", "dist/merged-adblock.plugin")
    sources = config.get("sources", [])

    if not sources:
        logger.error("未配置任何规则源。")
        return 1

    all_parsed: List[ParsedPlugin] = []

    logger.info("开始处理，共 %d 个源。", len(sources))

    for idx, source in enumerate(sources, start=1):
        name = source.get("name", f"source-{idx}")
        url = source.get("url", "").strip()

        if not url:
            logger.warning("跳过空 URL 源: %s", name)
            continue

        logger.info("正在处理源 [%d/%d]: %s", idx, len(sources), name)
        logger.info("下载地址: %s", url)

        text = get_source_text(source)
        if not text:
            logger.warning("源远程抓取失败且无可用缓存，跳过: %s", name)
            continue

        parsed = parse_plugin_text(text, source_name=name, source_url=url)

        logger.info(
            "解析完成 | %s | URL Rewrite=%d, Script=%d, MITM hostnames=%d, unknown=%d",
            name,
            len(parsed.url_rewrite),
            len(parsed.script),
            len(parsed.mitm_hostnames),
            len(parsed.unknown_sections),
        )

        if parsed.unknown_sections:
            logger.warning(
                "源 %s 存在未识别/未归类内容 %d 条，已保守忽略。",
                name,
                len(parsed.unknown_sections),
            )

        all_parsed.append(parsed)

    if not all_parsed:
        logger.error("所有源均处理失败，未生成最终插件。")
        return 1

    raw_rewrite: List[str] = []
    raw_script: List[str] = []
    raw_mitm: List[str] = []

    for parsed in all_parsed:
        raw_rewrite.extend(parsed.url_rewrite)
        raw_script.extend(parsed.script)
        raw_mitm.extend(parsed.mitm_hostnames)

    logger.info(
        "汇总完成 | 原始数量：URL Rewrite=%d, Script=%d, MITM hostnames=%d",
        len(raw_rewrite),
        len(raw_script),
        len(raw_mitm),
    )

    final_rewrite = dedupe_url_rewrite(raw_rewrite)
    final_script = dedupe_script_rules(raw_script)
    final_mitm = dedupe_mitm_hostnames(raw_mitm)

    logger.info(
        "去重完成 | 最终数量：URL Rewrite=%d, Script=%d, MITM hostnames=%d",
        len(final_rewrite),
        len(final_script),
        len(final_mitm),
    )

    plugin_text = build_plugin_text(
        config=config,
        rewrite_rules=final_rewrite,
        script_rules=final_script,
        mitm_hostnames=final_mitm,
    )

    changed = write_text_if_changed(output_path, plugin_text)

    if changed:
        logger.info("最终插件已生成/更新：%s", output_path)
        logger.info("检测到内容变化。")
    else:
        logger.info("最终插件已生成，但内容无变化：%s", output_path)
        logger.info("未检测到内容变化。")

    return 0


if __name__ == "__main__":
    sys.exit(main())
