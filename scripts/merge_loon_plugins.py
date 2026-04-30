#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import logging
import re
import sys
from dataclasses import dataclass, field
from html import unescape
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "sources.json"

SOURCE_PRIORITY = {
    "local-new-added": 6,
    "yfamilys-adlite": 5,
    "yfamilys-adultraplus": 4,
    "yfamilys-adblock": 3,
    "fmz200-blockads": 2,
    "blackmatrix7-advertising": 1,
}

ACTION_PRIORITY = {
    "reject-200": 100,
    "reject-dict": 95,
    "reject-array": 94,
    "reject-img": 93,
    "reject-empty": 92,
    "reject": 90,
    "302": 80,
    "307": 79,
    "header-replace": 70,
    "body-replace": 69,
}

ACTION_REGEX = r"(reject-200|reject-dict|reject-array|reject-img|reject-empty|reject|302|307|header-replace|body-replace)"

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("loon-merge")


@dataclass
class ParsedPlugin:
    source_name: str
    source_url: str
    url_rewrite: List[str] = field(default_factory=list)
    script: List[str] = field(default_factory=list)
    mitm_hostnames: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)
    unknown_sections: List[str] = field(default_factory=list)


def get_source_priority(source_name: str) -> int:
    return SOURCE_PRIORITY.get(source_name, 0)


def source_include_script(source_name: str, config: dict) -> bool:
    for source in config.get("sources", []):
        if source.get("name") == source_name:
            return bool(source.get("include_script", True))
    return True


def calc_reduce_stats(before: int, after: int) -> str:
    removed = before - after
    percent = 0.0 if before <= 0 else removed / before * 100
    return f"原始={before}, 最终={after}, 去重={removed}, 去重率={percent:.2f}%"


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def normalize_line(line: str) -> str:
    return re.sub(r"[ \t]+", " ", line.strip())


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        raise FileNotFoundError(f"配置文件不存在: {config_path}")
    return json.loads(config_path.read_text(encoding="utf-8"))


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
    return normalize_newlines(text)


def looks_like_html(text: str) -> bool:
    s = text.lstrip().lower()
    return s.startswith("<!doctype html") or s.startswith("<html") or "<body" in s or "<pre" in s


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

            text = normalize_newlines(resp.text)
            if not text:
                return None

            content_type = resp.headers.get("Content-Type", "").lower()
            if "text/html" in content_type or looks_like_html(text):
                text = extract_text_from_html(text)

            return text or None

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
                pass

            text = ""
            pre_nodes = page.locator("pre")
            count = pre_nodes.count()

            if count > 0:
                chunks = []
                for i in range(count):
                    item_text = pre_nodes.nth(i).inner_text(timeout=3000).strip()
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
                return None

            if looks_like_html(text):
                text = extract_text_from_html(text)

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
    local_file = source.get("local_file", "").strip()
    use_browser = bool(source.get("use_browser", False))
    cache_rel = source.get("cache", "").strip()
    cache_path = BASE_DIR / cache_rel if cache_rel else None

    if local_file:
        local_path = BASE_DIR / local_file
        if local_path.exists():
            try:
                text = normalize_newlines(local_path.read_text(encoding="utf-8"))
                if text:
                    logger.info("读取本地规则源成功: %s", local_path)
                    return text
            except Exception as e:
                logger.warning("读取本地规则源失败: %s | %s", local_path, e)

    text = None

    if url:
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


def split_mitm_hostnames(raw_value: str) -> List[str]:
    value = raw_value.strip()
    value = re.sub(r"^hostname\s*=\s*", "", value, flags=re.IGNORECASE).strip()
    value = re.sub(r"^%[A-Z_]+%\s*", "", value, flags=re.IGNORECASE).strip()
    return [item.strip() for item in value.split(",") if item.strip()]


def normalize_section_name(name: str) -> str:
    s = re.sub(r"\s+", " ", name.strip().lower())
    mapping = {
        "url rewrite": "url rewrite",
        "rewrite": "url rewrite",
        "script": "script",
        "mitm": "mitm",
        "host": "mitm",
        "rule": "rule",
        "rules": "rule",
    }
    return mapping.get(s, s)


def is_comment(line: str) -> bool:
    s = line.strip()
    return s.startswith("#") or s.startswith(";") or s.startswith("//")


def looks_like_script_rule(line: str) -> bool:
    s = line.strip().lower()
    return (
        "script-path=" in s
        or s.startswith("http-response ")
        or s.startswith("http-request ")
        or s.startswith("cron ")
    )


def looks_like_rule_line(line: str) -> bool:
    s = line.strip().lower()
    return s.startswith("host,") or s.startswith("host-suffix,")


def looks_like_rewrite_rule(line: str) -> bool:
    s = line.strip()
    if not s or is_comment(s):
        return False

    lower = s.lower()
    return (
        s.startswith("^http")
        or s.startswith("http://")
        or s.startswith("https://")
        or s.startswith("http?:")
        or s.startswith("https?:")
        or " reject" in lower
        or " - reject" in lower
        or "-reject" in lower
        or " 302" in lower
        or " 307" in lower
        or " header-replace" in lower
        or " body-replace" in lower
    )


def parse_plugin_text(text: str, source_name: str, source_url: str) -> ParsedPlugin:
    parsed = ParsedPlugin(source_name=source_name, source_url=source_url)
    current_section: Optional[str] = None

    for raw_line in text.split("\n"):
        line = raw_line.strip()

        if not line:
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

        if current_section == "rule":
            if looks_like_rule_line(line):
                parsed.rules.append(normalize_line(line))
            else:
                parsed.unknown_sections.append(f"[Rule] {line}")
            continue

        if current_section == "mitm":
            parsed.unknown_sections.append(f"[MITM] {line}")
            continue

        if looks_like_script_rule(line):
            parsed.script.append(line)
        elif looks_like_rewrite_rule(line):
            parsed.url_rewrite.append(line)
        elif looks_like_rule_line(line):
            parsed.rules.append(normalize_line(line))
        else:
            parsed.unknown_sections.append(line)

    return parsed


def parse_rewrite_rule(rule: str) -> Tuple[str, str]:
    rule = normalize_line(rule).strip()

    if (rule.startswith('"') and rule.endswith('"')) or (rule.startswith("'") and rule.endswith("'")):
        rule = rule[1:-1].strip()

    m = re.match(
        rf"^(.*?)\s+url\s+-?\s*{ACTION_REGEX}$",
        rule,
        flags=re.IGNORECASE,
    )
    if m:
        pattern = m.group(1).strip().strip('"').strip("'")
        action = m.group(2).strip().lower()
        return pattern, action

    m = re.match(
        rf"^(.*?)\s+-\s*{ACTION_REGEX}$",
        rule,
        flags=re.IGNORECASE,
    )
    if m:
        pattern = m.group(1).strip().strip('"').strip("'")
        action = m.group(2).strip().lower()
        return pattern, action

    m = re.match(
        rf"^(.*?)\s+{ACTION_REGEX}$",
        rule,
        flags=re.IGNORECASE,
    )
    if m:
        pattern = m.group(1).strip().strip('"').strip("'")
        action = m.group(2).strip().lower()
        return pattern, action

    return rule.strip().strip('"').strip("'"), ""


def canonicalize_rewrite(rule: str) -> Optional[Tuple[str, str, str]]:
    pattern, action = parse_rewrite_rule(rule)
    pattern = normalize_line(pattern).strip('"').strip("'")
    action = action.strip().lower()

    if not pattern or not action:
        return None

    normalized_rule = f"{pattern} {action}"
    return pattern, action, normalized_rule


def dedupe_url_rewrite(rule_entries: List[Tuple[str, str]]) -> List[str]:
    best_by_pattern: Dict[str, Dict[str, object]] = {}

    for source_name, rule in rule_entries:
        parsed = canonicalize_rewrite(rule)
        if not parsed:
            continue

        pattern, action, normalized_rule = parsed
        action_score = ACTION_PRIORITY.get(action, 0)
        source_score = get_source_priority(source_name)

        if pattern not in best_by_pattern:
            best_by_pattern[pattern] = {
                "rule": normalized_rule,
                "action": action,
                "action_score": action_score,
                "source_name": source_name,
                "source_score": source_score,
            }
            continue

        old = best_by_pattern[pattern]
        old_action_score = int(old["action_score"])
        old_source_score = int(old["source_score"])

        replace = action_score > old_action_score or (
            action_score == old_action_score and source_score > old_source_score
        )

        if replace:
            logger.info(
                "URL Rewrite 去重：保留更优规则 | %s (%s/%s) -> %s (%s/%s)",
                old["rule"],
                old["action"],
                old["source_name"],
                normalized_rule,
                action,
                source_name,
            )
            best_by_pattern[pattern] = {
                "rule": normalized_rule,
                "action": action,
                "action_score": action_score,
                "source_name": source_name,
                "source_score": source_score,
            }

    final_seen = set()
    final_rules = []

    for item in best_by_pattern.values():
        rule = str(item["rule"])
        parsed = canonicalize_rewrite(rule)
        if not parsed:
            continue

        pattern, action, normalized_rule = parsed
        key = (pattern, action)

        if key in final_seen:
            continue

        final_seen.add(key)
        final_rules.append(normalized_rule)

    return final_rules


def parse_script_identity(rule: str) -> str:
    canon = normalize_line(rule)
    pattern_match = re.search(r"^(.*?)\s+script-path=", canon, flags=re.IGNORECASE)
    path_match = re.search(r"script-path=([^\s,]+)", canon, flags=re.IGNORECASE)

    if pattern_match and path_match:
        pattern = pattern_match.group(1).strip()
        script_path = path_match.group(1).strip()
        return f"{pattern} | script-path={script_path}"

    return canon


def dedupe_script_rules(rule_entries: List[Tuple[str, str]]) -> List[str]:
    best_by_identity: Dict[str, Dict[str, object]] = {}

    for source_name, rule in rule_entries:
        normalized = normalize_line(rule)
        identity = parse_script_identity(normalized)
        source_score = get_source_priority(source_name)

        if identity not in best_by_identity:
            best_by_identity[identity] = {
                "rule": normalized,
                "source_name": source_name,
                "source_score": source_score,
            }
            continue

        old = best_by_identity[identity]

        if source_score > int(old["source_score"]):
            logger.info(
                "Script 去重：保留更高优先级来源 | %s (%s) -> %s (%s)",
                old["rule"],
                old["source_name"],
                normalized,
                source_name,
            )
            best_by_identity[identity] = {
                "rule": normalized,
                "source_name": source_name,
                "source_score": source_score,
            }

    return [str(v["rule"]) for v in best_by_identity.values()]


def dedupe_mitm_hostnames(host_entries: List[Tuple[str, str]]) -> List[str]:
    best_by_host: Dict[str, Dict[str, object]] = {}

    for source_name, host in host_entries:
        canon = host.strip().lower()
        if not canon:
            continue

        source_score = get_source_priority(source_name)

        if canon not in best_by_host:
            best_by_host[canon] = {
                "host": canon,
                "source_name": source_name,
                "source_score": source_score,
            }
            continue

        old = best_by_host[canon]

        if source_score > int(old["source_score"]):
            logger.info(
                "MITM 去重：保留更高优先级来源 | %s (%s -> %s)",
                canon,
                old["source_name"],
                source_name,
            )
            best_by_host[canon] = {
                "host": canon,
                "source_name": source_name,
                "source_score": source_score,
            }

    result = [str(v["host"]) for v in best_by_host.values()]
    result.sort()
    return result


def build_plugin_text(
    config: dict,
    rewrite_rules: List[str],
    script_rules: List[str],
    mitm_hostnames: List[str],
    rules: List[str],
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
    lines.append("# 多源聚合、自动拉取、自动更新")
    lines.append("# 上游来源：")

    for item in sources:
        src_url = item.get("url", "")
        src_local = item.get("local_file", "")
        include_script = item.get("include_script", True)

        if src_local:
            lines.append(
                f"# - {item['name']}: local_file={src_local} | include_script={include_script}"
            )
        else:
            lines.append(
                f"# - {item['name']}: {src_url} | include_script={include_script}"
            )

    lines.append("# 来源优先级：local-new-added > yfamilys-adlite > yfamilys-adultraplus > yfamilys-adblock > fmz200-blockads > blackmatrix7-advertising")
    lines.append("# ============================================")
    lines.append("")

    lines.append("[URL Rewrite]")
    lines.extend(rewrite_rules or ["# 无可用 URL Rewrite 规则"])
    lines.append("")

    lines.append("[Script]")
    lines.extend(script_rules or ["# 无可用 Script 规则"])
    lines.append("")

    lines.append("[Rule]")
    lines.extend(rules or ["# 无可用 Rule 规则"])
    lines.append("")

    lines.append("[MITM]")
    if mitm_hostnames:
        lines.append(f"hostname = %APPEND% {', '.join(mitm_hostnames)}")
    else:
        lines.append("# 无可用 MITM hostname")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_text_if_changed(path: Path, content: str) -> bool:
    old_content = path.read_text(encoding="utf-8") if path.exists() else None

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
        local_file = source.get("local_file", "").strip()

        if not url and not local_file:
            logger.warning("跳过空源（既无 url 也无 local_file）: %s", name)
            continue

        logger.info("正在处理源 [%d/%d]: %s", idx, len(sources), name)

        if local_file:
            logger.info("本地文件: %s", local_file)

        if url:
            logger.info("下载地址: %s", url)

        text = get_source_text(source)

        if not text:
            logger.warning("源远程抓取失败且无可用缓存/本地文件，跳过: %s", name)
            continue

        parsed = parse_plugin_text(text, source_name=name, source_url=url)

        logger.info(
            "解析完成 | %s | URL Rewrite=%d, Script=%d, Rule=%d, MITM hostnames=%d, unknown=%d",
            name,
            len(parsed.url_rewrite),
            len(parsed.script),
            len(parsed.rules),
            len(parsed.mitm_hostnames),
            len(parsed.unknown_sections),
        )

        all_parsed.append(parsed)

    if not all_parsed:
        logger.error("所有源均处理失败，未生成最终插件。")
        return 1

    raw_rewrite: List[Tuple[str, str]] = []
    raw_script: List[Tuple[str, str]] = []
    raw_mitm: List[Tuple[str, str]] = []
    raw_rules: List[str] = []

    for parsed in all_parsed:
        raw_rewrite.extend((parsed.source_name, rule) for rule in parsed.url_rewrite)

        if source_include_script(parsed.source_name, config):
            raw_script.extend((parsed.source_name, rule) for rule in parsed.script)
        else:
            logger.info(
                "已按配置跳过 Script | source=%s | Script=%d",
                parsed.source_name,
                len(parsed.script),
            )

        raw_mitm.extend((parsed.source_name, host) for host in parsed.mitm_hostnames)
        raw_rules.extend(parsed.rules)

    raw_rules_before = len(raw_rules)
    raw_rules = list(dict.fromkeys(raw_rules))

    logger.info(
        "汇总完成 | 原始数量：URL Rewrite=%d, Script=%d, Rule=%d, MITM hostnames=%d",
        len(raw_rewrite),
        len(raw_script),
        raw_rules_before,
        len(raw_mitm),
    )

    final_rewrite = dedupe_url_rewrite(raw_rewrite)
    final_script = dedupe_script_rules(raw_script)
    final_mitm = dedupe_mitm_hostnames(raw_mitm)

    logger.info("去重完成 | URL Rewrite | %s", calc_reduce_stats(len(raw_rewrite), len(final_rewrite)))
    logger.info("去重完成 | Script      | %s", calc_reduce_stats(len(raw_script), len(final_script)))
    logger.info("去重完成 | Rule        | %s", calc_reduce_stats(raw_rules_before, len(raw_rules)))
    logger.info("去重完成 | MITM        | %s", calc_reduce_stats(len(raw_mitm), len(final_mitm)))

    total_before = len(raw_rewrite) + len(raw_script) + raw_rules_before + len(raw_mitm)
    total_after = len(final_rewrite) + len(final_script) + len(raw_rules) + len(final_mitm)

    logger.info("去重完成 | 总计        | %s", calc_reduce_stats(total_before, total_after))

    plugin_text = build_plugin_text(
        config=config,
        rewrite_rules=final_rewrite,
        script_rules=final_script,
        mitm_hostnames=final_mitm,
        rules=raw_rules,
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
