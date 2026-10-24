#!/usr/bin/env python3
"""Static validator for Surge module files (.sgmodule).

Checks the things that actually make Surge refuse to install or silently
misbehave. Run it before handing any .sgmodule to a user.

Usage:
    python validate_sgmodule.py path/to/Module.sgmodule [more.sgmodule ...]
    python validate_sgmodule.py --json path/to/Module.sgmodule

Exit code 0 when there is no ERROR, 1 otherwise. WARN/INFO do not fail the run
unless --strict is given.

Rules encoded here come from:
  https://manual.nssurge.com/profile/module.html
  https://manual.nssurge.com/profile/format.html
  https://manual.nssurge.com/scripting/overview.html
  https://manual.nssurge.com/rules/overview.html
plus field observations from ~540 public modules. See
references/module-arguments-and-testing.md in this skill.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

# Sections a module is allowed to contribute / patch.
MODULE_SECTIONS = {
    "General",
    "MITM",
    "Rule",
    "Script",
    "URL Rewrite",
    "Header Rewrite",
    "Body Rewrite",
    "Map Local",
    "Host",
    "Panel",
}

# Sections whose name starts with one of these prefixes are also allowed.
MODULE_SECTION_PREFIXES = ("WireGuard ", "Ruleset ", "Tailscale ")

# Sections that exist in a profile but can never come from a module.
FORBIDDEN_SECTIONS = {
    "Proxy",
    "Proxy Group",
    "SSID Setting",
    "Ponte",
    "Port Forwarding",
    "Testing",
    "DHCP",
    "Snell Server",
    "MTProto",
    "Keystore",
}

# Policies a module rule may use (internal policies only).
MODULE_RULE_POLICIES = {
    "DIRECT",
    "REJECT",
    "REJECT-TINYGIF",
    "REJECT-DROP",
    "REJECT-NO-DROP",
}

# Documented metadata headers.
DOCUMENTED_HEADERS = {
    "#!name",
    "#!desc",
    "#!system",
    "#!arguments",
    "#!arguments-desc",
    "#!requirement",
}

# Widely used community headers (accepted in practice, not in the manual).
COMMUNITY_HEADERS = {
    "#!author",
    "#!auther",
    "#!homepage",
    "#!icon",
    "#!category",
    "#!date",
    "#!version",
    "#!repo",
    "#!tag",
    "#!openUrl",
    "#!open",
    "#!manual",
    "#!howto",
    "#!system_version",
    # Loon leftovers frequently seen after converting Loon plugins.
    "#!loon_version",
}

SCRIPT_TYPES = {
    "http-request",
    "http-response",
    "rule",
    "dns",
    "event",
    "cron",
    "generic",
}

KNOWN_EVENTS = {
    "network-changed",
    "notification",
    "engine-started",
    "profile-reloaded",
}

PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
PLACEHOLDER_RE = re.compile(r"\{\{\{(.*?)\}\}\}")
ANY_BRACE_RE = re.compile(r"\{\{|\}\}")

# Line-requirement prefixes that gate a whole line. Surge recognises these at
# the start of a line (or as a trailing //!REQUIREMENT comment). Documented in
# profile/requirement.html; PROFILE-VERSION-REQUIRED is the older form and is no
# longer in the manual (the release-note page it pointed at now 404s), so it is
# reported as INFO rather than assumed broken.
LINE_REQ_START = re.compile(
    r"^#!(REQUIREMENT|IOS-ONLY|MACOS-ONLY|TVOS-ONLY|PROFILE-VERSION-REQUIRED)\b[ \t]*"
)
LINE_REQ_END = re.compile(
    r"[ \t]*(?://|;)[ \t]*!(REQUIREMENT|IOS-ONLY|MACOS-ONLY|TVOS-ONLY|"
    r"PROFILE-VERSION-REQUIRED)\b[ \t]*.*$"
)
LEGACY_REQ = "PROFILE-VERSION-REQUIRED"


def split_line_requirement(line: str) -> tuple[str, str | None]:
    """Split '<requirement prefix> <content>' / '<content> //!REQUIREMENT <expr>'.

    Returns (content, directive_name_or_None). The content is what Surge would
    actually parse once the requirement gate is evaluated.
    """
    directive = None
    rest = line

    m = LINE_REQ_END.search(rest)
    if m:
        directive = m.group(1)
        rest = rest[: m.start()].rstrip()

    m = LINE_REQ_START.match(rest)
    if m:
        directive = directive or m.group(1)
        tail = rest[m.end():].lstrip()
        if m.group(1) == "REQUIREMENT":
            if tail[:1] in "\"'":
                quote = tail[0]
                end = tail.find(quote, 1)
                tail = tail[end + 1:].lstrip() if end != -1 else tail
            else:
                _, _, tail = tail.partition(" ")
                tail = tail.lstrip()
        elif m.group(1) == LEGACY_REQ:
            # '#!PROFILE-VERSION-REQUIRED 10 <content>'
            _, _, tail = tail.partition(" ")
            tail = tail.lstrip()
        rest = tail

    return rest, directive

# Keys that must be a boolean.
BOOLEAN_SCRIPT_KEYS = {
    "requires-body",
    "binary-body-mode",
    "full-header-mode",
    "wake-system",
    "debug",
}


@dataclass
class Finding:
    level: str  # ERROR | WARN | INFO
    line: int
    message: str


@dataclass
class Module:
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    header_lines: dict[str, int] = field(default_factory=dict)
    arguments: list[tuple[str, str]] = field(default_factory=list)
    sections: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def add(self, level: str, line: int, message: str) -> None:
        self.findings.append(Finding(level, line, message))


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------


def strip_comment(line: str) -> str:
    """Remove an inline comment that starts at a token boundary."""
    out = line
    for marker in (" //", " #", " ;", "\t//", "\t#", "\t;"):
        idx = out.find(marker)
        if idx != -1:
            out = out[:idx]
    return out


def split_top_level(value: str, sep: str = ",") -> list[str]:
    """Split on `sep` while respecting double/single quotes."""
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    for ch in value:
        if quote is not None:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            continue
        if ch == sep:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts]


def unquote(value: str) -> tuple[str, bool]:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1], True
    return v, False


def parse_script_line(line: str) -> tuple[str, list[tuple[str, str]]]:
    """Return (name, [(key, value), ...]) for a [Script]/[Panel] line."""
    name, _, rest = line.partition("=")
    params: list[tuple[str, str]] = []
    for chunk in split_top_level(rest):
        if not chunk:
            continue
        key, _, value = chunk.partition("=")
        params.append((key.strip().lower(), value.strip()))
    return name.strip(), params


def is_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def load_module(path: str) -> Module:
    mod = Module(path=path)
    current: str | None = None
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        raw_lines = fh.read().splitlines()

    for lineno, raw in enumerate(raw_lines, start=1):
        if raw.rstrip() != raw:
            mod.add("WARN", lineno, "trailing whitespace")
        if "\t" in raw:
            mod.add("WARN", lineno, "contains a TAB character; use spaces")
        line = raw.strip()
        if not line:
            continue

        if line.startswith("#!"):
            key, sep, value = line.partition("=")
            key = key.strip()
            if current is not None:
                # Inside a section a '#!' line is normally a comment, EXCEPT for
                # the documented line-requirement forms, which gate the rest of
                # the line. Handle both instead of blindly skipping.
                content, directive = split_line_requirement(line)
                if directive and content:
                    if directive == LEGACY_REQ:
                        mod.add(
                            "INFO",
                            lineno,
                            "line is gated by the legacy #!"
                            + LEGACY_REQ
                            + " directive. Surge's current manual no longer "
                            "documents it (the release-note page 404s), so verify "
                            "on-device that the line is actually active. The "
                            "documented equivalent is #!REQUIREMENT "
                            "CORE_VERSION>=<n>.",
                        )
                    line = content
                    mod.sections[current].append((lineno, line))
                    continue
                mod.add(
                    "ERROR",
                    lineno,
                    "line starts with #! inside [" + current + "]; Surge treats it "
                    "as a comment, so this line has no effect. Common cause: a "
                    "directive was left in front of a real entry — delete the "
                    "#! prefix.",
                )
                continue
            mod.headers[key] = value.strip()
            mod.header_lines[key] = lineno
            if not sep:
                if key in DOCUMENTED_HEADERS:
                    mod.add("ERROR", lineno, "metadata header " + key + " has no '=' value")
                else:
                    mod.add(
                        "WARN",
                        lineno,
                        "line " + key + " has no '=' value and is not a known "
                        "metadata header; Surge ignores it (treat it as a comment)",
                    )
            if key not in DOCUMENTED_HEADERS and key not in COMMUNITY_HEADERS:
                mod.add(
                    "INFO",
                    lineno,
                    "unknown metadata header " + key + "; Surge ignores it",
                )
            continue

        if line[0] in "#;":
            continue
        if line.startswith("//"):
            continue

        m = re.match(r"^\[(.+?)\]\s*$", line)
        if m:
            current = m.group(1).strip()
            mod.sections.setdefault(current, [])
            if current not in MODULE_SECTIONS and not current.startswith(
                MODULE_SECTION_PREFIXES
            ):
                if current in FORBIDDEN_SECTIONS or current.lower() in {
                    s.lower() for s in FORBIDDEN_SECTIONS
                }:
                    mod.add(
                        "ERROR",
                        lineno,
                        f"[{current}] can never be contributed by a module",
                    )
                else:
                    mod.add(
                        "WARN",
                        lineno,
                        f"[{current}] is not a module-patchable section "
                        f"(allowed: {', '.join(sorted(MODULE_SECTIONS))} "
                        f"+ 'WireGuard *'/'Ruleset *'/'Tailscale *')",
                    )
            continue

        if current is None:
            mod.add(
                "ERROR",
                lineno,
                "content outside any section (only #! metadata may precede the first section)",
            )
            continue

        # Drop trailing inline comments before storing the entry, so parsers
        # below see only real content. strip_comment only cuts at a delimiter
        # preceded by whitespace, so values like COLOR:#FFB6C1 survive.
        cleaned = strip_comment(line).strip()
        if not cleaned:
            continue
        mod.sections[current].append((lineno, cleaned))

    return mod


def check_metadata(mod: Module) -> None:
    if "#!name" not in mod.headers:
        mod.add(
            "ERROR",
            0,
            "missing required header #!name. A file without #!name cannot be "
            "installed as a module; if this is a section fragment meant to be "
            "pulled in with #!include, rename it (e.g. .dconf) instead of "
            ".sgmodule.",
        )
    elif not mod.headers["#!name"]:
        mod.add("ERROR", mod.header_lines.get("#!name", 0), "#!name is empty")
    if "#!desc" not in mod.headers:
        mod.add(
            "ERROR",
            0,
            "missing required header #!desc (single line; put first-use steps here)",
        )
    elif not mod.headers["#!desc"]:
        mod.add("ERROR", mod.header_lines.get("#!desc", 0), "#!desc is empty")

    if "#!system" in mod.headers:
        value = mod.headers["#!system"].strip().lower()
        if value not in {"ios", "mac", "macos", "tvos", "ios, mac", "mac, ios"}:
            mod.add(
                "WARN",
                mod.header_lines["#!system"],
                f"#!system={value!r} is unusual; expected ios / mac / tvos",
            )

    if "#!requirement" in mod.headers:
        expr = mod.headers["#!requirement"]
        if not re.search(r"CORE_VERSION|SYSTEM|DEVICE_MODEL|LANGUAGE|DEVICE_NAME", expr):
            mod.add(
                "WARN",
                mod.header_lines["#!requirement"],
                "#!requirement does not reference any known variable",
            )
        if re.search(r"==?\s*'[^']*'", expr) is None and "==" in expr:
            mod.add(
                "WARN",
                mod.header_lines["#!requirement"],
                "string comparisons in #!requirement should use single quotes",
            )

    if "#!arguments" in mod.headers and "#!name" in mod.headers:
        pass  # handled in check_arguments


def check_arguments(mod: Module) -> None:
    if "#!arguments" not in mod.headers:
        if "#!arguments-desc" in mod.headers:
            mod.add(
                "WARN",
                mod.header_lines["#!arguments-desc"],
                "#!arguments-desc present without #!arguments",
            )
        return

    lineno = mod.header_lines["#!arguments"]
    raw = mod.headers["#!arguments"]
    seen: set[str] = set()

    for chunk in split_top_level(raw):
        if not chunk:
            mod.add("ERROR", lineno, "empty parameter declaration (stray comma)")
            continue
        name, sep, value = chunk.partition(":")
        name = name.strip()
        value = value.strip()

        if not sep:
            mod.add(
                "ERROR",
                lineno,
                f"parameter {name!r} has no default value; a bare name fails at load "
                f'with: The value of argument "{name}" is not found.',
            )
            mod.arguments.append((name, ""))
            continue

        if value == "":
            mod.add(
                "ERROR",
                lineno,
                f"parameter {name!r} has an empty default; Surge rejects the header "
                f"with: 模块头部的参数声明格式错误：{name}：",
            )

        if not PARAM_NAME_RE.match(name):
            mod.add(
                "WARN",
                lineno,
                f"parameter name {name!r} is outside the documented "
                f"^[A-Za-z0-9_]+$ subset. Hyphens, brackets and Chinese names do "
                f"work in current builds (widely used in the wild) but are not "
                f"documented; rename to ASCII letters/digits/underscores unless you "
                f"are deliberately matching an existing public module.",
            )

        if name in seen:
            mod.add("WARN", lineno, f"duplicate parameter name {name!r}")
        seen.add(name)
        mod.arguments.append((name, unquote(value)[0]))

    # Observed in widely deployed modules but not allowed by the manual: report
    # once, as INFO, so the author can make a conscious choice.
    off_spec = [
        n
        for n, _ in mod.arguments
        if not PARAM_NAME_RE.match(n) and re.search(r"[A-Za-z0-9_]", n)
    ]
    if off_spec:
        mod.add(
            "INFO",
            lineno,
            f"parameter name(s) outside the documented ^[A-Za-z0-9_]+$ subset: "
            f"{', '.join(off_spec)}. Hyphens and brackets work in practice but are "
            f"not documented; prefer underscores for anything you publish.",
        )

    # Placeholder cross-check.
    declared = {n for n, _ in mod.arguments}
    used: dict[str, int] = {}
    for section, entries in mod.sections.items():
        for line_no, line in entries:
            for ph in PLACEHOLDER_RE.findall(line):
                used.setdefault(ph, line_no)

    for ph, line_no in used.items():
        if ph not in declared:
            mod.add(
                "ERROR",
                line_no,
                f"placeholder {{{{{ph}}}}} is used but never declared in #!arguments",
            )
    for name in declared:
        if name not in used:
            mod.add(
                "WARN",
                lineno,
                f"parameter {name!r} is declared but never referenced "
                f"(remove it or use it)",
            )

    for section, entries in mod.sections.items():
        for line_no, line in entries:
            if ANY_BRACE_RE.search(line) and not PLACEHOLDER_RE.search(line):
                mod.add(
                    "ERROR",
                    line_no,
                    "malformed placeholder: placeholders need exactly three braces "
                    "on each side, e.g. {{{NAME}}}",
                )

    if "#!arguments-desc" in mod.headers:
        desc = mod.headers["#!arguments-desc"]
        if "\n" in desc:
            mod.add(
                "WARN",
                mod.header_lines["#!arguments-desc"],
                "#!arguments-desc contains a real newline; use the literal two "
                r"characters \n instead",
            )
        for name in declared:
            if name not in desc and name.lower() not in desc.lower():
                mod.add(
                    "INFO",
                    mod.header_lines["#!arguments-desc"],
                    f"#!arguments-desc does not mention parameter {name!r}",
                )


def substitute(line: str, args: list[tuple[str, str]]) -> str:
    """Replace placeholders with their default values for further checking."""
    out = line
    for name, value in args:
        out = out.replace("{{{ %s }}}" % name, value)
        out = out.replace("{{{ %s}}}" % name, value)
        out = out.replace("{{{ %s }}}" % name, value)
        out = out.replace("{{{%s}}}" % name, value)
    return out


def check_scripts(mod: Module) -> None:
    entries = mod.sections.get("Script", [])
    names: set[str] = set()
    for lineno, line in entries:
        name, params = parse_script_line(line)
        if not name:
            mod.add("ERROR", lineno, "[Script] line has no script name")
            continue
        if name in names:
            mod.add(
                "WARN",
                lineno,
                f"duplicate script name {name!r}; the later line wins, which is "
                f"rarely what the author intended",
            )
        names.add(name)

        kv = dict(params)
        stype = kv.get("type", "generic")
        if stype not in SCRIPT_TYPES:
            mod.add(
                "ERROR",
                lineno,
                f"unknown script type {stype!r}; Surge rejects the whole line",
            )
        if "script-path" not in kv:
            mod.add("ERROR", lineno, "missing required parameter script-path")
        path_value = kv.get("script-path", "").strip().strip('"')
        remote = path_value.startswith(("http://", "https://"))

        if stype in {"http-request", "http-response"}:
            if "pattern" not in kv:
                mod.add(
                    "ERROR",
                    lineno,
                    f"{stype} requires a pattern (the regex is matched against the URL)",
                )
            else:
                pattern = unquote(kv["pattern"])[0]
                try:
                    re.compile(pattern)
                except re.error as exc:
                    mod.add("ERROR", lineno, f"pattern is not a valid regex: {exc}")
                if pattern in {".*", "^.*$", "^https?://.*", ".*"}:
                    mod.add(
                        "WARN",
                        lineno,
                        "pattern matches everything; narrow it down",
                    )
        if stype == "cron":
            if "cronexp" not in kv:
                mod.add("ERROR", lineno, "cron script requires cronexp")
            else:
                expr = unquote(kv["cronexp"])[0]
                if "{{{" in expr:
                    expr = substitute(expr, mod.arguments)
                fields = expr.split()
                if len(fields) not in (5, 6):
                    mod.add(
                        "ERROR",
                        lineno,
                        f"cronexp has {len(fields)} fields; expected 5 (or 6 with a "
                        f"leading seconds field): {expr!r}",
                    )
        if stype == "event":
            if "event-name" not in kv:
                mod.add(
                    "ERROR",
                    lineno,
                    "event script without event-name never runs",
                )
            elif unquote(kv["event-name"])[0] not in KNOWN_EVENTS:
                mod.add(
                    "WARN",
                    lineno,
                    f"event-name {kv['event-name']!r} is not one of "
                    f"{sorted(KNOWN_EVENTS)}",
                )

        for key in BOOLEAN_SCRIPT_KEYS:
            if key in kv and kv[key].strip().lower() not in {
                "0",
                "1",
                "true",
                "false",
                "",
            }:
                mod.add(
                    "WARN",
                    lineno,
                    f"{key}={kv[key]!r} is not a boolean",
                )

        if "requires-body" in kv and is_truthy(kv["requires-body"]):
            if "max-size" not in kv:
                mod.add(
                    "INFO",
                    lineno,
                    "requires-body set without max-size; default is 1 MB on iOS / "
                    "10 MB on macOS",
                )

        if remote and "script-update-interval" not in kv:
            mod.add(
                "INFO",
                lineno,
                "remote script-path without script-update-interval "
                "(default 86400 s); set it explicitly for clarity",
            )

        if remote and is_truthy(kv.get("debug", "false")):
            mod.add(
                "ERROR",
                lineno,
                "debug=true on a remote script-path: Surge re-downloads the script "
                "before every run, so a transient network failure breaks the task",
            )

        if "argument" in kv:
            value = kv["argument"]
            if value and not (value.startswith('"') and value.endswith('"')):
                if " " in value:
                    mod.add(
                        "WARN",
                        lineno,
                        "argument contains spaces; wrap the whole value in double "
                        'quotes: argument="a={{{A}}} b={{{B}}}"',
                    )
                elif "&" in value:
                    mod.add(
                        "INFO",
                        lineno,
                        'argument uses & without quotes. This works, but quoting '
                        'the whole value (argument="a={{{A}}}&b={{{B}}}") is the '
                        "form shown in the manual and is safer when a value may "
                        "contain spaces.",
                    )

        # A single-brace placeholder is a common typo for a module parameter.
        # Surge substitutes nothing, so the literal text is passed through and
        # the line silently misbehaves (e.g. cronexp={TimingParameters}).
        for key, value in params:
            if key in {"script-path", "pattern", "argument", "type"}:
                continue
            bare = value.strip().strip("\"'")
            if re.fullmatch(r"\{[A-Za-z0-9_.\-]+\}", bare):
                inner = bare.strip("{}")
                suggestion = "{{{" + inner + "}}}"
                mod.add(
                    "ERROR",
                    lineno,
                    key
                    + "="
                    + value
                    + " looks like a module parameter written with single braces. "
                    + "Surge substitutes nothing and passes the literal text "
                    + "through; use triple braces: "
                    + suggestion,
                )

    # SCRIPT rule references must resolve to a declared script.
    for lineno, line in mod.sections.get("Rule", []):
        effective = substitute(line, mod.arguments)
        if effective.upper().startswith("SCRIPT,"):
            parts = split_top_level(effective)
            if len(parts) >= 2:
                ref = parts[1].strip()
                if ref not in names:
                    mod.add(
                        "ERROR",
                        lineno,
                        f"SCRIPT rule references unknown script name {ref!r}; "
                        f"profile verification fails",
                    )

    # [Host] script references must resolve too.
    for lineno, line in mod.sections.get("Host", []):
        if "script:" in line:
            ref = line.split("script:", 1)[1].strip()
            if ref not in names:
                mod.add(
                    "ERROR",
                    lineno,
                    f"[Host] entry references unknown script name {ref!r}",
                )

    # [Panel] script-name references must resolve too.
    for lineno, line in mod.sections.get("Panel", []):
        _, params = parse_script_line(line)
        kv = dict(params)
        if "script-name" in kv:
            ref = unquote(kv["script-name"])[0]
            if ref not in names:
                mod.add(
                    "ERROR",
                    lineno,
                    f"[Panel] script-name references unknown script {ref!r}",
                )
        if "update-interval" not in kv and "script-name" in kv:
            mod.add(
                "INFO",
                lineno,
                "panel has a script but no update-interval; it will only refresh "
                "when the user taps refresh",
            )
        if "style" in kv and unquote(kv["style"])[0] not in {
            "good",
            "info",
            "alert",
            "error",
        }:
            mod.add(
                "WARN",
                lineno,
                f"panel style {kv['style']!r} should be good/info/alert/error",
            )


def rule_policy(parts: list[str]) -> str:
    """Extract the policy token from an already comma-split rule line.

    Handles logical rules, whose value contains commas inside balanced
    parentheses, e.g. AND,((DOMAIN,a.com),(DEST-PORT,443)),REJECT,pre-matching
    """
    depth = 0
    for idx, token in enumerate(parts):
        depth += token.count("(") - token.count(")")
        if depth == 0 and idx > 0:
            nxt = parts[idx + 1].strip() if idx + 1 < len(parts) else ""
            if nxt and "=" not in nxt and nxt.upper() not in {
                "NO-RESOLVE",
                "DNS-FAILED",
                "EXTENDED-MATCHING",
                "PRE-MATCHING",
                "REQUIRES-RESOLVE",
            }:
                return nxt
            return ""
    return ""


def check_rules(mod: Module) -> None:
    for lineno, line in mod.sections.get("Rule", []):
        effective = substitute(line, mod.arguments)
        parts = split_top_level(effective)
        if not parts:
            continue
        rtype = parts[0].strip().upper()
        if rtype in {"FINAL", "SCRIPT"}:
            continue
        policy = rule_policy(parts)
        raw_policy = rule_policy(split_top_level(line))
        if not policy:
            mod.add("WARN", lineno, f"rule line has no resolvable policy: {line}")
            continue
        if policy.upper() in MODULE_RULE_POLICIES:
            continue

        # A placeholder in the policy position is a legitimate and widely used
        # pattern (e.g. `DOMAIN-SUFFIX,x.com,{{{Proxy}}}` with
        # `#!arguments=Proxy:你的策略组`): the user replaces it in the parameter
        # editor. The manual still restricts module rules to internal policies,
        # so warn rather than fail, and make the trade-off explicit.
        if "{{{" in raw_policy or "{{{" in line:
            mod.add(
                "WARN",
                lineno,
                "policy is a parameter placeholder (" + raw_policy.strip() + "). "
                "This pattern is used by public modules, but the manual restricts "
                "module rules to internal policies ("
                + ", ".join(sorted(MODULE_RULE_POLICIES))
                + "). Document in #!arguments-desc that the user must fill in a "
                "valid policy, and that DIRECT disables the split.",
            )
            continue

        mod.add(
            "ERROR",
            lineno,
            "module rules may only use internal policies ("
            + ", ".join(sorted(MODULE_RULE_POLICIES))
            + "); found "
            + repr(policy),
        )


def check_rewrites(mod: Module) -> None:
    for lineno, line in mod.sections.get("URL Rewrite", []):
        parts = line.rsplit(None, 1)
        if len(parts) < 2:
            mod.add("ERROR", lineno, "URL Rewrite line needs '<regex> <replacement> [type]'")
            continue
        try:
            re.compile(split_top_level(line)[0].strip())
        except re.error:
            # The regex may contain spaces; only flag if it cannot compile at all.
            mod.add("INFO", lineno, "could not verify URL Rewrite regex (contains spaces)")

    for lineno, line in mod.sections.get("Header Rewrite", []):
        tokens = line.split()
        actions = [t for t in tokens if t.startswith("header-")]
        if not actions:
            mod.add(
                "ERROR",
                lineno,
                "Header Rewrite line has no header-add/header-del/header-replace/"
                "header-replace-regex action",
            )
        if "header-del" in actions and len(tokens) < 3:
            mod.add("WARN", lineno, "header-del needs a header field name")

    for lineno, line in mod.sections.get("Body Rewrite", []):
        if not re.match(r"^http-(request|response)(-jq)?\s", line):
            mod.add(
                "ERROR",
                lineno,
                "Body Rewrite line must start with http-request / http-response / "
                "http-request-jq / http-response-jq",
            )

    for lineno, line in mod.sections.get("Map Local", []):
        if not any(
            tok.startswith(("data-type=", "data=", "status-code=", "header="))
            for tok in line.split()
        ):
            mod.add(
                "WARN",
                lineno,
                "Map Local line has no data/data-type/status-code/header parameter",
            )
        for m in re.finditer(r"status-code=(\S+)", line):
            try:
                code = int(m.group(1))
            except ValueError:
                mod.add("ERROR", lineno, f"status-code {m.group(1)!r} is not a number")
                continue
            if not 200 <= code <= 999:
                mod.add(
                    "ERROR",
                    lineno,
                    f"status-code {code} is out of range (200-999)",
                )


def check_mitm(mod: Module) -> None:
    for lineno, line in mod.sections.get("MITM", []):
        key, _, value = line.partition("=")
        key = key.strip().lower()
        if PLACEHOLDER_RE.search(key):
            # Parameterised key: users disable the whole line by setting the
            # parameter to '#'. Legitimate and common.
            mod.add(
                "INFO",
                lineno,
                f"[MITM] line key is a placeholder ({key}); confirm the declared "
                f"default is a valid key name such as 'hostname', and that setting "
                f"it to '#' is documented in #!arguments-desc",
            )
        elif key == "hostname":
            value_up = value.upper()
            has_append = "%APPEND%" in value_up
            has_insert = "%INSERT%" in value_up
            has_exclusion = re.search(r"(?:^|,\s*)-\S", value) is not None
            if not has_append and not has_insert:
                if has_exclusion:
                    mod.add(
                        "ERROR",
                        lineno,
                        "[MITM] hostname without %INSERT% overwrites the profile's "
                        "list. It also contains exclusion entries (a leading '-'), "
                        "and Host List matching stops at the first hit, so the "
                        "exclusions must come first: use hostname = %INSERT% -a.com, *",
                    )
                else:
                    mod.add(
                        "WARN",
                        lineno,
                        "[MITM] hostname without %APPEND% overwrites the profile's "
                        "list and breaks MITM for every other module; use "
                        "hostname = %APPEND% your.host",
                    )
            elif has_append and has_exclusion:
                mod.add(
                    "WARN",
                    lineno,
                    "[MITM] hostname uses %APPEND% but contains exclusion entries "
                    "(a leading '-'). Host List matching stops at the first hit, so "
                    "the profile's earlier entries win and your exclusions may never "
                    "be reached. Use %INSERT% for exclusions.",
                )
        elif key in {"ca-p12", "ca-passphrase"}:
            mod.add(
                "ERROR",
                lineno,
                "[MITM] ca-p12 / ca-passphrase cannot come from a module",
            )
        elif key not in {"hostname", "hostname-disabled", "skip-server-cert-verify"}:
            mod.add(
                "WARN",
                lineno,
                f"[MITM] key {key!r} is not one of hostname / hostname-disabled / "
                f"skip-server-cert-verify",
            )


def check_general(mod: Module) -> None:
    # Host List typed keys: order decides priority, so the operator matters.
    ORDER_SENSITIVE = {
        "skip-proxy",
        "always-real-ip",
        "force-http-engine-hosts",
        "always-raw-tcp-hosts",
        "hostname",
        "hijack-dns",
    }
    for lineno, line in mod.sections.get("General", []):
        key, _, value = line.partition("=")
        key = key.strip().lower()
        if not value.strip():
            mod.add("ERROR", lineno, f"[General] key {key!r} has no value")
            continue
        value_up = value.upper()
        if key in ORDER_SENSITIVE and "%APPEND%" not in value_up and "%INSERT%" not in value_up:
            mod.add(
                "WARN",
                lineno,
                "[General] "
                + key
                + " replaces the profile's whole list. It is a Host List type, so "
                "items are matched in order and the first hit wins: use %INSERT% "
                "when your entries must take priority, %APPEND% for plain "
                "additions, and a bare value only when replacing the list is "
                "intentional.",
            )


def validate(path: str) -> Module:
    mod = load_module(path)
    check_metadata(mod)
    check_arguments(mod)
    check_scripts(mod)
    check_rules(mod)
    check_rewrites(mod)
    check_mitm(mod)
    check_general(mod)
    mod.findings.sort(key=lambda f: (f.line, f.level))
    return mod


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def report(mod: Module, as_json: bool) -> int:
    order = {"ERROR": 0, "WARN": 1, "INFO": 2}
    errors = [f for f in mod.findings if f.level == "ERROR"]
    warns = [f for f in mod.findings if f.level == "WARN"]
    infos = [f for f in mod.findings if f.level == "INFO"]

    if as_json:
        print(
            json.dumps(
                {
                    "path": mod.path,
                    "name": mod.headers.get("#!name", ""),
                    "sections": sorted(mod.sections),
                    "parameters": [n for n, _ in mod.arguments],
                    "counts": {
                        "error": len(errors),
                        "warn": len(warns),
                        "info": len(infos),
                    },
                    "findings": [f.__dict__ for f in mod.findings],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1 if errors else 0

    print(f"\n=== {mod.path}")
    print(f"    name     : {mod.headers.get('#!name', '(missing)')}")
    print(f"    sections : {', '.join(sorted(mod.sections)) or '(none)'}")
    if mod.arguments:
        print(f"    params   : {', '.join(n for n, _ in mod.arguments)}")
    for f in sorted(mod.findings, key=lambda f: (order[f.level], f.line)):
        loc = f"L{f.line}" if f.line else "--"
        print(f"    [{f.level:5s}] {loc:>6s}  {f.message}")
    if not mod.findings:
        print("    no findings")
    print(
        f"    -> {len(errors)} error(s), {len(warns)} warning(s), {len(infos)} info"
    )
    return 1 if errors else 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help=".sgmodule files to validate")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat warnings as failures too",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    worst = 0
    for path in args.paths:
        mod = validate(path)
        code = report(mod, args.json)
        if code:
            worst = 1
        elif args.strict and any(f.level == "WARN" for f in mod.findings):
            worst = 1
    return worst


if __name__ == "__main__":
    sys.exit(main())
