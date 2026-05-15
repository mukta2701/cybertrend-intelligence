# Mobile-First Digest Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the daily digest renderer for Gmail mobile — adding a "Today in 30 seconds" summary, a top-actions block, and tiered card layouts (Critical=full, High=compact, Medium=list) — so the reader sees what matters in the first screen without scrolling.

**Architecture:** All changes are in `src/cybertrend/email/render.py` and `tests/test_email_rendering.py`. No DB migrations, no LLM prompt changes, no model or ingestion changes. New helper functions are added, `_item_html()` is lightly modified, and `render_daily_digest()` is restructured to use tiered rendering and suppress empty sections.

**Tech Stack:** Python, html.escape, existing Pydantic models (`TrendItem`, `DigestPayload`, `RenderedEmail`)

---

## File Map

| File | What changes |
|---|---|
| `src/cybertrend/email/render.py` | Add `_derive_action_type`, `_derive_timeframe`, `_action_badge`, `_top_summary_bullets`, `_item_compact_html/text`, `_item_minimal_html/text`; modify `_item_html` (action first, `show_vulnerability` param); restructure `render_daily_digest`; fix `_SOURCE_LABELS` and footer |
| `tests/test_email_rendering.py` | Add tests for each new helper and new digest structure |

---

### Task 1: Fix source labels and auto-derive footer

**Files:**
- Modify: `src/cybertrend/email/render.py:9-18` (`_SOURCE_LABELS`) and `render.py:310-318` (footer string)
- Test: `tests/test_email_rendering.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_email_rendering.py`:

```python
from cybertrend.email.render import _SOURCE_LABELS, _source_label


def test_source_label_reddit_pwnhub():
    i = item()
    i = i.model_copy(update={"source_name": "reddit_pwnhub", "community": None})
    assert _source_label(i) == "r/pwnhub"


def test_footer_contains_all_source_labels():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[DigestSection(name="Critical Threats", severity="Critical", items=[item()])],
    )
    message = render_daily_digest(payload)
    for label in _SOURCE_LABELS.values():
        assert label in message.html, f"Footer missing: {label}"
    assert "r/pwnhub" in message.html
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_email_rendering.py::test_source_label_reddit_pwnhub tests/test_email_rendering.py::test_footer_contains_all_source_labels -v
```

Expected: FAIL — `reddit_pwnhub` not in `_SOURCE_LABELS`, footer is hardcoded.

- [ ] **Step 3: Add `reddit_pwnhub` to `_SOURCE_LABELS`**

In `src/cybertrend/email/render.py`, change `_SOURCE_LABELS` to:

```python
_SOURCE_LABELS = {
    "bleepingcomputer": "BleepingComputer",
    "thehackernews": "The Hacker News",
    "krebsonsecurity": "Krebs on Security",
    "sans_isc": "SANS ISC",
    "darkreading": "Dark Reading",
    "securityweek": "SecurityWeek",
    "tenable": "Tenable Research",
    "nvd": "NVD / NIST",
    "reddit_pwnhub": "r/pwnhub",
}
```

- [ ] **Step 4: Auto-derive the footer source string**

In `render_daily_digest()`, find the hardcoded footer string:

```python
'Sources: NVD · Tenable · BleepingComputer · The Hacker News · Krebs · SANS ISC · '
'Dark Reading · SecurityWeek'
```

Replace with:

```python
f'Sources: {escape(" · ".join(_SOURCE_LABELS.values()))}'
```

The full footer block becomes:

```python
footer = (
    '<div style="background:#0f1923;padding:16px 24px;border-radius:0 0 8px 8px;">'
    + quality_html
    + '<p style="margin:0;font-size:11px;color:#4a5568;">'
    f'Cybertrend Intelligence &nbsp;·&nbsp; Automated daily briefing &nbsp;·&nbsp; '
    f'Sources: {escape(" · ".join(_SOURCE_LABELS.values()))}'
    '</p></div>'
)
```

- [ ] **Step 5: Run tests to verify they pass**

```
pytest tests/test_email_rendering.py::test_source_label_reddit_pwnhub tests/test_email_rendering.py::test_footer_contains_all_source_labels -v
```

Expected: PASS

- [ ] **Step 6: Run full test suite to confirm no regressions**

```
pytest tests/test_email_rendering.py -v
```

Expected: all existing tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/cybertrend/email/render.py tests/test_email_rendering.py
git commit -m "feat: add r/pwnhub source label and auto-derive footer from source map"
```

---

### Task 2: Add `_derive_action_type`, `_derive_timeframe`, and `_action_badge`

These are pure helpers used by the summary and top-actions blocks.

**Files:**
- Modify: `src/cybertrend/email/render.py` (add three functions after existing helpers)
- Test: `tests/test_email_rendering.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_email_rendering.py`:

```python
from cybertrend.email.render import _derive_action_type, _derive_timeframe


def test_derive_action_type_patch():
    assert _derive_action_type("Patch to 9.18.4+; restrict management interface.") == "Patch"


def test_derive_action_type_update():
    assert _derive_action_type("Update the firmware to the latest version.") == "Patch"


def test_derive_action_type_monitor():
    assert _derive_action_type("Monitor for unusual outbound connections.") == "Monitor"


def test_derive_action_type_block():
    assert _derive_action_type("Restrict ingress from untrusted networks.") == "Block"


def test_derive_action_type_investigate():
    assert _derive_action_type("Investigate affected hosts for indicators of compromise.") == "Investigate"


def test_derive_action_type_fallback():
    assert _derive_action_type("Consult your vendor for further guidance.") == "Review"


def test_derive_timeframe_kev_flag():
    i = item()  # the existing fixture has kev_flag=True
    assert _derive_timeframe(i) == "Today"


def test_derive_timeframe_no_exploitation():
    i = TrendItem(
        item_id="med-1",
        source_type=SourceType.RSS,
        source_name="securityweek",
        title="Low risk advisory",
        url="https://example.com/low",
        published_at=datetime(2026, 5, 15, 9, 0, tzinfo=timezone.utc),
        kev_flag=False,
        exploit_evidence=None,
        epss_percentile=0.1,
        epss_probability=0.01,
        criticality_score=40,
        severity_label="Medium",
        llm_analysis={
            "headline": "Low risk advisory",
            "affected_assets": "Some product",
            "vulnerability": "Minor flaw",
            "threat": "Limited impact",
            "exploitation_status": "No exploitation reported",
            "organizational_risk": "Low",
            "recommended_action": "Monitor for vendor updates",
            "why_it_matters": "Low priority awareness item",
        },
    )
    assert _derive_timeframe(i) == "Monitor"


def test_derive_timeframe_poc():
    i = TrendItem(
        item_id="high-poc",
        source_type=SourceType.RSS,
        source_name="bleepingcomputer",
        title="PoC for GitLab runner SSRF",
        url="https://example.com/poc",
        published_at=datetime(2026, 5, 15, 9, 0, tzinfo=timezone.utc),
        kev_flag=False,
        exploit_evidence="proof-of-concept published on GitHub",
        epss_percentile=0.5,
        epss_probability=0.3,
        criticality_score=74,
        severity_label="High",
        llm_analysis={
            "headline": "GitLab Runner SSRF",
            "affected_assets": "GitLab CE/EE runners",
            "vulnerability": "SSRF via runner job metadata",
            "threat": "Internal network access",
            "exploitation_status": "PoC available",
            "organizational_risk": "Internal services reachable",
            "recommended_action": "Restrict runner network egress",
            "why_it_matters": "PoC lowers barrier to exploitation",
        },
    )
    assert _derive_timeframe(i) == "This week"
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_email_rendering.py::test_derive_action_type_patch tests/test_email_rendering.py::test_derive_timeframe_kev_flag -v
```

Expected: FAIL — functions not yet defined.

- [ ] **Step 3: Add the three helpers to `render.py`**

Add these three functions after the existing `_meta_pill` function (around line 92):

```python
def _action_badge(text: str, bg: str) -> str:
    return (
        f'<span style="display:inline-block;padding:2px 7px;border-radius:3px;'
        f'background:{bg};color:#fff;font-size:10px;font-weight:700;margin-right:4px;">'
        f'{escape(text)}</span>'
    )


def _derive_action_type(action_text: str) -> str:
    text = action_text.lower()
    if any(w in text for w in ("patch", "update", "upgrade")):
        return "Patch"
    if any(w in text for w in ("monitor", "watch")):
        return "Monitor"
    if "investigate" in text:
        return "Investigate"
    if any(w in text for w in ("block", "restrict", "disable")):
        return "Block"
    return "Review"


def _derive_timeframe(item: TrendItem) -> str:
    exploitation = (_derive_exploitation(item) or _llm(item, "exploitation_status", "")).lower()
    if item.kev_flag or "actively exploited" in exploitation:
        return "Today"
    if "poc" in exploitation or "exploitation likely" in exploitation:
        return "This week"
    return "Monitor"
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_email_rendering.py::test_derive_action_type_patch tests/test_email_rendering.py::test_derive_action_type_update tests/test_email_rendering.py::test_derive_action_type_monitor tests/test_email_rendering.py::test_derive_action_type_block tests/test_email_rendering.py::test_derive_action_type_investigate tests/test_email_rendering.py::test_derive_action_type_fallback tests/test_email_rendering.py::test_derive_timeframe_kev_flag tests/test_email_rendering.py::test_derive_timeframe_no_exploitation tests/test_email_rendering.py::test_derive_timeframe_poc -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cybertrend/email/render.py tests/test_email_rendering.py
git commit -m "feat: add _derive_action_type, _derive_timeframe, _action_badge helpers"
```

---

### Task 3: Add `_top_summary_bullets`

Selects top N items by score and builds short imperative bullets for the "Today in 30 seconds" block.

**Files:**
- Modify: `src/cybertrend/email/render.py`
- Test: `tests/test_email_rendering.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_email_rendering.py`:

```python
from cybertrend.email.render import _top_summary_bullets


def test_top_summary_bullets_uses_highest_scored_items():
    high_item = item("High")
    high_item = high_item.model_copy(update={"criticality_score": 50, "item_id": "low-score"})
    critical_item = item("Critical")  # criticality_score=96 from fixture

    bullets = _top_summary_bullets([high_item, critical_item])

    assert len(bullets) >= 1
    # The Critical item (score 96) should appear first
    assert "Cisco ASA" in bullets[0]


def test_top_summary_bullets_falls_back_to_title_when_no_llm():
    i = TrendItem(
        item_id="no-llm",
        source_type=SourceType.RSS,
        source_name="nvd",
        title="CVE-2026-99999 affects Acme product",
        url="https://example.com/cve",
        published_at=datetime(2026, 5, 15, 9, 0, tzinfo=timezone.utc),
        kev_flag=False,
        criticality_score=60,
        severity_label="High",
        llm_analysis=None,
    )
    bullets = _top_summary_bullets([i])
    assert bullets[0] == "CVE-2026-99999 affects Acme product"


def test_top_summary_bullets_respects_n_limit():
    items = [
        item("Critical").model_copy(update={"item_id": f"item-{x}", "criticality_score": 90 - x})
        for x in range(10)
    ]
    bullets = _top_summary_bullets(items, n=3)
    assert len(bullets) == 3
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_email_rendering.py::test_top_summary_bullets_uses_highest_scored_items -v
```

Expected: FAIL — `_top_summary_bullets` not defined.

- [ ] **Step 3: Implement `_top_summary_bullets`**

Add after `_derive_timeframe` in `render.py`:

```python
def _top_summary_bullets(items: Iterable[TrendItem], n: int = 5) -> List[str]:
    sorted_items = sorted(items, key=lambda i: i.criticality_score, reverse=True)[:n]
    bullets = []
    for i in sorted_items:
        action = _derive_action_type(_llm(i, "recommended_action", ""))
        assets = _llm(i, "affected_assets") or i.title
        exploitation = _derive_exploitation(i) or _llm(i, "exploitation_status", "")
        if exploitation:
            bullets.append(f"{action} {assets} — {exploitation}")
        else:
            bullets.append(f"{action} {assets}")
    return bullets
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_email_rendering.py::test_top_summary_bullets_uses_highest_scored_items tests/test_email_rendering.py::test_top_summary_bullets_falls_back_to_title_when_no_llm tests/test_email_rendering.py::test_top_summary_bullets_respects_n_limit -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cybertrend/email/render.py tests/test_email_rendering.py
git commit -m "feat: add _top_summary_bullets for today-in-30-seconds block"
```

---

### Task 4: Add `_item_compact_html` and `_item_compact_text`

The compact card used for High-severity items: headline + exploit badge + action line + meta row.

**Files:**
- Modify: `src/cybertrend/email/render.py`
- Test: `tests/test_email_rendering.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_email_rendering.py`:

```python
from cybertrend.email.render import _item_compact_html, _item_compact_text


def test_item_compact_html_contains_headline_and_action():
    i = item("High")
    html = _item_compact_html(i)

    assert "Cisco ASA" in html
    assert "Patch to 9.18.4" in html
    assert 'href="https://example.com/advisory"' in html


def test_item_compact_html_omits_org_risk_and_vulnerability():
    i = item("High")
    html = _item_compact_html(i)

    assert "Org Risk" not in html
    assert "Vulnerability" not in html
    assert "Unpatched edge firewalls" not in html  # org_risk value from fixture


def test_item_compact_html_shows_score():
    i = item("High")
    html = _item_compact_html(i)
    assert "96/100" in html


def test_item_compact_text_contains_headline_action_link():
    i = item("High")
    text = _item_compact_text(i)

    assert "Cisco ASA" in text
    assert "Patch to 9.18.4" in text
    assert "https://example.com/advisory" in text
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_email_rendering.py::test_item_compact_html_contains_headline_and_action -v
```

Expected: FAIL — `_item_compact_html` not defined.

- [ ] **Step 3: Implement both functions**

Add after `_item_text` in `render.py`:

```python
def _item_compact_html(item: TrendItem) -> str:
    exploitation = _derive_exploitation(item) or _llm(item, "exploitation_status", "Unknown")
    headline = _llm(item, "headline") or item.title
    action = _llm(item, "recommended_action")
    source = _source_label(item)

    return (
        f'<div style="background:#ffffff;border-radius:6px;margin:0 0 8px;'
        f'border:1px solid #e2e8f0;border-left:4px solid #dd6b20;">'
        f'<div style="padding:10px 12px;">'
        f'<div style="display:flex;align-items:flex-start;justify-content:space-between;'
        f'gap:6px;margin-bottom:4px;">'
        f'<a href="{escape(item.url)}" style="font-size:13px;font-weight:700;color:#1a202c;'
        f'text-decoration:none;line-height:1.3;flex:1;">{escape(headline)}</a>'
        f'{_exploit_badge(exploitation)}'
        f'</div>'
        + (
            f'<p style="margin:0 0 4px;font-size:12px;color:#4a5568;line-height:1.4;">'
            f'{escape(_truncate(action))}</p>'
            if action else ''
        )
        + f'<p style="margin:0;font-size:11px;color:#a0aec0;">'
        f'Score {_score(item.criticality_score)}/100 &nbsp;·&nbsp; {escape(source)} &nbsp;·&nbsp; '
        f'<a href="{escape(item.url)}" style="color:#3182ce;font-weight:600;">Read →</a></p>'
        f'</div></div>'
    )


def _item_compact_text(item: TrendItem) -> str:
    exploitation = _derive_exploitation(item) or _llm(item, "exploitation_status", "Unknown")
    headline = _llm(item, "headline") or item.title
    action = _llm(item, "recommended_action", "")
    lines = [
        headline,
        f"[{exploitation}] Score: {_score(item.criticality_score)}/100 | {_source_label(item)}",
    ]
    if action:
        lines.append(f"Action: {_truncate(action)}")
    lines.append(f"Link: {item.url}")
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_email_rendering.py::test_item_compact_html_contains_headline_and_action tests/test_email_rendering.py::test_item_compact_html_omits_org_risk_and_vulnerability tests/test_email_rendering.py::test_item_compact_html_shows_score tests/test_email_rendering.py::test_item_compact_text_contains_headline_action_link -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cybertrend/email/render.py tests/test_email_rendering.py
git commit -m "feat: add _item_compact_html/text for High-severity cards"
```

---

### Task 5: Add `_item_minimal_html` and `_item_minimal_text`

Single-line list entries for Medium items.

**Files:**
- Modify: `src/cybertrend/email/render.py`
- Test: `tests/test_email_rendering.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_email_rendering.py`:

```python
from cybertrend.email.render import _item_minimal_html, _item_minimal_text


def test_item_minimal_html_is_one_linked_line():
    i = item("Medium")
    html = _item_minimal_html(i)

    assert "Cisco ASA" in html
    assert 'href="https://example.com/advisory"' in html
    assert "96" in html  # score
    # no card chrome — no box-shadow, no border-radius card wrapper
    assert "border-radius:8px" not in html


def test_item_minimal_text_is_single_line():
    i = item("Medium")
    text = _item_minimal_text(i)

    assert "Cisco ASA" in text
    assert "\n" not in text  # single line
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_email_rendering.py::test_item_minimal_html_is_one_linked_line -v
```

Expected: FAIL — `_item_minimal_html` not defined.

- [ ] **Step 3: Implement both functions**

Add after `_item_compact_text` in `render.py`:

```python
def _item_minimal_html(item: TrendItem) -> str:
    headline = _llm(item, "headline") or item.title
    return (
        f'<div style="display:flex;align-items:flex-start;justify-content:space-between;'
        f'gap:8px;padding:5px 0;border-bottom:1px solid #f0f4f8;">'
        f'<div style="display:flex;align-items:flex-start;gap:7px;flex:1;">'
        f'<span style="width:6px;height:6px;background:#d69e2e;border-radius:50%;'
        f'flex-shrink:0;margin-top:5px;display:inline-block;"></span>'
        f'<a href="{escape(item.url)}" style="font-size:12px;color:#2d3748;'
        f'text-decoration:none;line-height:1.4;">{escape(headline)}</a>'
        f'</div>'
        f'<span style="font-size:11px;color:#a0aec0;white-space:nowrap;flex-shrink:0;">'
        f'{_score(item.criticality_score)}</span>'
        f'</div>'
    )


def _item_minimal_text(item: TrendItem) -> str:
    headline = _llm(item, "headline") or item.title
    return f"  • {_truncate(headline, 100)} [{_score(item.criticality_score)}]"
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_email_rendering.py::test_item_minimal_html_is_one_linked_line tests/test_email_rendering.py::test_item_minimal_text_is_single_line -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cybertrend/email/render.py tests/test_email_rendering.py
git commit -m "feat: add _item_minimal_html/text for Medium list entries"
```

---

### Task 6: Modify `_item_html` — action first, add `show_vulnerability` param

The existing full card used for Critical items gets two changes: the action box moves above the field table, and a `show_vulnerability` parameter lets the digest suppress the Vulnerability row (which duplicates the headline).

**Files:**
- Modify: `src/cybertrend/email/render.py:93-177` (`_item_html`)
- Test: `tests/test_email_rendering.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_email_rendering.py`:

```python
from cybertrend.email.render import _item_html


def test_item_html_action_appears_before_affected_field():
    i = item("Critical")
    html = _item_html(i, "Critical")

    action_pos = html.find("background:#ebf8ff")  # action box style
    affected_pos = html.find("AFFECTED")
    assert action_pos < affected_pos, "Action box must appear before the Affected field row"


def test_item_html_show_vulnerability_false_omits_vulnerability_row():
    i = item("Critical")
    html = _item_html(i, "Critical", show_vulnerability=False)
    assert "VULNERABILITY" not in html.upper() or "Vulnerability" not in html


def test_item_html_show_vulnerability_true_keeps_vulnerability_row():
    i = item("Critical")
    html = _item_html(i, "Critical", show_vulnerability=True)
    assert "VULNERABILITY" in html.upper()


def test_item_html_default_show_vulnerability_is_true():
    i = item("Critical")
    html = _item_html(i, "Critical")
    assert "VULNERABILITY" in html.upper()
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_email_rendering.py::test_item_html_action_appears_before_affected_field tests/test_email_rendering.py::test_item_html_show_vulnerability_false_omits_vulnerability_row -v
```

Expected: first test FAIL (action currently after field table), second FAIL (no such param).

- [ ] **Step 3: Replace `_item_html` with the modified version**

Replace the entire `_item_html` function in `render.py` with:

```python
def _item_html(item: TrendItem, severity: str = "", show_vulnerability: bool = True) -> str:
    sev_color = _SEV_COLORS.get(severity or item.severity_label, _SEV_COLORS["Medium"])
    exploitation = _derive_exploitation(item) or _llm(item, "exploitation_status", "Unknown")
    headline = _llm(item, "headline") or item.title
    affected  = _llm(item, "affected_assets")
    vuln      = _llm(item, "vulnerability", item.summary or item.title)
    threat    = _llm(item, "threat", item.what_went_wrong)
    org_risk  = _llm(item, "organizational_risk", item.why_this_matters_now)
    action    = _llm(item, "recommended_action")
    why       = _llm(item, "why_it_matters")
    cves      = ", ".join(item.cves) if item.cves else ""

    meta_pills = _meta_pill(_source_label(item))
    meta_pills += _meta_pill(f"Score {_score(item.criticality_score)}/100")
    if item.cvss_base:
        meta_pills += _meta_pill(f"CVSS {item.cvss_base}")
    if item.epss_probability and item.epss_probability > 0.1:
        meta_pills += _meta_pill(f"EPSS {item.epss_probability:.0%}")

    def field_row(label: str, value: str, value_color: str = "#2d3748") -> str:
        if not value:
            return ""
        return (
            f'<tr>'
            f'<td style="padding:5px 12px 5px 0;font-size:11px;font-weight:700;'
            f'color:#718096;white-space:nowrap;vertical-align:top;'
            f'text-transform:uppercase;letter-spacing:0.5px;">{escape(label)}</td>'
            f'<td style="padding:5px 0;font-size:13px;color:{value_color};line-height:1.5;">'
            f'{escape(_truncate(value))}</td>'
            f'</tr>'
        )

    rows = (
        field_row("Affected", affected)
        + (field_row("Vulnerability", vuln) if show_vulnerability else "")
        + field_row("Threat", threat)
        + field_row("Org Risk", org_risk)
    )

    action_html = ""
    if action:
        action_html = (
            f'<div style="margin:12px 0 8px;padding:10px 14px;background:#ebf8ff;'
            f'border-left:3px solid #3182ce;border-radius:0 6px 6px 0;">'
            f'<span style="font-size:11px;font-weight:700;color:#2b6cb0;'
            f'text-transform:uppercase;letter-spacing:0.5px;">Action &nbsp;</span>'
            f'<span style="font-size:13px;color:#2c5282;">{escape(_truncate(action))}</span>'
            f'</div>'
        )

    why_html = ""
    if why:
        why_html = (
            f'<p style="margin:8px 0 0;font-size:12px;color:#718096;font-style:italic;">'
            f'{escape(_truncate(why))}</p>'
        )

    cves_html = ""
    if cves:
        cves_html = (
            f'<p style="margin:6px 0 0;font-size:11px;color:#a0aec0;">'
            f'CVEs: {escape(cves)}</p>'
        )

    return (
        f'<div style="background:#ffffff;border-radius:8px;margin:0 0 16px;'
        f'box-shadow:0 1px 3px rgba(0,0,0,0.08);overflow:hidden;'
        f'border:1px solid #e2e8f0;">'
        f'<div style="height:3px;background:{sev_color["border"]};"></div>'
        f'<div style="padding:16px 18px;">'
        f'<div style="margin-bottom:8px;">{_exploit_badge(exploitation)}</div>'
        f'<h3 style="margin:0 0 6px;font-size:14px;line-height:1.4;font-weight:700;">'
        f'<a href="{escape(item.url)}" style="color:#1a202c;text-decoration:none;">'
        f'{escape(headline)}</a></h3>'
        f'<div style="margin-bottom:12px;">{meta_pills}</div>'
        f'{action_html}'
        f'<table style="border-collapse:collapse;width:100%;">{rows}</table>'
        f'{why_html}'
        f'{cves_html}'
        f'<p style="margin:10px 0 0;font-size:12px;">'
        f'<a href="{escape(item.url)}" style="color:#3182ce;text-decoration:none;'
        f'font-weight:600;">Read full article →</a></p>'
        f'</div></div>'
    )
```

- [ ] **Step 4: Run the new tests**

```
pytest tests/test_email_rendering.py::test_item_html_action_appears_before_affected_field tests/test_email_rendering.py::test_item_html_show_vulnerability_false_omits_vulnerability_row tests/test_email_rendering.py::test_item_html_show_vulnerability_true_keeps_vulnerability_row tests/test_email_rendering.py::test_item_html_default_show_vulnerability_is_true -v
```

Expected: all PASS.

- [ ] **Step 5: Run full suite to confirm immediate alert test still passes**

```
pytest tests/test_email_rendering.py -v
```

Expected: all PASS. The immediate alert calls `_item_html(item, "Critical")` — default `show_vulnerability=True` means "Vulnerability" is still in the alert HTML.

- [ ] **Step 6: Commit**

```bash
git add src/cybertrend/email/render.py tests/test_email_rendering.py
git commit -m "feat: promote action above field table in full card, add show_vulnerability param"
```

---

### Task 7: Restructure `render_daily_digest`

Wire up the summary block, top-actions block, tiered rendering, and empty-section suppression.

**Files:**
- Modify: `src/cybertrend/email/render.py:235-334` (`render_daily_digest`)
- Test: `tests/test_email_rendering.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_email_rendering.py`:

```python
def test_render_daily_digest_contains_today_in_30_seconds_block():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="Critical Threats", severity="Critical", items=[item("Critical")]),
        ],
    )
    message = render_daily_digest(payload)
    assert "Today in 30 seconds" in message.html
    assert "Today in 30 seconds" in message.text
    assert "Cisco ASA" in message.html  # top-scored item appears in summary


def test_render_daily_digest_contains_top_actions_block():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="Critical Threats", severity="Critical", items=[item("Critical")]),
        ],
    )
    message = render_daily_digest(payload)
    assert "Top actions" in message.html
    assert "Today" in message.html  # timeframe badge for KEV item


def test_render_daily_digest_critical_uses_full_card_without_vulnerability():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="Critical Threats", severity="Critical", items=[item("Critical")]),
        ],
    )
    message = render_daily_digest(payload)
    # Full card fields present
    assert "AFFECTED" in message.html.upper()
    assert "THREAT" in message.html.upper()
    assert "ORG RISK" in message.html.upper()
    # Vulnerability row suppressed
    assert "VULNERABILITY" not in message.html.upper()


def test_render_daily_digest_high_uses_compact_card():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="High Priority", severity="High", items=[item("High")]),
        ],
    )
    message = render_daily_digest(payload)
    # compact card: score present, no Org Risk field
    assert "96/100" in message.html
    assert "ORG RISK" not in message.html.upper()


def test_render_daily_digest_medium_uses_minimal_list():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="Medium Risk", severity="Medium", items=[item("Medium")]),
        ],
    )
    message = render_daily_digest(payload)
    # minimal entry: headline present, no action box background color
    assert "Cisco ASA" in message.html
    assert "background:#ebf8ff" not in message.html  # action box style absent


def test_render_daily_digest_empty_section_produces_no_html():
    payload = DigestPayload(
        digest_date=date(2026, 5, 15),
        sections=[
            DigestSection(name="Critical Threats", severity="Critical", items=[item("Critical")]),
            DigestSection(name="High Priority", severity="High", items=[]),
            DigestSection(name="Medium Risk", severity="Medium", items=[]),
        ],
    )
    message = render_daily_digest(payload)
    assert "No items today" not in message.html
    assert "High Priority" not in message.html
    assert "Medium Risk" not in message.html
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_email_rendering.py::test_render_daily_digest_contains_today_in_30_seconds_block tests/test_email_rendering.py::test_render_daily_digest_empty_section_produces_no_html -v
```

Expected: both FAIL — summary block not present, empty sections still render.

- [ ] **Step 3: Replace `render_daily_digest` with the restructured version**

Replace the entire `render_daily_digest` function in `render.py` with:

```python
def render_daily_digest(payload: DigestPayload) -> RenderedEmail:
    all_items = list(_all_items(payload))
    counts = Counter(i.severity_label for i in all_items)
    date_str = payload.digest_date.strftime("%B %d, %Y")
    day_str  = payload.digest_date.strftime("%A")
    subject = (
        f"Cyber Threat Digest — {date_str} | "
        f"{counts['Critical']} Critical, {counts['High']} High, {counts['Medium']} Medium"
    )

    # ── Header ──────────────────────────────────────────────────────────────
    header = (
        '<div style="background:#0f1923;padding:28px 24px 20px;border-radius:8px 8px 0 0;">'
        '<p style="margin:0 0 4px;font-size:11px;color:#718096;'
        'text-transform:uppercase;letter-spacing:1px;">Automated Intelligence Brief</p>'
        '<h1 style="margin:0 0 6px;font-size:22px;color:#ffffff;font-weight:800;">'
        '&#x1F6E1; Cyber Threat Digest</h1>'
        f'<p style="margin:0 0 16px;font-size:13px;color:#a0aec0;">{day_str}, {date_str}</p>'
        '<div>'
        + _count_badge("Critical", counts["Critical"], "#c0392b")
        + _count_badge("High", counts["High"], "#c05621")
        + _count_badge("Medium", counts["Medium"], "#975a16")
        + '</div></div>'
    )

    # ── Today in 30 seconds ─────────────────────────────────────────────────
    bullets = _top_summary_bullets(all_items)
    if bullets:
        bullet_html = "".join(
            f'<p style="margin:0 0 5px;font-size:13px;color:#e2e8f0;padding-left:14px;'
            f'position:relative;line-height:1.5;">'
            f'<span style="position:absolute;left:0;color:#63b3ed;font-weight:800;">·</span>'
            f'{escape(b)}</p>'
            for b in bullets
        )
        summary_html = (
            '<div style="margin:0;padding:12px 16px;background:#1a2744;'
            'border-left:3px solid #63b3ed;">'
            '<p style="margin:0 0 8px;font-size:10px;font-weight:800;color:#63b3ed;'
            'text-transform:uppercase;letter-spacing:1px;">Today in 30 seconds</p>'
            + bullet_html
            + '</div>'
        )
        summary_text = "Today in 30 seconds\n" + "\n".join(f"- {b}" for b in bullets)
    else:
        summary_html = ""
        summary_text = ""

    # ── Top actions ─────────────────────────────────────────────────────────
    top_items = sorted(all_items, key=lambda i: i.criticality_score, reverse=True)[:5]
    if top_items:
        rows_html = ""
        rows_text = []
        for idx, i in enumerate(top_items, 1):
            action_type = _derive_action_type(_llm(i, "recommended_action", ""))
            timeframe   = _derive_timeframe(i)
            assets      = _llm(i, "affected_assets") or i.title
            tf_color    = "#c0392b" if timeframe == "Today" else (
                "#975a16" if timeframe == "This week" else "#4a5568"
            )
            rows_html += (
                f'<tr>'
                f'<td style="padding:3px 8px 3px 0;font-size:12px;color:#718096;">{idx}.</td>'
                f'<td style="padding:3px 0;">'
                f'{_action_badge(action_type, "#553c9a")}'
                f'{_action_badge(timeframe, tf_color)}'
                f'<span style="font-size:12px;color:#2d3748;">'
                f'{escape(_truncate(assets, 80))}</span>'
                f'</td></tr>'
            )
            rows_text.append(f"{idx}. [{action_type}] [{timeframe}] {_truncate(assets, 80)}")

        top_actions_html = (
            '<div style="margin:0;padding:12px 16px;background:#f7fafc;'
            'border-top:1px solid #e2e8f0;">'
            '<p style="margin:0 0 8px;font-size:10px;font-weight:800;color:#718096;'
            'text-transform:uppercase;letter-spacing:1px;">Top actions</p>'
            f'<table style="border-collapse:collapse;width:100%;">{rows_html}</table>'
            '</div>'
        )
        top_actions_text = "Top actions\n" + "\n".join(rows_text)
    else:
        top_actions_html = ""
        top_actions_text = ""

    # ── Sections ─────────────────────────────────────────────────────────────
    sev_order = [
        ("Critical", "Critical Threats"),
        ("High",     "High Priority"),
        ("Medium",   "Medium Risk"),
    ]
    html_sections: List[str] = []
    text_sections: List[str] = []

    section_map = {s.severity: s for s in payload.sections}

    for sev_key, sev_label in sev_order:
        section = section_map.get(sev_key)
        items = section.items if section else []
        if not items:
            continue
        sev_color = _SEV_COLORS.get(sev_key, _SEV_COLORS["Medium"])

        section_header = (
            f'<div style="background:{sev_color["bg"]};padding:10px 18px;margin:0 0 16px;">'
            f'<span style="font-size:13px;font-weight:800;color:#fff;'
            f'text-transform:uppercase;letter-spacing:1px;">{escape(sev_label)}</span>'
            f'<span style="font-size:12px;color:rgba(255,255,255,0.7);margin-left:8px;">'
            f'({len(items)})</span>'
            f'</div>'
        )

        if sev_key == "Critical":
            cards = "".join(_item_html(i, sev_key, show_vulnerability=False) for i in items)
            content = f'<div style="padding:0 16px 8px;">{cards}</div>'
            text_items = "\n\n".join(_item_text(i) for i in items)
        elif sev_key == "High":
            cards = "".join(_item_compact_html(i) for i in items)
            content = f'<div style="padding:0 16px 8px;">{cards}</div>'
            text_items = "\n\n".join(_item_compact_text(i) for i in items)
        else:
            list_items = "".join(_item_minimal_html(i) for i in items)
            content = (
                f'<div style="padding:0 16px 8px;">'
                f'<div style="background:#ffffff;border-radius:6px;padding:6px 12px;'
                f'border:1px solid #e2e8f0;">{list_items}</div>'
                f'</div>'
            )
            text_items = "\n".join(_item_minimal_text(i) for i in items)

        html_sections.append(
            f'<div style="margin-bottom:24px;">{section_header}{content}</div>'
        )
        text_sections.append(f"{sev_label} ({len(items)})\n{'─'*40}\n{text_items}")

    # ── Footer ───────────────────────────────────────────────────────────────
    quality_html = ""
    quality_text = ""
    if payload.source_quality_footer:
        quality_html = (
            f'<p style="font-size:12px;color:#718096;margin:0 0 8px;">'
            f'<strong>Source quality:</strong> {escape(payload.source_quality_footer)}</p>'
        )
        quality_text = payload.source_quality_footer

    footer = (
        '<div style="background:#0f1923;padding:16px 24px;border-radius:0 0 8px 8px;">'
        + quality_html
        + '<p style="margin:0;font-size:11px;color:#4a5568;">'
        f'Cybertrend Intelligence &nbsp;·&nbsp; Automated daily briefing &nbsp;·&nbsp; '
        f'Sources: {escape(" · ".join(_SOURCE_LABELS.values()))}'
        '</p></div>'
    )

    html = (
        '<html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head>'
        '<body style="font-family:-apple-system,Arial,sans-serif;background:#edf2f7;'
        'padding:20px 10px;margin:0;">'
        '<div style="max-width:640px;margin:0 auto;border-radius:8px;overflow:hidden;'
        'box-shadow:0 4px 12px rgba(0,0,0,0.12);">'
        + header
        + summary_html
        + top_actions_html
        + '<div style="background:#f7fafc;">'
        + "".join(html_sections)
        + '</div>'
        + footer
        + '</div></body></html>'
    )

    text_parts = [f"CYBER THREAT DIGEST — {date_str}"]
    if summary_text:
        text_parts.append(summary_text)
    if top_actions_text:
        text_parts.append(top_actions_text)
    text_parts.extend(text_sections)
    if quality_text:
        text_parts.append(f"Source quality: {quality_text}")
    text = "\n\n".join(text_parts)

    return RenderedEmail(subject=subject, html=html, text=text)
```

- [ ] **Step 4: Run the new digest tests**

```
pytest tests/test_email_rendering.py::test_render_daily_digest_contains_today_in_30_seconds_block tests/test_email_rendering.py::test_render_daily_digest_contains_top_actions_block tests/test_email_rendering.py::test_render_daily_digest_critical_uses_full_card_without_vulnerability tests/test_email_rendering.py::test_render_daily_digest_high_uses_compact_card tests/test_email_rendering.py::test_render_daily_digest_medium_uses_minimal_list tests/test_email_rendering.py::test_render_daily_digest_empty_section_produces_no_html -v
```

Expected: all PASS.

- [ ] **Step 5: Run the full test suite**

```
pytest tests/test_email_rendering.py -v
```

Expected: all PASS including existing tests.

- [ ] **Step 6: Run the broader test suite to catch regressions**

```
pytest tests/ -v
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add src/cybertrend/email/render.py tests/test_email_rendering.py
git commit -m "feat: mobile-first digest — summary block, top actions, tiered cards, hide empty sections"
```

---

## Self-Review Checklist

**Spec coverage:**

| Spec requirement | Task |
|---|---|
| Add reddit_pwnhub to source label map | Task 1 |
| Auto-derive footer from `_SOURCE_LABELS` | Task 1 |
| `_derive_action_type` keyword matching | Task 2 |
| `_derive_timeframe` from exploitation status | Task 2 |
| `_top_summary_bullets` selects top N by score | Task 3 |
| `_item_compact_html/text` for High items | Task 4 |
| `_item_minimal_html/text` for Medium items | Task 5 |
| Action box promoted above field table | Task 6 |
| `show_vulnerability=False` for digest Critical cards | Task 6 + Task 7 |
| "Today in 30 seconds" block in digest | Task 7 |
| "Top actions" block in digest | Task 7 |
| Empty sections suppressed entirely | Task 7 |
| Tiered rendering (Critical/High/Medium) | Task 7 |

All spec requirements covered. No TBDs. All code shown in full.
