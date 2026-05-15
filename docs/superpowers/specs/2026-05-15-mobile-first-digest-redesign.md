# Spec: Mobile-First Digest Redesign

Date: 2026-05-15

## Problem

The daily digest is read on Gmail mobile. Three concrete pain points drive this redesign:

1. **No urgency signal on first screen.** The reader must scroll every card to understand what matters today.
2. **Cards are too long for mobile.** Every severity tier uses a full card regardless of how important the item is. A Medium item and a Critical actively-exploited vulnerability take similar visual space.
3. **No freshness signal.** The reader cannot tell whether an item is new today or a repeat from earlier in the week.

An additional constraint the gap analysis does not address: Gmail clips emails over ~102KB and shows a "Message clipped — View entire message" prompt. A digest with 12+ full cards hits this limit, silently hiding Medium items.

This spec addresses pain points 1 and 2 in a single renderer-only change. Pain point 3 (freshness) is deferred to the next phase because it requires a repository query change, and improving scanability first is higher leverage.

## Scope

All changes are inside `src/cybertrend/email/render.py` and `tests/test_email_rendering.py`. No database migrations, no LLM prompt changes, no ingestion or scoring changes, no model changes.

## Email Structure

The rendered email follows this top-to-bottom order:

1. **Header** — date, count badges (Critical / High / Medium). Unchanged.
2. **Today in 30 seconds** — 3–5 short imperative bullets derived from the top items by `criticality_score`. Rendered as a left-bordered block immediately below the header.
3. **Top actions** — compact numbered list of the same top items with derived `action_type` and `timeframe` badges.
4. **Critical Threats** — one full card per item. Hidden entirely if empty.
5. **High Priority** — one compact card per item. Hidden entirely if empty.
6. **Medium Risk** — minimal linked list, one line per item. Hidden entirely if empty.
7. **Footer** — source list auto-derived from `_SOURCE_LABELS`, not hardcoded.

## Component Design

### `_SOURCE_LABELS` fix

Add `"reddit_pwnhub": "r/pwnhub"` to the existing dict. The footer source string is replaced by `" · ".join(_SOURCE_LABELS.values())` so it stays in sync automatically when new sources are added.

### `_top_summary_bullets(items, n=5)`

Selects the top `n` items across all sections sorted by `criticality_score` descending. For each item, builds a short imperative bullet:

```
{affected_assets} — {exploitation_reason}
```

Where `affected_assets` comes from `_llm(item, "affected_assets")` and `exploitation_reason` is a shortened form of `_derive_exploitation()` or `_llm(item, "exploitation_status")`. Falls back to `item.title` if `llm_analysis` is absent.

Returns a list of plain strings. The caller renders them as HTML bullets or plain-text lines.

### `_derive_action_type(action_text)`

Keyword match against the `recommended_action` string:

| Keywords present | Returns |
|---|---|
| "patch", "update", "upgrade" | `Patch` |
| "monitor", "watch" | `Monitor` |
| "investigate" | `Investigate` |
| "block", "restrict", "disable" | `Block` |
| "review", "audit", "check" | `Review` |
| fallback | `Review` |

Case-insensitive. Returns the first match.

### `_derive_timeframe(item)`

Derived from exploitation status:

| Condition | Returns |
|---|---|
| `item.kev_flag` is true | `Today` |
| `_derive_exploitation()` contains "actively exploited" | `Today` |
| contains "poc" or "exploitation likely" | `This week` |
| all others | `Monitor` |

### `_item_compact_html(item)` / `_item_compact_text(item)`

Three-line compact card for High items:

- Row 1: Headline (linked) + exploit badge right-aligned.
- Row 2: `recommended_action` truncated to one line.
- Row 3: `Score X/100 · {source_label} · Read →` meta line.

Left border colored with High severity orange (`#dd6b20`). No Vulnerability, Threat, Org Risk, or CVE fields.

### `_item_minimal_html(item)` / `_item_minimal_text(item)`

Single linked line for Medium items:

```
• {headline}    {score}
```

Headline links to `item.url`. Score right-aligned. No fields, no card chrome.

### `render_daily_digest()` restructure

```
header
today-in-30-seconds block
top-actions block
for sev in [Critical, High, Medium]:
    if no items: skip entirely
    section header
    for item in items:
        Critical → _item_html()         (existing, action promoted)
        High     → _item_compact_html()
        Medium   → _item_minimal_html()
footer (auto-derived source list)
```

### Existing `_item_html()` modification

Action box is moved above the field table. Field order becomes:

1. Exploit badge
2. Headline (linked)
3. Meta pills (source, score, CVSS, EPSS)
4. Action box
5. Field table: Affected · Threat · Org Risk
6. Why it matters (italic)
7. CVEs
8. Read full article link

Vulnerability field is removed from the Critical card. It duplicates the headline in most cases and adds length without adding decision-relevant information.

## Fallback Behaviour

- Missing `llm_analysis`: all helpers fall back to raw `title` / `summary` / `what_went_wrong` fields via the existing `_llm()` helper.
- Zero `criticality_score` across all items: top-summary picks items in severity order (Critical first).
- Empty section: section heading and content block are both suppressed. No "No items today." text.
- Plain-text version mirrors the HTML structure: summary bullets as `- ` lines, top-action rows as numbered lines, Critical as full text, High as 2-liner, Medium as title-only.

## Testing

Additions to `tests/test_email_rendering.py`:

- Summary block present in HTML and plain text; contains bullet text derived from the top-scored item.
- Critical item: full field table rendered (Affected, Threat, Org Risk present; Vulnerability field absent); action box appears before the field table.
- High item: compact card rendered; Vulnerability and Org Risk fields absent from output.
- Medium item: minimal list entry rendered; no card markup.
- Empty severity section: no HTML emitted for that section (no "No items today." string).
- `reddit_pwnhub` source key resolves to `r/pwnhub` via `_source_label()`.
- Footer contains all display names from `_SOURCE_LABELS`.
- `_derive_action_type("patch the system to version X")` returns `Patch`.
- `_derive_action_type("monitor for unusual outbound connections")` returns `Monitor`.
- `_derive_timeframe(item_with_kev_flag=True)` returns `Today`.
- `_derive_timeframe(item_with_no_exploitation)` returns `Monitor`.

## Files Changed

- `src/cybertrend/email/render.py` — all rendering changes
- `tests/test_email_rendering.py` — new test cases above

## Files Not Changed

- `src/cybertrend/db/models.py`
- `src/cybertrend/summaries_openai.py`
- `src/cybertrend/models.py`
- `src/cybertrend/services/` (ingestion, pipeline, enrichment)
- `src/cybertrend/scoring.py`
- `src/cybertrend/email/smtp.py` / `ses.py`

## Success Criteria

- First screen of the Gmail mobile email shows the 30-second summary and top actions without scrolling.
- Critical items show full detail. High items show headline + action. Medium items are a scannable list.
- Email with 12 items stays well under 102KB.
- Empty severity sections produce no visible output.
- `r/pwnhub` appears correctly in source labels and footer.
- All existing tests pass. New tests cover the additions above.
