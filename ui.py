"""Presentation layer for CyberSentinel AI.

All custom styling derives its colours from the active Streamlit theme
(`currentColor` + `color-mix`), so the interface follows Streamlit's own
light/dark setting (Settings menu) without a second, hand-maintained theme.

Every dynamic value that reaches raw HTML is escaped here. Scan targets, email
subjects and indicators are attacker-controlled strings in this application,
so nothing is interpolated into markup without `html.escape`.
"""
from __future__ import annotations

import html

import pandas as pd
import streamlit as st

SEVERITY_LABEL = {"high": "High risk", "medium": "Medium risk", "low": "Low risk"}

LOGO_SVG = (
    '<svg viewBox="0 0 32 32" width="30" height="30" aria-hidden="true" fill="none">'
    '<path d="M16 2.5 5 6.8v8.1c0 7 4.6 12.2 11 14.6 6.4-2.4 11-7.6 11-14.6V6.8L16 2.5Z" '
    'fill="#2f6fed"/>'
    '<path d="M10.5 16.2h3.2l1.7-4.6 2.7 8.4 1.7-3.8h1.7" stroke="#fff" stroke-width="1.8" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');

.stApp {
  --cs-font: 'IBM Plex Sans', -apple-system, 'Segoe UI', Roboto, sans-serif;
  --cs-mono: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
  --cs-line: color-mix(in srgb, currentColor 14%, transparent);
  --cs-line-strong: color-mix(in srgb, currentColor 26%, transparent);
  --cs-surface: color-mix(in srgb, currentColor 4%, transparent);
  --cs-surface-strong: color-mix(in srgb, currentColor 8%, transparent);
  --cs-muted: color-mix(in srgb, currentColor 66%, transparent);
  --cs-accent: #2f6fed;
  --cs-high: #e5484d;
  --cs-medium: #d9930d;
  --cs-low: #2f9e6b;
}
.stApp :not([data-testid="stIconMaterial"]):not(code):not(pre):not(svg):not(path) { font-family: var(--cs-font); }
.stApp [data-testid="stCode"] *, .stApp [data-testid="stJson"] *, .stApp .cs-mono, .stApp .cs-mono * { font-family: var(--cs-mono) !important; }
.block-container { max-width: 1280px; padding: 2.4rem 2.6rem 4rem; }
footer { visibility: hidden; }
[data-testid="stHeader"] { background: transparent; }
@media (max-width: 760px) { .block-container { padding: 1.4rem 1rem 3rem; } }

/* ---------- Native widgets ---------- */
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button { border-radius: 6px; font-weight: 550; }
[data-baseweb="input"], [data-baseweb="textarea"], [data-baseweb="select"] > div { border-radius: 6px !important; }
div[data-testid="stMetric"] { border: 1px solid var(--cs-line); border-radius: 8px; padding: .8rem 1rem; background: var(--cs-surface); }
div[data-testid="stExpander"] details { border-color: var(--cs-line); border-radius: 8px; }
div[data-testid="stDataFrame"] { border: 1px solid var(--cs-line); border-radius: 8px; overflow: hidden; }
div[data-testid="stAlert"] { border-radius: 8px; }
button[data-baseweb="tab"] { font-weight: 500; }
hr { border-color: var(--cs-line) !important; }

/* ---------- Sidebar ---------- */
section[data-testid="stSidebar"] { border-right: 1px solid var(--cs-line); }
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: .15rem; }
section[data-testid="stSidebar"] .stButton > button {
  justify-content: flex-start; width: 100%; gap: .6rem; padding: .42rem .75rem; min-height: 0;
  border: 0; border-radius: 6px; background: transparent; color: inherit; font-weight: 500; font-size: .9rem; box-shadow: none;
}
section[data-testid="stSidebar"] .stButton > button > div { justify-content: flex-start; width: 100%; }
section[data-testid="stSidebar"] .stButton > button p { text-align: left; }
section[data-testid="stSidebar"] .stButton > button:hover { background: var(--cs-surface-strong); }
section[data-testid="stSidebar"] .stButton > button[kind="primary"],
section[data-testid="stSidebar"] .stButton > button[data-testid="stBaseButton-primary"] {
  background: color-mix(in srgb, var(--cs-accent) 18%, transparent); color: inherit; box-shadow: inset 3px 0 0 var(--cs-accent);
}
.cs-brand { display: flex; align-items: center; gap: .7rem; padding: .3rem .2rem 1rem; border-bottom: 1px solid var(--cs-line); margin-bottom: .4rem; }
.cs-brand-name { font-weight: 600; font-size: 1.02rem; letter-spacing: -.01em; line-height: 1.2; }
.cs-brand-sub { color: var(--cs-muted); font-size: .76rem; line-height: 1.3; }
.cs-nav-group { color: var(--cs-muted); font-size: .76rem; font-weight: 600; margin: 1.1rem .25rem .25rem; }
.cs-account { display: flex; align-items: center; gap: .65rem; padding: .75rem .25rem .5rem; border-top: 1px solid var(--cs-line); margin-top: 1.2rem; }
.cs-avatar { width: 32px; height: 32px; border-radius: 50%; background: color-mix(in srgb, var(--cs-accent) 24%, transparent); display: grid; place-items: center; font-weight: 600; font-size: .85rem; flex: none; }
.cs-account-name { font-weight: 550; font-size: .9rem; line-height: 1.2; overflow-wrap: anywhere; }
.cs-account-role { color: var(--cs-muted); font-size: .76rem; }

/* ---------- Page header ---------- */
.cs-page { padding-bottom: 1rem; margin-bottom: 1.4rem; border-bottom: 1px solid var(--cs-line); }
.cs-crumb { color: var(--cs-muted); font-size: .8rem; }
.cs-title { font-size: 1.75rem; font-weight: 600; letter-spacing: -.02em; line-height: 1.2; margin: .25rem 0 .35rem; }
.cs-desc { color: var(--cs-muted); font-size: .95rem; max-width: 66ch; line-height: 1.5; }
.cs-section { margin: 1.7rem 0 .6rem; }
.cs-section-title { font-size: 1.05rem; font-weight: 600; letter-spacing: -.01em; }
.cs-section-sub { color: var(--cs-muted); font-size: .85rem; margin-top: .1rem; max-width: 70ch; }

/* ---------- Verdict panel ---------- */
.cs-verdict { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: .9rem 2rem; border: 1px solid var(--cs-line); border-left: 4px solid var(--sev); border-radius: 8px; padding: 1.1rem 1.4rem; background: color-mix(in srgb, var(--sev) 6%, transparent); margin: .2rem 0 1rem; }
.cs-sev { display: inline-flex; align-items: center; gap: .45rem; font-weight: 600; font-size: .85rem; color: color-mix(in srgb, var(--sev) 62%, currentColor); }
.cs-sev::before { content: ""; width: .55rem; height: .55rem; border-radius: 50%; background: var(--sev); }
.cs-verdict-text { font-size: 1.2rem; font-weight: 600; letter-spacing: -.01em; margin: .35rem 0 .15rem; line-height: 1.3; overflow-wrap: anywhere; }
.cs-verdict-sub { color: var(--cs-muted); font-size: .88rem; }
.cs-score { text-align: right; align-self: center; }
.cs-score-num { font-size: 2.7rem; font-weight: 600; line-height: 1; letter-spacing: -.03em; }
.cs-score-den { color: var(--cs-muted); font-size: 1rem; margin-left: .15rem; }
.cs-score-label { color: var(--cs-muted); font-size: .8rem; margin-top: .25rem; }
.cs-meter-wrap { grid-column: 1 / -1; }
.cs-meter { position: relative; height: 8px; }
.cs-meter-track, .cs-meter-fill { position: absolute; inset: 0; border-radius: 4px; background: linear-gradient(90deg, var(--cs-low) 0 40%, var(--cs-medium) 40% 70%, var(--cs-high) 70% 100%); }
.cs-meter-track { opacity: .2; }
.cs-meter-scale { position: relative; height: 1.1rem; margin-top: .3rem; color: var(--cs-muted); font-size: .72rem; }
.cs-meter-scale span { position: absolute; transform: translateX(-50%); white-space: nowrap; }
.cs-meter-scale span:first-child { transform: none; }
.cs-meter-scale span:last-child { transform: translateX(-100%); }
.cs-evidence { grid-column: 1 / -1; border-top: 1px solid var(--cs-line); padding-top: .75rem; font-size: .86rem; line-height: 1.5; }
.cs-evidence b { font-weight: 600; }
.cs-evidence span { color: var(--cs-muted); }
@media (max-width: 760px) { .cs-verdict { grid-template-columns: 1fr; } .cs-score { text-align: left; } }

/* ---------- Stat strip ---------- */
.cs-stats { border: 1px solid var(--cs-line); border-radius: 8px; overflow: hidden; margin: .2rem 0 1rem; background: var(--cs-surface); }
.cs-stats-in { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); margin: 0 -1px -1px 0; }
.cs-stat { padding: .9rem 1.1rem; border-right: 1px solid var(--cs-line); border-bottom: 1px solid var(--cs-line); min-width: 0; }
.cs-stat-label { color: var(--cs-muted); font-size: .8rem; }
.cs-stat-value { font-size: 1.55rem; font-weight: 600; letter-spacing: -.02em; margin-top: .1rem; overflow-wrap: anywhere; line-height: 1.25; }
.cs-stat-hint { color: var(--cs-muted); font-size: .76rem; margin-top: .1rem; }
.cs-tone-high { color: color-mix(in srgb, var(--cs-high) 68%, currentColor); }
.cs-tone-medium { color: color-mix(in srgb, var(--cs-medium) 68%, currentColor); }
.cs-tone-low { color: color-mix(in srgb, var(--cs-low) 68%, currentColor); }

/* ---------- Lists, key/value, chips ---------- */
.cs-list { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--cs-line); }
.cs-list li { display: flex; gap: .65rem; padding: .6rem .1rem; border-bottom: 1px solid var(--cs-line); font-size: .92rem; line-height: 1.45; overflow-wrap: anywhere; }
.cs-list li::before { content: ""; flex: none; width: .45rem; height: .45rem; margin-top: .5rem; border-radius: 1px; background: var(--cs-accent); }
.cs-list.warn li::before { background: var(--cs-medium); }
.cs-kv { display: grid; grid-template-columns: minmax(7rem, 11rem) minmax(0, 1fr); border-top: 1px solid var(--cs-line); font-size: .92rem; }
.cs-kv dt, .cs-kv dd { margin: 0; padding: .6rem .1rem; border-bottom: 1px solid var(--cs-line); overflow-wrap: anywhere; }
.cs-kv dt { color: var(--cs-muted); }
.cs-chips { display: flex; flex-wrap: wrap; gap: .4rem; margin: .2rem 0 .8rem; }
.cs-chip { display: inline-flex; align-items: center; gap: .4rem; padding: .18rem .65rem; border: 1px solid var(--cs-line-strong); border-radius: 999px; font-size: .8rem; background: var(--cs-surface); }
.cs-chip b { font-weight: 600; }
.cs-dist { display: flex; height: 8px; border-radius: 4px; overflow: hidden; background: var(--cs-surface-strong); }
.cs-dist span { display: block; height: 100%; }
.cs-dist-legend { display: flex; flex-wrap: wrap; gap: .4rem 1.4rem; margin-top: .6rem; font-size: .85rem; color: var(--cs-muted); }
.cs-dist-legend i { display: inline-block; width: .6rem; height: .6rem; border-radius: 2px; margin-right: .4rem; }
.cs-empty { border: 1px dashed var(--cs-line-strong); border-radius: 8px; padding: 1.5rem 1.2rem; text-align: center; margin: .4rem 0 1rem; }
.cs-empty-title { font-weight: 600; font-size: .95rem; }
.cs-empty-text { color: var(--cs-muted); font-size: .88rem; margin-top: .2rem; }
.cs-note { color: var(--cs-muted); font-size: .82rem; line-height: 1.5; max-width: 80ch; }

/* ---------- Sign-in ---------- */
.cs-auth-brand { display: flex; align-items: center; gap: .75rem; margin-bottom: 2.2rem; }
.cs-auth-name { font-size: 1.15rem; font-weight: 600; letter-spacing: -.01em; }
.cs-auth-head { font-size: 2.1rem; font-weight: 600; letter-spacing: -.025em; line-height: 1.15; margin-bottom: .8rem; max-width: 18ch; }
.cs-auth-copy { color: var(--cs-muted); max-width: 46ch; line-height: 1.55; margin-bottom: 1.6rem; }
.cs-auth-points { list-style: none; padding: 0; margin: 0 0 1.6rem; max-width: 46ch; border-top: 1px solid var(--cs-line); }
.cs-auth-points li { padding: .65rem 0; border-bottom: 1px solid var(--cs-line); font-size: .93rem; }
.cs-auth-points b { font-weight: 600; display: block; }
.cs-auth-points span { color: var(--cs-muted); font-size: .86rem; }

/* ---------- Sign-in v2 ---------- */
.cs-hero { position: relative; overflow: hidden; border-radius: 16px; padding: 2.6rem 2.4rem; min-height: 560px;
  color: #f2f6fc; background: radial-gradient(120% 90% at 0% 0%, var(--cs-hero2) 0%, var(--cs-hero1) 62%);
  box-shadow: 0 20px 50px -24px rgba(8,20,48,.55); }
.cs-hero::before { content: ""; position: absolute; inset: 0; opacity: .16;
  background-image: linear-gradient(rgba(255,255,255,.35) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.35) 1px, transparent 1px);
  background-size: 36px 36px; -webkit-mask-image: radial-gradient(90% 70% at 20% 10%, #000, transparent); mask-image: radial-gradient(90% 70% at 20% 10%, #000, transparent); }
.cs-hero > * { position: relative; }
.stApp .cs-hero, .stApp .cs-hero .cs-auth-name, .stApp .cs-hero .cs-auth-head, .stApp .cs-hero b { color: #fff; }
.cs-hero .cs-auth-head { font-size: 2.3rem; max-width: 16ch; }
.stApp .cs-hero .cs-auth-copy, .stApp .cs-hero .cs-auth-points span { color: rgba(235,242,252,.76); }
.cs-hero .cs-auth-points { border-top: 1px solid rgba(255,255,255,.18); }
.cs-hero .cs-auth-points li { border-bottom: 1px solid rgba(255,255,255,.14); display: flex; gap: .8rem; align-items: flex-start; }
.cs-ico { flex: none; width: 30px; height: 30px; border-radius: 8px; display: grid; place-items: center; background: rgba(255,255,255,.12); border: 1px solid rgba(255,255,255,.18); margin-top: .1rem; }
.cs-ico svg { width: 16px; height: 16px; stroke: #fff; fill: none; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.stApp .cs-hero-foot { margin-top: 1.4rem; font-size: .78rem; color: rgba(235,242,252,.6); }
.cs-formhead { margin: .2rem 0 .9rem; }
.cs-formhead .t { font-size: 1.5rem; font-weight: 600; letter-spacing: -.02em; }
.cs-formhead .s { color: var(--cs-muted); font-size: .9rem; margin-top: .15rem; }
.cs-trust { display: flex; gap: .5rem 1rem; flex-wrap: wrap; justify-content: center; color: var(--cs-muted); font-size: .76rem; margin-top: .9rem; }
.cs-trust span::before { content: "\2713"; margin-right: .35rem; color: var(--cs-low); }
@media (max-width: 760px) { .cs-hero { min-height: 0; padding: 1.6rem 1.3rem; } .cs-hero .cs-auth-head { font-size: 1.7rem; } }
</style>
"""


THEME_VARS = {
    "light": {"bg": "#f5f7fb", "bg2": "#ffffff", "side": "#ffffff", "text": "#0f1b2d", "muted": "#5b6b82",
              "line": "rgba(15,27,45,.12)", "accent": "#1f5fd1", "input": "#ffffff", "hero1": "#0d2a5c", "hero2": "#1f5fd1"},
    "dark":  {"bg": "#0a111b", "bg2": "#111b29", "side": "#0d1622", "text": "#e6edf4", "muted": "#93a3b8",
              "line": "rgba(230,237,244,.12)", "accent": "#4b8bf5", "input": "#0d1622", "hero1": "#07101d", "hero2": "#16336b"},
}


def current_theme() -> str:
    if "theme" not in st.session_state:
        st.session_state["theme"] = "dark"
    return st.session_state["theme"]


def theme_css(mode: str) -> str:
    t = THEME_VARS.get(mode, THEME_VARS["dark"])
    return f"""
<style>
:root, .stApp {{ color-scheme: {mode}; }}
.stApp {{ --cs-accent: {t['accent']}; background: {t['bg']}; color: {t['text']}; }}
.stApp, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp [data-testid="stWidgetLabel"] p,
.stApp [data-testid="stMarkdownContainer"] p {{ color: {t['text']}; }}
.stApp [data-testid="stHeader"] {{ background: transparent; }}
section[data-testid="stSidebar"] {{ background: {t['side']}; }}
section[data-testid="stSidebar"] > div {{ background: {t['side']}; }}
.stApp [data-baseweb="input"], .stApp [data-baseweb="textarea"], .stApp [data-baseweb="select"] > div {{
  background: {t['input']} !important; border-color: {t['line']} !important; }}
.stApp input, .stApp textarea {{ color: {t['text']} !important; -webkit-text-fill-color: {t['text']}; }}
.stApp [data-baseweb="input"]:focus-within, .stApp [data-baseweb="textarea"]:focus-within {{
  border-color: {t['accent']} !important; box-shadow: 0 0 0 3px color-mix(in srgb, {t['accent']} 25%, transparent); }}
.stApp [data-testid="stVerticalBlockBorderWrapper"] {{ background: {t['bg2']}; border-color: {t['line']}; }}
.stApp .stButton > button[kind="primary"], .stApp .stFormSubmitButton > button[kind="primary"],
.stApp .stFormSubmitButton > button[data-testid="stBaseButton-primaryFormSubmit"] {{
  background: {t['accent']}; border-color: {t['accent']}; color: #fff; }}
.stApp .stButton > button:not([kind="primary"]), .stApp .stDownloadButton > button {{ border-color: {t['line']}; background: transparent; color: {t['text']}; }}
.stApp div[data-testid="stMetric"], .stApp .cs-stats {{ background: {t['bg2']}; }}
.stApp [data-baseweb="tab-list"] {{ gap: .25rem; border-bottom: 1px solid {t['line']}; }}
.stApp button[data-baseweb="tab"] {{ color: {t['muted']}; }}
.stApp button[data-baseweb="tab"][aria-selected="true"] {{ color: {t['text']}; }}
.stApp [data-baseweb="tab-highlight"] {{ background-color: {t['accent']}; }}
.stApp {{ --cs-hero1: {t['hero1']}; --cs-hero2: {t['hero2']}; --cs-card: {t['bg2']}; --cs-ink: {t['text']}; --cs-sub: {t['muted']}; }}
</style>
"""


def theme_toggle(key: str = "theme_toggle") -> None:
    """Light/Dark switch that persists in the session."""
    mode = current_theme()
    choice = st.segmented_control("Theme", ["Light", "Dark"], default=mode.capitalize(),
                                  key=key, label_visibility="collapsed",
                                  selection_mode="single") if hasattr(st, "segmented_control") else None
    if choice and choice.lower() != mode:
        st.session_state["theme"] = choice.lower()
        st.rerun()


def e(value) -> str:
    """Escape any value for safe inclusion in HTML."""
    return html.escape("" if value is None else str(value), quote=True)


def _flat(markup: str) -> str:
    # Markdown treats 4+ leading spaces as a code block, so flatten the markup.
    return "".join(line.strip() for line in markup.splitlines())


def _render(markup: str) -> None:
    st.markdown(_flat(markup), unsafe_allow_html=True)


def tier_of(score) -> str:
    value = float(score or 0)
    return "high" if value >= 70 else "medium" if value >= 40 else "low"


def inject_theme() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown(theme_css(current_theme()), unsafe_allow_html=True)


# ---------------------------------------------------------------- widgets
def button(label, **kwargs):
    """Full-width button that works across Streamlit versions."""
    try:
        return st.button(label, width="stretch", **kwargs)
    except Exception:
        return st.button(label, use_container_width=True, **kwargs)


def submit(label, **kwargs):
    """Full-width form submit button that works across Streamlit versions."""
    try:
        return st.form_submit_button(label, width="stretch", **kwargs)
    except Exception:
        return st.form_submit_button(label, use_container_width=True, **kwargs)


def dataframe(data, **kwargs):
    """Full-width dataframe that works across Streamlit versions."""
    try:
        return st.dataframe(data, width="stretch", **kwargs)
    except Exception:
        return st.dataframe(data, use_container_width=True, **kwargs)


def history_table(frame: pd.DataFrame, rows: int | None = None) -> None:
    """Scan table with a readable header row and an inline risk bar."""
    view = frame.head(rows) if rows else frame
    view = view.rename(columns={"id": "ID", "scan_type": "Type", "target": "Target",
                                "score": "Risk", "created_at": "Created", "status": "Status"})
    config = {"Risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d")}
    dataframe(view, hide_index=True, column_config=config)


def records_table(records, empty_title="Nothing to show", empty_text="") -> None:
    if records is None or len(records) == 0:
        empty(empty_title, empty_text)
        return
    dataframe(pd.DataFrame(records), hide_index=True)


# ------------------------------------------------------------ page chrome
def brand_block() -> None:
    _render(f'<div class="cs-brand">{LOGO_SVG}<div><div class="cs-brand-name">CyberSentinel AI</div>'
            '<div class="cs-brand-sub">Threat detection and risk analysis</div></div></div>')


def nav_group(label: str) -> None:
    _render(f'<div class="cs-nav-group">{e(label)}</div>')


def nav_button(label: str, key: str, icon: str, active: bool):
    return button(label, key=key, icon=icon, type="primary" if active else "secondary")


def account_block(username: str, role: str) -> None:
    initial = (username or "?")[:1].upper()
    _render(f'<div class="cs-account"><div class="cs-avatar">{e(initial)}</div><div>'
            f'<div class="cs-account-name">{e(username)}</div>'
            f'<div class="cs-account-role">{e(str(role).capitalize())}</div></div></div>')


def page_header(group: str, title: str, description: str) -> None:
    _render(f'<div class="cs-page"><div class="cs-crumb">{e(group)} / {e(title)}</div>'
            f'<div class="cs-title">{e(title)}</div><div class="cs-desc">{e(description)}</div></div>')


def section(title: str, subtitle: str = "") -> None:
    sub = f'<div class="cs-section-sub">{e(subtitle)}</div>' if subtitle else ""
    _render(f'<div class="cs-section"><div class="cs-section-title">{e(title)}</div>{sub}</div>')


def note(text: str) -> None:
    _render(f'<div class="cs-note">{e(text)}</div>')


def empty(title: str, text: str = "") -> None:
    body = f'<div class="cs-empty-text">{e(text)}</div>' if text else ""
    _render(f'<div class="cs-empty"><div class="cs-empty-title">{e(title)}</div>{body}</div>')


# ------------------------------------------------------- result components
def verdict_panel(score, assessment: dict, headline: str | None = None, detail: str = "") -> None:
    """Severity, score meter and evidence strength for one scan result."""
    value = max(0.0, min(100.0, float(score or 0)))
    severity = (assessment or {}).get("severity") or tier_of(value)
    colour = f"var(--cs-{severity})"
    headline = headline or SEVERITY_LABEL.get(severity, "Result")
    detail_html = f'<div class="cs-verdict-sub">{e(detail)}</div>' if detail else ""
    strength = str((assessment or {}).get("confidence", "unavailable")).capitalize()
    basis = (assessment or {}).get("confidence_basis", "")
    _render(f"""
    <div class="cs-verdict" style="--sev:{colour}">
      <div>
        <div class="cs-sev">{e(SEVERITY_LABEL.get(severity, severity))}</div>
        <div class="cs-verdict-text">{e(headline)}</div>
        {detail_html}
      </div>
      <div class="cs-score">
        <div><span class="cs-score-num">{value:.0f}</span><span class="cs-score-den">/ 100</span></div>
        <div class="cs-score-label">Risk score</div>
      </div>
      <div class="cs-meter-wrap">
        <div class="cs-meter" role="meter" aria-label="Risk score" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{value:.0f}">
          <div class="cs-meter-track"></div>
          <div class="cs-meter-fill" style="clip-path: inset(0 {100 - value:.1f}% 0 0)"></div>
        </div>
        <div class="cs-meter-scale"><span style="left:0">0</span><span style="left:40%">40 medium</span><span style="left:70%">70 high</span><span style="left:100%">100</span></div>
      </div>
      <div class="cs-evidence"><b>Evidence strength: {e(strength)}.</b> <span>{e(basis)} This is a heuristic summary, not a calibrated probability.</span></div>
    </div>""")


def stat_strip(items) -> None:
    """items: iterable of (label, value[, hint[, tone]]) shown as one connected strip."""
    cells = []
    for item in items:
        label, value = item[0], item[1]
        hint = item[2] if len(item) > 2 and item[2] else ""
        tone = item[3] if len(item) > 3 and item[3] else ""
        tone_class = f" cs-tone-{e(tone)}" if tone in ("high", "medium", "low") else ""
        hint_html = f'<div class="cs-stat-hint">{e(hint)}</div>' if hint else ""
        cells.append(f'<div class="cs-stat"><div class="cs-stat-label">{e(label)}</div>'
                     f'<div class="cs-stat-value{tone_class}">{e(value)}</div>{hint_html}</div>')
    _render(f'<div class="cs-stats"><div class="cs-stats-in">{"".join(cells)}</div></div>')


def indicator_list(items, empty_text="Nothing matched.", warn=False, mono=False) -> None:
    items = list(items or [])
    if not items:
        empty(empty_text)
        return
    css = "cs-list warn" if warn else "cs-list"
    mono_open, mono_close = ('<span class="cs-mono">', "</span>") if mono else ("", "")
    rows = "".join(f"<li><div>{mono_open}{e(item)}{mono_close}</div></li>" for item in items)
    _render(f'<ul class="{css}">{rows}</ul>')


def key_values(pairs, mono_keys=()) -> None:
    rows = []
    for label, value in pairs:
        text = value if value not in (None, "") else "Not available"
        cell = f'<span class="cs-mono">{e(text)}</span>' if label in mono_keys else e(text)
        rows.append(f"<dt>{e(label)}</dt><dd>{cell}</dd>")
    _render(f'<dl class="cs-kv">{"".join(rows)}</dl>')


def chips(pairs) -> None:
    """pairs: iterable of (label, count)."""
    pairs = list(pairs or [])
    if not pairs:
        return
    body = "".join(f'<span class="cs-chip">{e(k)} <b>{e(v)}</b></span>' for k, v in pairs)
    _render(f'<div class="cs-chips">{body}</div>')


def distribution(high: int, medium: int, low: int) -> None:
    total = max(1, high + medium + low)
    parts = [("high", high, "High"), ("medium", medium, "Medium"), ("low", low, "Low")]
    bar = "".join(f'<span style="width:{count / total * 100:.2f}%;background:var(--cs-{key})"></span>'
                  for key, count, _ in parts)
    legend = "".join(f'<span><i style="background:var(--cs-{key})"></i>{label} {count}</span>'
                     for key, count, label in parts)
    _render(f'<div class="cs-dist" role="img" aria-label="Scans by risk tier">{bar}</div>'
            f'<div class="cs-dist-legend">{legend}</div>')


def raw_output(result, label="Raw analyzer output") -> None:
    with st.expander(label):
        st.json(result)


# ----------------------------------------------------------------- sign-in
def auth_intro() -> None:
    icons = {
        "link": '<svg viewBox="0 0 24 24"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg>',
        "net": '<svg viewBox="0 0 24 24"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v5M12 12l-6 5M12 12l6 5"/></svg>',
        "case": '<svg viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/></svg>',
    }
    points = [
        ("link", "URLs, email and files", "Score suspicious links, messages and attachments with transparent evidence."),
        ("net", "Packet captures and logs", "Surface scans, beaconing, brute force and unusual flows."),
        ("case", "Investigations", "Group related scans, assign owners, keep notes and export PDF reports."),
    ]
    rows = "".join(f'<li><div class="cs-ico">{icons[i]}</div><div><b>{e(t)}</b><span>{e(d)}</span></div></li>'
                   for i, t, d in points)
    _render(f"""
    <div class="cs-hero">
      <div class="cs-auth-brand">{LOGO_SVG}<div class="cs-auth-name">CyberSentinel AI</div></div>
      <div class="cs-auth-head">One workspace for threat triage</div>
      <div class="cs-auth-copy">Unified detection and risk analysis for analysts. Findings are triage aids, not proof of compromise or safety.</div>
      <ul class="cs-auth-points">{rows}</ul>
      <div class="cs-hero-foot">Evidence-first scoring &middot; Local model inference &middot; Audit trail on every action</div>
    </div>""")


def auth_form_head(title: str = "Welcome back", sub: str = "Sign in to your analyst workspace.") -> None:
    _render(f'<div class="cs-formhead"><div class="t">{e(title)}</div><div class="s">{e(sub)}</div></div>')


def auth_trust() -> None:
    _render('<div class="cs-trust"><span>Passwords hashed with bcrypt</span><span>Sessions expire when idle</span></div>')
