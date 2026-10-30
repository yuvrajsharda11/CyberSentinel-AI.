import sqlite3
import json
import os
import ast
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

import ui
from services.auth import (
    init_db, register_user, authenticate,
    create_session, validate_session, invalidate_session,
)
from services.file_analyzer import analyze_file
from services.image_analyzer import analyze_image
from services.log_analyzer import analyze_logs
from services.pcap_analyzer import analyze_pcap
from services.reports import create_pdf_report
from services.risk_engine import summarize_history
from services.url_detector import analyze_url
from services.extended_features import (
    init_extended_db, record_audit, add_feedback, role_for, audit_frame,
    compare_scans, extract_iocs, analyze_email, answer_log_query, map_attack,
    feedback_frame, set_role,
    incident_timeline, set_scan_workflow, workflow_for, delete_old_scans,
    list_investigations, create_investigation, update_investigation,
    attach_investigation_scans, investigation_detail,
)
from services.domain_intel import lookup_domain, lookup_file_hash
from services.behavior import detect_flow_outliers
from services.chatbot import load_user_scans, answer_question
from services.evidence import assess
from services.cybercrime import (
    CASE_STATUSES, CASE_TYPES, INDICATOR_TYPES, add_case_event, add_evidence,
    add_indicator, attach_scans as attach_case_scans, create_case as create_cybercrime_case,
    export_case_bundle, get_case as get_cybercrime_case, init_cybercrime_db,
    list_case_events, list_case_evidence, list_case_indicators, list_case_scans,
    list_cases as list_cybercrime_cases, related_case_indicators,
    update_case as update_cybercrime_case,
)

DB = os.getenv("CYBERSENTINEL_DB", "data/cybersecurity.db")
REPORT_DIR = Path(os.getenv("CYBERSENTINEL_REPORT_DIR", "data/reports"))
Path(DB).parent.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)
init_db(DB)
init_extended_db(DB)
init_cybercrime_db(DB)

st.set_page_config(page_title="CyberSentinel AI", page_icon=":material/shield_lock:", layout="wide",
                   initial_sidebar_state="expanded")
ui.inject_theme()

WORKFLOW_STATUSES = ["New", "Reviewing", "Confirmed", "Benign", "Resolved"]


def save_scan(username, scan_type, target, result, score):
    result = dict(result)
    result["assessment"] = assess(scan_type, result, score)
    con = sqlite3.connect(DB)
    con.execute("""INSERT INTO scans(username, scan_type, target, result, score, created_at)
                   VALUES(?,?,?,?,?,?)""",
                (username, scan_type, target, str(result), float(score),
                 datetime.now().isoformat(timespec="seconds")))
    con.commit()
    con.close()
    record_audit(DB, username, "scan", f"type={scan_type}; target={target}")


def get_history(username):
    con = sqlite3.connect(DB)
    df = pd.read_sql_query(
        "SELECT id, scan_type, target, score, created_at FROM scans WHERE username=? ORDER BY id DESC",
        con, params=(username,))
    con.close()
    return df


def filter_history_controls(history, key_prefix):
    if history.empty:
        return history
    frame = history.copy()
    frame["_created"] = pd.to_datetime(frame["created_at"], errors="coerce")
    valid = frame["_created"].dropna()
    if valid.empty:
        return frame.drop(columns=["_created"])
    c1, c2 = st.columns(2)
    date_range = c1.date_input("Date range", value=(valid.min().date(), valid.max().date()), key=f"{key_prefix}_dates")
    tier = c2.selectbox("Risk tier", ["All", "High", "Medium", "Low"], key=f"{key_prefix}_tier")
    selected = frame
    if isinstance(date_range, tuple) and len(date_range) == 2:
        start, end = pd.Timestamp(date_range[0]), pd.Timestamp(date_range[1]) + pd.Timedelta(days=1)
        selected = selected[(selected["_created"] >= start) & (selected["_created"] < end)]
    if tier == "High": selected = selected[selected["score"] >= 70]
    elif tier == "Medium": selected = selected[(selected["score"] >= 40) & (selected["score"] < 70)]
    elif tier == "Low": selected = selected[selected["score"] < 40]
    return selected.drop(columns=["_created"])


# --- Session bootstrap: a server-side token backs the Streamlit session so
# idle logins expire even if the browser tab is left open. ---
if "user" not in st.session_state:
    st.session_state.user = None
if "session_token" not in st.session_state:
    st.session_state.session_token = None

if st.session_state.user and st.session_state.session_token:
    validated_user = validate_session(DB, st.session_state.session_token)
    if not validated_user:
        st.session_state.user = None
        st.session_state.session_token = None
        st.info("You were signed out after a period of inactivity. Sign in again to continue.")

# ------------------------------------------------------------------ sign in
if not st.session_state.user:
    top_l, top_r = st.columns([5, 1.4])
    with top_r:
        ui.theme_toggle("theme_toggle_login")
    intro, form_col = st.columns([1.15, 1], gap="large")
    with intro:
        ui.auth_intro()
    with form_col:
        st.write("")
        with st.container(border=True):
            tab_in, tab_up = st.tabs(["Sign in", "Create account"])
            with tab_in:
                ui.auth_form_head("Welcome back", "Sign in to your analyst workspace.")
                with st.form("login_form", border=False):
                    u = st.text_input("Username", key="login_u", placeholder="your.username")
                    p = st.text_input("Password", type="password", key="login_p", placeholder="Enter your password")
                    signed_in = ui.submit("Sign in", type="primary")
                if signed_in:
                    ok, msg = authenticate(DB, u, p)
                    if ok:
                        st.session_state.user = u.strip()
                        st.session_state.session_token = create_session(DB, u.strip())
                        record_audit(DB, u.strip(), "login")
                        st.rerun()
                    else:
                        st.error(msg)
            with tab_up:
                ui.auth_form_head("Create your account", "Set up access in under a minute.")
                with st.form("register_form", border=False):
                    nu = st.text_input("Choose a username", placeholder="e.g. analyst.jdoe")
                    npw = st.text_input("Choose a password", type="password", placeholder="At least 8 characters",
                                        help="Use 8 or more characters, with at least one letter and one number.")
                    created = ui.submit("Create account")
                if created:
                    ok, msg = register_user(DB, nu, npw)
                    (st.success if ok else st.error)(msg)
        ui.auth_trust()
    st.stop()

user = st.session_state.user
role = role_for(DB, user)

all_pages = {
    "Overview": ["Dashboard"],
    "Analyze": ["URL & Phishing", "PCAP Analyzer", "Log Analyzer", "File Security", "Email Analyzer", "Image Analyzer"],
    "Intelligence": ["Threat Toolkit", "Model Evaluation", "NLP Log Assistant"],
    "Assistant": ["CyberSentinel Chat"],
    "Workspace": ["Scan History", "Investigations", "Cybercrime Cases", "Feedback & Audit"],
    "Help": ["How to Use"],
}
if role == "admin":
    all_pages["Workspace"].append("Admin")

page_icons = {
    "Dashboard": ":material/space_dashboard:",
    "URL & Phishing": ":material/link:",
    "PCAP Analyzer": ":material/lan:",
    "Log Analyzer": ":material/receipt_long:",
    "File Security": ":material/description:",
    "Email Analyzer": ":material/mail:",
    "Image Analyzer": ":material/image_search:",
    "Threat Toolkit": ":material/travel_explore:",
    "Model Evaluation": ":material/analytics:",
    "NLP Log Assistant": ":material/manage_search:",
    "CyberSentinel Chat": ":material/forum:",
    "Scan History": ":material/history:",
    "Investigations": ":material/folder_open:",
    "Cybercrime Cases": ":material/gavel:",
    "Feedback & Audit": ":material/fact_check:",
    "Admin": ":material/admin_panel_settings:",
    "How to Use": ":material/menu_book:",
}
if "current_page" not in st.session_state or st.session_state.current_page not in sum(all_pages.values(), []):
    st.session_state.current_page = "Dashboard"

# ------------------------------------------------------------------ sidebar
with st.sidebar:
    ui.brand_block()
    for group, items in all_pages.items():
        ui.nav_group(group)
        for item in items:
            if ui.nav_button(item, f"page_{item}", page_icons[item], st.session_state.current_page == item):
                st.session_state.current_page = item
                st.rerun()
    ui.account_block(user, role)
    ui.theme_toggle("theme_toggle_side")
    if ui.button("Sign out", key="sidebar_logout", icon=":material/logout:"):
        invalidate_session(DB, st.session_state.session_token)
        record_audit(DB, user, "logout")
        st.session_state.user = None
        st.session_state.session_token = None
        st.rerun()

page = st.session_state.current_page
page_group = next(group for group, items in all_pages.items() if page in items)
descriptions = {
    "Dashboard": "A current view of scan activity, risk trends, and indicators that recur across investigations.",
    "URL & Phishing": "Inspect URL structure and review the model and rule evidence behind its risk estimate.",
    "PCAP Analyzer": "Summarize a packet capture and surface traffic patterns that merit investigation.",
    "Log Analyzer": "Find suspicious events, extract indicators, and map selected evidence to ATT&CK.",
    "File Security": "Review file metadata and static indicators without executing the uploaded file.",
    "Email Analyzer": "Inspect an email's headers, links, and wording for common phishing signals.",
    "Image Analyzer": "Extract text and QR links from screenshots, then review any URLs with the existing analyzer.",
    "Threat Toolkit": "Check public domain registration and reputation sources when you choose to share a domain.",
    "Model Evaluation": "Review the URL model's reported metrics and their dataset limitations.",
    "NLP Log Assistant": "Search saved log findings with simple natural-language requests.",
    "CyberSentinel Chat": "Ask cybersecurity questions or discuss a selected scan using its saved evidence.",
    "How to Use": "A quick guide to each section, what it does, and what to provide.",
    "Scan History": "Review, compare, and annotate previous analysis results.",
    "Investigations": "Group related scans, assign an owner, and track an incident through review and resolution.",
    "Cybercrime Cases": "Record reported online crime, preserve evidence hashes, track timelines, and find repeated indicators.",
    "Feedback & Audit": "Track analyst assessments and account activity.",
    "Admin": "Manage analyst and administrator roles.",
}
ui.page_header(page_group, page, descriptions.get(page, ""))

# ---------------------------------------------------------------- dashboard
if page == "Dashboard":
    history = get_history(user)
    summary = summarize_history(history)
    has_data = len(history) > 0

    ui.stat_strip([
        ("Total scans", len(history), "Saved to your account"),
        ("Overall risk", f"{summary['overall_score']}/100", "Recent scans weigh more (7-day half-life)",
         summary["tier"] if has_data else None),
        ("Trend", summary["trend"].capitalize(), "Recent scans compared with earlier ones"),
        ("High-risk scans", summary["counts"]["high"], "Risk score of 70 or more",
         "high" if summary["counts"]["high"] else None),
    ])

    if not has_data:
        ui.empty("No scans yet", "Choose a tool under Analyze in the sidebar. Every scan you run is saved and summarized here.")
    else:
        ui.section("Risk distribution", "All scans, grouped by risk tier.")
        ui.distribution(summary["counts"]["high"], summary["counts"]["medium"], summary["counts"]["low"])

        ui.section("Recent activity")
        with st.container(border=True):
            history = filter_history_controls(history, "dashboard")
            history["status"] = [workflow_for(DB, user, int(scan_id))[0] for scan_id in history["id"]]
            f1, f2 = st.columns(2)
            types = ["All"] + sorted(history["scan_type"].unique().tolist())
            statuses = ["All"] + sorted(history["status"].unique().tolist())
            chosen_type = f1.selectbox("Scan type", types, key="dashboard_type")
            chosen_status = f2.selectbox("Investigation status", statuses, key="dashboard_status")
        view = history.copy()
        if chosen_type != "All": view = view[view["scan_type"] == chosen_type]
        if chosen_status != "All": view = view[view["status"] == chosen_status]
        if len(view):
            ui.history_table(view, rows=25)
            if len(view) > 25:
                ui.note(f"Showing the 25 most recent of {len(view)} matching scans. Open Scan History to see all of them.")
        else:
            ui.empty("No scans match these filters", "Widen the date range or reset the filters above.")

        if len(history):
            col_a, col_b = st.columns(2, gap="large")
            with col_a:
                ui.section("Scans by type")
                st.bar_chart(history.groupby("scan_type").size(), color="#2f6fed")
            with col_b:
                ui.section("Risk over time", "Most recent 30 scans.")
                st.line_chart(history.sort_values("id").tail(30).set_index("created_at")["score"], color="#2f6fed")

        timeline, related = incident_timeline(DB, user)
        ui.section("Cross-scan analysis")
        tab_timeline, tab_related = st.tabs(["Incident timeline", "Repeated indicators"])
        with tab_timeline:
            if timeline:
                frame = pd.DataFrame(timeline).rename(columns={"time": "Time", "scan_id": "Scan", "type": "Type",
                                                               "target": "Target", "risk": "Risk"})
                ui.dataframe(frame, hide_index=True,
                             column_config={"Risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d")})
            else:
                ui.empty("No timeline yet")
        with tab_related:
            if related:
                ui.note("Indicators that appear in more than one scan can point to a shared campaign or source.")
                frame = pd.DataFrame([{"Type": r["type"], "Indicator": r["indicator"],
                                       "Scans": ", ".join(map(str, r["scan_ids"]))} for r in related])
                ui.dataframe(frame, hide_index=True)
                related_labels = [f"{item['type']}: {item['indicator']} (scans {', '.join(map(str, item['scan_ids']))})" for item in related]
                selected_indicator = st.selectbox("Show the scans behind an indicator", related_labels, key="repeated_indicator")
                indicator_record = related[related_labels.index(selected_indicator)]
                linked_history = get_history(user)
                linked_history = linked_history[linked_history["id"].isin(indicator_record["scan_ids"])].copy()
                if len(linked_history):
                    linked_history["status"] = [workflow_for(DB, user, int(scan_id))[0] for scan_id in linked_history["id"]]
                    ui.history_table(linked_history)
            else:
                ui.empty("No repeated indicators", "Indicators that show up in more than one scan will be listed here.")

# ------------------------------------------------------------------- guide
elif page == "How to Use":
    ui.section("Choose a tool for the task", "Pick a tool from the sidebar. Uploads are analyzed when you select the matching Analyze button.")
    guides = [
        ("Dashboard", "See scan counts, recent activity, risk trends, and indicators repeated across scans.", "No input needed; it summarizes scans saved to your account."),
        ("URL & Phishing", "Estimate whether a URL looks suspicious using model output and transparent rules.", "Paste a full URL such as https://example.com, then select Analyze URL."),
        ("PCAP Analyzer", "Summarize network packets and look for port scanning, beaconing, DNS anomalies, and unusual flows.", "Upload a .pcap or .pcapng file, then select Analyze PCAP."),
        ("Log Analyzer", "Find suspicious patterns in text logs, identify possible brute force, map selected events to ATT&CK, and extract indicators.", "Upload a .log, .txt, or .csv file, then select Analyze Logs."),
        ("File Security", "Inspect file type, hashes, extension mismatch, macros, and other static indicators. The app does not run uploaded files.", "Upload a file, then select Analyze File."),
        ("Email Analyzer", "Review an email's sender and reply-to fields, authentication results, wording, and links.", "Upload an .eml email file, then select Analyze email."),
        ("Image Analyzer", "Extract screenshot text and QR payloads locally, and check any extracted URLs.", "Upload a PNG, JPEG, or WebP screenshot, then select Analyze image. QR links are shown but never opened."),
        ("Threat Toolkit", "Look up public domain registration and optional VirusTotal reputation.", "Enter a public domain and check the disclosure box before looking it up."),
        ("NLP Log Assistant", "Search events from a log scan already saved to your account.", "Choose a saved log scan and ask for failed logins, critical events, or events with an IP."),
        ("CyberSentinel Chat", "Ask questions about saved scans, request a summary, or get general next-step suggestions.", "Try 'Show high-risk findings' or 'Why was scan 12 flagged?'"),
        ("Model Evaluation", "View the URL model's reported evaluation metrics and feature importance.", "No input needed. Metrics come from the held-out split recorded when the model was trained."),
        ("Scan History", "Review saved scans, compare two results, add analyst feedback, and create PDF reports.", "Choose a scan from the list to see its details and actions."),
        ("Investigations", "Group related scans, assign an owner, and track response status and notes.", "Create an investigation, then attach scans from your account."),
        ("Cybercrime Cases", "Record phishing, fraud, account-takeover, identity-theft, or extortion reports with evidence and indicators.", "Create a case, add timeline events and evidence files, then export a case bundle. Evidence stays in the private application data folder."),
        ("Feedback & Audit", "Review analyst feedback and recorded account activity.", "No input needed; administrators can see all users' records."),
        ("Admin", "Change account roles. Only administrator accounts can open this page.", "Select an account and role, then select Update role."),
    ]
    for title, purpose, instructions in guides:
        with st.expander(title):
            st.write(purpose)
            st.caption("How to use: " + instructions)
    st.info("Risk scores and AI outputs are triage aids. Check the supporting evidence before making security decisions.")

# --------------------------------------------------------------- URL & phishing
elif page == "URL & Phishing":
    with st.container(border=True):
        with st.form("url_form", border=False):
            url = st.text_input("URL to analyze", placeholder="https://example.com/login",
                                help="The URL is analyzed locally. It is not requested or opened.")
            submitted = ui.submit("Analyze URL", type="primary", icon=":material/search:")
    if submitted and not url.strip():
        st.warning("Enter a URL to analyze.")
    elif submitted:
        url = url.strip()
        result = analyze_url(url)
        score = result["risk_score"]
        save_scan(user, "URL", url, result, score)
        assessment = assess("URL", result, score)
        result["assessment"] = assessment
        ui.verdict_panel(score, assessment, result["verdict"], f"Detection mode: {result['detection_mode']}")
        ui.stat_strip([
            ("Phishing score", f'{result["phishing_probability"]:.1f}%', "Uncalibrated"),
            ("Model score", f'{result["ml_probability"]:.1f}%' if result["ml_probability"] is not None else "n/a", "Uncalibrated"),
            ("Rule-based score", result["rule_score"], "Transparent indicators"),
            ("Suspicious indicators", result["indicator_count"], "Matched rules"),
        ])
        left, right = st.columns([3, 2], gap="large")
        with left:
            ui.section("Indicators found")
            ui.indicator_list(result["indicators"], "No configured indicators matched.", warn=True)
        with right:
            ui.section("How the score is built")
            st.write(f"Final score = 65% model probability + 35% rule score when the model is available; otherwise the rule score is used. Current mode: **{result['detection_mode']}**.")
            if result.get("top_model_features"):
                st.caption("Most influential features in the model overall (not a per-URL explanation): "
                           + ", ".join(result["top_model_features"]))
        with st.expander("URL properties inspected"):
            st.json(result.get("features", {}))
        ui.raw_output(result)

# ---------------------------------------------------------------- PCAP analyzer
elif page == "PCAP Analyzer":
    with st.container(border=True):
        uploaded = st.file_uploader("Packet capture", type=["pcap", "pcapng"],
                                    help="Parsing is capped at 25 MB and 25,000 packets.")
        run = st.button("Analyze PCAP", type="primary", icon=":material/search:", disabled=uploaded is None)
    if uploaded and run:
        result = analyze_pcap(uploaded.getvalue())
        score = result["risk_score"]
        save_scan(user, "PCAP", uploaded.name, result, score)
        assessment = assess("PCAP", result, score)
        result["assessment"] = assessment
        if result.get("error"):
            ui.verdict_panel(score, assessment, "Capture could not be analyzed")
            st.error(f"Could not parse capture: {result['error']}")
        else:
            ui.verdict_panel(score, assessment, None, f"{result['packet_count']:,} packets analyzed from {uploaded.name}")
            if result.get("truncated"):
                st.warning(result.get("analysis_note", "Capture analysis was truncated by the packet limit."))
            ui.stat_strip([
                ("Packets", f"{result['packet_count']:,}"),
                ("Port scan indicators", len(result.get("port_scan_indicators", []))),
                ("Beaconing indicators", len(result.get("beaconing_indicators", []))),
                ("DNS anomalies", len(result.get("dns_anomalies", []))),
            ])
            tab_det, tab_conn, tab_flow = st.tabs(["Detections", "Connections", "Flow anomalies"])
            with tab_det:
                ui.section("Port scanning")
                ui.records_table(result.get("port_scan_indicators"), "No port scanning detected")
                ui.section("Beaconing", "Regular-interval traffic that can indicate command-and-control.")
                ui.records_table(result.get("beaconing_indicators"), "No beaconing detected")
                ui.section("DNS anomalies", "Long or high-entropy queries that can indicate tunneling or exfiltration.")
                ui.records_table(result.get("dns_anomalies"), "No anomalous DNS queries detected")
            with tab_conn:
                ui.section("Top connections by packet count")
                ui.records_table(result.get("top_connections"), "No connections recorded")
                ui.section("Top connections by bytes")
                ui.records_table(result.get("top_connections_by_bytes"), "No connections recorded")
            with tab_flow:
                outlier_result = detect_flow_outliers(result)
                ui.note("Isolation Forest flags flows that differ from the rest of this capture. An outlier is not proof of malicious activity.")
                if outlier_result["available"]:
                    ui.records_table(outlier_result["outliers"], "No outlier flows found")
                else:
                    st.info(outlier_result["reason"])
            ui.raw_output(result)

# ------------------------------------------------------------------ log analyzer
elif page == "Log Analyzer":
    with st.container(border=True):
        uploaded = st.file_uploader("Log file", type=["log", "txt", "csv"])
        run = st.button("Analyze Logs", type="primary", icon=":material/search:", disabled=uploaded is None)
    if uploaded and run:
        text = uploaded.getvalue().decode("utf-8", errors="ignore")
        result = analyze_logs(text)
        score = result["risk_score"]
        save_scan(user, "LOG", uploaded.name, result, score)
        assessment = assess("LOG", result, score)
        result["assessment"] = assessment
        ui.verdict_panel(score, assessment, result["verdict"], f"Source: {uploaded.name}")
        severity_breakdown = result.get("severity_breakdown", {})
        ui.stat_strip([
            ("Events flagged", len(result.get("events", []))),
            ("Brute-force sources", len(result.get("brute_force_source_ips", []) or []),
             "Likely attacking IPs", "high" if result.get("brute_force_source_ips") else None),
        ])
        if result.get("brute_force_source_ips"):
            st.warning("Likely brute-force source IP(s) detected.")
            ui.records_table(result["brute_force_source_ips"])
        tab_events, tab_attack, tab_ioc = st.tabs(["Events", "ATT&CK references", "Indicators of compromise"])
        iocs = extract_iocs(text)
        with tab_events:
            if severity_breakdown:
                ui.chips([(str(k).capitalize(), v) for k, v in severity_breakdown.items()])
            ui.records_table(result["events"], "No suspicious events found", "Absence of findings does not establish safety.")
        with tab_attack:
            mappings = map_attack(result["events"])
            ui.records_table(mappings, "No ATT&CK techniques matched", "References are shown only for events that match a known pattern.")
        with tab_ioc:
            for kind, values in iocs.items():
                with st.expander(f"{kind} ({len(values)})"):
                    if values:
                        ui.indicator_list(values, mono=True)
                    else:
                        st.caption("None found")
            st.download_button("Export indicators as JSON", json.dumps(iocs, indent=2),
                               file_name="indicators.json", mime="application/json", icon=":material/download:")
        ui.raw_output(result)

# ------------------------------------------------------------------ file security
elif page == "File Security":
    with st.container(border=True):
        uploaded = st.file_uploader("File to inspect")
        st.caption("Files are hashed and inspected statically. This application never executes uploaded files.")
        run = st.button("Analyze File", type="primary", icon=":material/search:", disabled=uploaded is None)
    if uploaded and run:
        result = analyze_file(uploaded.name, uploaded.getvalue())
        score = result["risk_score"]
        save_scan(user, "FILE", uploaded.name, result, score)
        assessment = assess("FILE", result, score)
        result["assessment"] = assessment
        ui.verdict_panel(score, assessment, None, f"Static analysis of {uploaded.name}")
        ui.stat_strip([
            ("Detected type", result["detected_type"]),
            ("Extension mismatch", "Yes" if result["extension_mismatch"] else "No", None,
             "medium" if result["extension_mismatch"] else None),
            ("Contains macros", "Yes" if result["contains_macros"] else "No", None,
             "medium" if result["contains_macros"] else None),
        ])
        ui.section("Indicators found")
        ui.indicator_list(result["indicators"], "No suspicious static indicators found.", warn=True)
        if result.get("pe_info"):
            with st.expander("PE header details"):
                st.json(result["pe_info"])
        ui.raw_output(result)

# ------------------------------------------------------------------ email analyzer
elif page == "Email Analyzer":
    with st.container(border=True):
        uploaded = st.file_uploader("Email message", type=["eml"],
                                    help="Header and body checks are heuristic and do not establish sender authenticity.")
        run = st.button("Analyze email", type="primary", icon=":material/search:", disabled=uploaded is None)
    if uploaded and run:
        result = analyze_email(uploaded.getvalue())
        save_scan(user, "EMAIL", uploaded.name, result, result["risk_score"])
        assessment = assess("EMAIL", result, result["risk_score"])
        result["assessment"] = assessment
        ui.verdict_panel(result["risk_score"], assessment, result["subject"] or "(No subject)", f"Source: {uploaded.name}")
        left, right = st.columns([3, 2], gap="large")
        with left:
            ui.section("Message")
            ui.key_values([("Subject", result["subject"] or "(none)"),
                           ("Sender", result["sender"] or "(not available)"),
                           ("Reply-To", result["reply_to"] or "(not set)")])
            ui.section("Links", "Shown as plain text so they cannot be opened by accident.")
            ui.indicator_list(result["urls"], "No links found.", mono=True)
        with right:
            ui.section("Indicators")
            ui.indicator_list(result["indicators"], "No configured warning indicators found.", warn=True)
        ui.section("Attachments", "Hashed locally; the files are not uploaded anywhere.")
        ui.records_table(result.get("attachments"), "No attachments found")
        st.info(result["summary"])
        ui.raw_output(result)

# ------------------------------------------------------------------ image analyzer
elif page == "Image Analyzer":
    ui.section("Image and screenshot analysis", "Extract visible text and QR payloads, then apply CyberSentinel's existing URL checks. This is local OCR and heuristic analysis, not a trained visual classifier.")
    with st.container(border=True):
        uploaded = st.file_uploader("Image or screenshot", type=["png", "jpg", "jpeg", "webp", "bmp", "tif", "tiff"],
                                    help="Maximum 10 MB and 20 megapixels. Image content is processed locally and links are never opened.")
        run = st.button("Analyze image", type="primary", icon=":material/image_search:", disabled=uploaded is None)
    if uploaded and run:
        result = analyze_image(uploaded.name, uploaded.getvalue())
        if result.get("error"):
            st.error(result["error"])
        else:
            score = result["risk_score"]
            save_scan(user, "IMAGE", uploaded.name, result, score)
            assessment = assess("IMAGE", result, score)
            result["assessment"] = assessment
            ui.verdict_panel(score, assessment, "Review extracted image content", result["analysis_method"])
            ui.stat_strip([
                ("Image size", result["image_dimensions"]),
                ("QR codes", len(result["qr_payloads"]), "Decoded locally"),
                ("URLs checked", len(result["url_results"]), "Not opened"),
                ("Risk score", f"{score}/100", "Heuristic triage only"),
            ])
            if result.get("ocr_error"):
                st.warning(result["ocr_error"])
            left, right = st.columns([3, 2], gap="large")
            with left:
                ui.section("Indicators")
                ui.indicator_list(result["indicators"], "No configured warning indicators matched.", warn=True)
                ui.section("Extracted URLs", "Review these as text. CyberSentinel did not open or request them.")
                if result["url_results"]:
                    ui.dataframe(pd.DataFrame([{"URL": item["url"], "Risk": item["risk_score"], "Assessment": item["verdict"]}
                                               for item in result["url_results"]]), hide_index=True)
                else:
                    ui.empty("No web URLs extracted")
            with right:
                ui.section("QR payloads", "Decoded content is displayed only; no QR link is opened.")
                ui.indicator_list(result["qr_payloads"], "No QR codes decoded.", mono=True)
                ui.section("Limits")
                ui.indicator_list(result["limitations"], warn=True)
            if result.get("ocr_text"):
                with st.expander("OCR text preview"):
                    st.text(result["ocr_text"] + ("\n[Text truncated for display.]" if result["ocr_truncated"] else ""))
            ui.raw_output(result)

# ------------------------------------------------------------------ threat toolkit
elif page == "Threat Toolkit":
    ui.section("Domain reputation")
    with st.container(border=True):
        st.warning("A lookup sends the domain name to public RDAP and, if configured, VirusTotal. Do not submit private or confidential domains.")
        domain = st.text_input("Public domain name", placeholder="example.com")
        consent = st.checkbox("I understand the domain will be sent to public lookup services")
        if st.button("Check domain reputation", icon=":material/travel_explore:"):
            if not domain.strip():
                st.warning("Enter a domain name first.")
            elif not consent:
                st.warning("Confirm that you understand the domain will be shared before running a lookup.")
            else:
                with st.expander("Lookup result", expanded=True):
                    st.json(lookup_domain(domain))
    ui.section("File hash reputation", "The hash is sent to VirusTotal when you choose to look it up. The file itself is never uploaded.")
    with st.container(border=True):
        file_hash = st.text_input("MD5, SHA-1, or SHA-256 hash", key="hash_lookup")
        hash_consent = st.checkbox("I understand this hash will be shared with VirusTotal", key="hash_consent")
        if st.button("Check file hash", icon=":material/fingerprint:"):
            if not file_hash.strip():
                st.warning("Enter a file hash first.")
            elif not hash_consent:
                st.warning("Confirm that you understand the hash will be shared before running a lookup.")
            else:
                with st.expander("Lookup result", expanded=True):
                    st.json(lookup_file_hash(file_hash))
    ui.note("VirusTotal reputation is enabled by setting VIRUSTOTAL_API_KEY in the deployment environment. RDAP registration details are best-effort.")

# ------------------------------------------------------------------ NLP log assistant
elif page == "NLP Log Assistant":
    con = sqlite3.connect(DB)
    saved = con.execute("SELECT id,target,created_at,result FROM scans WHERE username=? AND scan_type='LOG' ORDER BY id DESC LIMIT 50", (user,)).fetchall()
    con.close()
    if not saved:
        ui.empty("No saved log scans", "Analyze a log file first. This assistant searches the findings saved to your account.")
    else:
        with st.container(border=True):
            choices = {f"Scan {r[0]} · {r[1]} · {r[2]}": r for r in saved}
            label = st.selectbox("Saved log scan", list(choices))
            question = st.text_input("Ask about the findings", placeholder="Show critical events from an IP")
        try:
            scan_result = ast.literal_eval(choices[label][3])
            if question:
                answer = answer_log_query(question, scan_result.get("events", []))
                ui.section(f"Matched {answer['matched_count']} events")
                ui.note(answer["explanation"])
                ui.records_table(answer["events"], "No events matched", "Try asking for failed logins, critical events, or events from an IP.")
        except Exception:
            st.error("Could not read the saved scan result.")

# ------------------------------------------------------------------ copilot
elif page == "CyberSentinel Chat":
    ui.note("Runs locally with a built-in reference guide and your own saved scan data. Chat and scan content are not sent to an external AI service.")
    scans = load_user_scans(DB, user)
    context_items = {"General question": ("general", None)}
    for scan in scans:
        context_items[f"Scan {scan['id']} · {scan['type']} · {scan['target']} · {scan['created_at']}"] = ("scan", str(scan["id"]))
    incident_contexts = {}
    for incident in list_investigations(DB, user):
        incident_row, linked = investigation_detail(DB, user, incident[0])
        label = f"Investigation {incident[0]} · {incident[1]} · {incident[2]}"
        incident_contexts[label] = [s for s in scans if s["id"] in {row[0] for row in linked}]
        context_items[label] = ("investigation", str(incident[0]))
    selected_label = st.selectbox("Conversation context", list(context_items),
                                  help="Ask a general question, focus on one scan, or use all scans linked to an investigation.")
    context_mode, selected_scan_id = context_items[selected_label]
    if context_mode == "investigation":
        scans = incident_contexts[selected_label]

    chat_key = f"chat_history_{user}"
    if chat_key not in st.session_state:
        st.session_state[chat_key] = []

    if not st.session_state[chat_key]:
        ui.empty("Start a conversation",
                 "Try 'What is SQL injection?' or 'How should I investigate ransomware?'. Select a scan or investigation above, then ask 'Explain the evidence'.")
    for message in st.session_state[chat_key]:
        with st.chat_message(message["role"]):
            st.text(message["content"])
    if st.session_state[chat_key]:
        st.download_button("Export conversation", json.dumps({"context": selected_label, "messages": st.session_state[chat_key]}, indent=2, ensure_ascii=False),
                           file_name="cybersentinel_conversation.json", mime="application/json", icon=":material/download:")

    prompt = st.chat_input("Ask a cybersecurity question or about the selected context")
    if prompt:
        st.session_state[chat_key].append({"role": "user", "content": prompt})
        reply = answer_question(prompt, scans, selected_scan_id=selected_scan_id, mode=context_mode)
        st.session_state[chat_key].append({"role": "assistant", "content": reply})
        st.rerun()

# ------------------------------------------------------------------ cybercrime cases
elif page == "Cybercrime Cases":
    ui.note("Use this workspace to document reported cybercrime and organize evidence. Records are private to your account. SHA-256 hashes help verify that stored evidence has not changed, but the application does not provide independently immutable chain-of-custody storage or identify perpetrators.")
    with st.expander("Create a cybercrime case", expanded=not bool(list_cybercrime_cases(DB, user))):
        with st.form("cybercrime_case_create", border=False):
            category = st.selectbox("Incident type", CASE_TYPES)
            title = st.text_input("Case title", placeholder="Impersonation email requesting an urgent payment")
            incident_at = st.text_input("When did it happen? (optional)", placeholder="2026-10-01 14:30 UTC")
            description = st.text_area("What was reported?", max_chars=5000)
            contact = st.text_input("Victim or reporting contact (optional)", max_chars=500)
            payment = st.text_area("Payment references or details (optional)", max_chars=3000)
            extortion = st.text_area("Extortion or ransomware details (optional)", max_chars=3000)
            create_clicked = ui.submit("Create case", icon=":material/add:")
        if create_clicked:
            created_id = create_cybercrime_case(DB, user, category, title, description,
                                                incident_at, contact, payment, extortion)
            if created_id:
                record_audit(DB, user, "cybercrime_case_create", f"case={created_id}; category={category}")
                st.success(f"Created case #{created_id}.")
                st.rerun()
            else:
                st.error("Enter a case title and choose a valid incident type.")

    cases = list_cybercrime_cases(DB, user)
    if cases:
        labels = {f"#{row['id']} · {row['category']} · {row['title']} · {row['status']}": row['id'] for row in cases}
        selected_case_label = st.selectbox("Open case", list(labels), key="cybercrime_case_select")
        case_id = int(labels[selected_case_label])
        case = get_cybercrime_case(DB, user, case_id)
        ui.section(f"Case #{case_id}: {case['title']}", f"Created {case['created_at']} · Updated {case['updated_at']}")

        with st.expander("Case details", expanded=True):
            with st.form(f"cybercrime_case_update_{case_id}", border=False):
                c1, c2 = st.columns(2)
                category_index = CASE_TYPES.index(case["category"]) if case["category"] in CASE_TYPES else 0
                status_index = CASE_STATUSES.index(case["status"]) if case["status"] in CASE_STATUSES else 0
                updated_category = c1.selectbox("Incident type", CASE_TYPES, index=category_index)
                updated_status = c2.selectbox("Status", CASE_STATUSES, index=status_index)
                updated_title = st.text_input("Case title", value=case["title"], max_chars=180)
                updated_incident_at = st.text_input("Incident time", value=case["incident_at"], placeholder="2026-10-01 14:30 UTC")
                updated_description = st.text_area("Reported details", value=case["description"], max_chars=5000)
                updated_contact = st.text_input("Victim or reporting contact", value=case["victim_contact"], max_chars=500)
                updated_payment = st.text_area("Payment references or details", value=case["payment_details"], max_chars=3000)
                updated_extortion = st.text_area("Extortion or ransomware details", value=case["extortion_details"], max_chars=3000)
                update_clicked = ui.submit("Save case details", icon=":material/save:")
            if update_clicked:
                ok = update_cybercrime_case(DB, user, case_id, updated_category, updated_title, updated_status,
                                            updated_description, updated_incident_at, updated_contact,
                                            updated_payment, updated_extortion)
                if ok:
                    record_audit(DB, user, "cybercrime_case_update", f"case={case_id}; status={updated_status}")
                    st.success("Case updated.")
                    st.rerun()
                else:
                    st.error("Could not update the case. Check the title and status.")

        ui.section("Timeline")
        with st.form(f"cybercrime_event_add_{case_id}", border=False):
            event_at = st.text_input("Event time (optional)", placeholder="2026-10-01 14:45 UTC")
            event_summary = st.text_area("What happened?", max_chars=2000)
            event_clicked = ui.submit("Add timeline event", icon=":material/event:")
        if event_clicked:
            if add_case_event(DB, user, case_id, event_at, event_summary):
                record_audit(DB, user, "cybercrime_timeline_add", f"case={case_id}")
                st.success("Timeline event added.")
            else:
                st.error("Enter an event summary.")
        events = list_case_events(DB, user, case_id)
        if events:
            ui.dataframe(pd.DataFrame(events).rename(columns={"event_at": "Event time", "summary": "Reported event",
                                                               "created_at": "Recorded at"})[["Event time", "Reported event", "Recorded at"]], hide_index=True)
        else:
            ui.empty("No timeline events yet")

        ui.section("Evidence", "Original files are stored privately under the server's data directory. Hashes are recorded on intake; protect the server and backups. Limits: 25 MB per file and 100 MB total per case.")
        with st.form(f"cybercrime_evidence_add_{case_id}", border=False, clear_on_submit=True):
            evidence_files = st.file_uploader("Evidence files", type=None, accept_multiple_files=True,
                                              help="Up to 25 MB per file and 20 files per case. Keep original source files when possible.")
            evidence_type = st.selectbox("Evidence type", ["Screenshot", "Email", "Chat export", "Payment receipt",
                                                           "Log or capture", "Document", "Other"])
            evidence_clicked = ui.submit("Preserve selected evidence", icon=":material/verified_user:", disabled=not evidence_files)
        if evidence_clicked and evidence_files:
            for evidence_file in evidence_files:
                saved, error = add_evidence(DB, user, case_id, evidence_file.name,
                                            evidence_file.type, evidence_type, evidence_file.getvalue())
                if error:
                    st.error(f"{evidence_file.name}: {error}")
                else:
                    record_audit(DB, user, "cybercrime_evidence_add", f"case={case_id}; sha256={saved['sha256']}")
                    st.success(f"Stored {saved['filename']} · SHA-256 {saved['sha256']}")
        evidence_rows = list_case_evidence(DB, user, case_id)
        if evidence_rows:
            safe_evidence = [{"File": row["filename"], "Type": row["evidence_type"], "Size": row["size_bytes"],
                              "SHA-256": row["sha256"], "Added": row["created_at"]} for row in evidence_rows]
            ui.dataframe(pd.DataFrame(safe_evidence), hide_index=True)
        else:
            ui.empty("No evidence files stored")

        ui.section("Indicators and related cases", "Add identifiers found in the report. Exact matches within your account may link cases; a match is a lead, not proof of attribution.")
        with st.form(f"cybercrime_ioc_add_{case_id}", border=False):
            indicator_type = st.selectbox("Indicator type", INDICATOR_TYPES)
            indicator_value = st.text_input("Indicator value", max_chars=500)
            indicator_note = st.text_input("Context (optional)", max_chars=500)
            indicator_clicked = ui.submit("Add indicator", icon=":material/add_link:")
        if indicator_clicked:
            if add_indicator(DB, user, case_id, indicator_type, indicator_value, indicator_note):
                record_audit(DB, user, "cybercrime_indicator_add", f"case={case_id}; type={indicator_type}")
                st.success("Indicator added.")
            else:
                st.error("Enter an indicator value.")
        indicators = list_case_indicators(DB, user, case_id)
        if indicators:
            ui.dataframe(pd.DataFrame(indicators).rename(columns={"indicator_type": "Type", "value": "Value",
                                                                   "note": "Context", "created_at": "Added"})[["Type", "Value", "Context", "Added"]], hide_index=True)
        related = related_case_indicators(DB, user, case_id)
        if related:
            ui.section("Exact matches in other cases")
            ui.dataframe(pd.DataFrame(related).rename(columns={"indicator_type": "Type", "value": "Matched indicator",
                                                                "related_case_id": "Related case", "related_case_title": "Case title",
                                                                "note": "Context"})[["Type", "Matched indicator", "Related case", "Case title", "Context"]], hide_index=True)
        else:
            ui.note("No exact cross-case indicator matches found.")

        ui.section("Related CyberSentinel scans")
        scan_history = get_history(user)
        scan_choices = {f"Scan {int(row.id)} · {row.scan_type} · {row.target} · risk {row.score:.0f}": int(row.id)
                        for row in scan_history.itertuples(index=False)}
        selected_scan_labels = st.multiselect("Attach scans from your account", list(scan_choices),
                                              default=[label for label, scan_id in scan_choices.items()
                                                       if scan_id in {int(r['id']) for r in list_case_scans(DB, user, case_id)}],
                                              key=f"cybercrime_scans_{case_id}")
        if st.button("Save linked scans", key=f"cybercrime_save_scans_{case_id}", icon=":material/link:"):
            attach_case_scans(DB, user, case_id, [scan_choices[label] for label in selected_scan_labels])
            record_audit(DB, user, "cybercrime_scans_link", f"case={case_id}; count={len(selected_scan_labels)}")
            st.success("Linked scans updated.")
        linked_scans = list_case_scans(DB, user, case_id)
        if linked_scans:
            ui.dataframe(pd.DataFrame(linked_scans).rename(columns={"id": "Scan", "scan_type": "Type",
                                                                      "target": "Target", "score": "Risk",
                                                                      "created_at": "Created"}), hide_index=True)

        ui.section("Export case package")
        redact_export = st.checkbox("Redact narrative, contact details, payment details, and indicator values", value=True,
                                    key=f"cybercrime_redact_{case_id}")
        include_originals = st.checkbox("Include original evidence files in the ZIP", value=False,
                                        disabled=redact_export or not evidence_rows,
                                        key=f"cybercrime_originals_{case_id}")
        if redact_export:
            st.caption("Redacted exports omit original evidence files and mask incident narrative, contacts, payment information, and indicator values; hashes and type labels remain.")
        package = export_case_bundle(DB, user, case_id, redact=redact_export,
                                     include_originals=include_originals)
        st.download_button("Download case package (ZIP)", package,
                           file_name=f"cybercrime_case_{case_id}.zip", mime="application/zip",
                           icon=":material/download:", on_click=record_audit,
                           args=(DB, user, "cybercrime_export", f"case={case_id}; redacted={redact_export}; originals={include_originals}"))
    else:
        ui.empty("No cybercrime cases yet", "Create a case to record a reported phishing, fraud, account takeover, identity theft, or extortion incident.")

# ------------------------------------------------------------------ investigations
elif page == "Investigations":
    ui.note("Investigations group your scans and notes under one response record. Records are private to your account.")
    with st.container(border=True):
        with st.form("create_investigation_form", border=False):
            new_name = st.text_input("New investigation", placeholder="Suspicious login activity")
            create_clicked = ui.submit("Create investigation", icon=":material/add:")
    if create_clicked and new_name.strip():
        created_id = create_investigation(DB, user, new_name)
        if created_id:
            st.success(f"Created investigation {created_id}.")
            st.rerun()
    investigations = list_investigations(DB, user)
    if investigations:
        options = {f"#{row[0]} · {row[1]} · {row[2]}": row for row in investigations}
        selected_investigation = st.selectbox("Choose investigation", list(options))
        item = options[selected_investigation]
        detail, linked_scans = investigation_detail(DB, user, int(item[0]))
        ui.section(f"#{detail[0]} {detail[1]}", f"Created {detail[5]}. Last updated {detail[6]}.")
        with st.container(border=True):
            i1, i2 = st.columns(2)
            incident_status = i1.selectbox("Status", WORKFLOW_STATUSES, index=WORKFLOW_STATUSES.index(detail[2]), key=f"inv_status_{detail[0]}")
            incident_owner = i2.text_input("Owner", value=detail[3], key=f"inv_owner_{detail[0]}")
            incident_notes = st.text_area("Notes", value=detail[4], key=f"inv_notes_{detail[0]}")
            choices = {f"Scan {r[0]} · {r[1]} · {r[2]} · risk {r[3]:.0f}": int(r[0]) for r in get_history(user).itertuples(index=False)}
            currently_linked = {int(r[0]) for r in linked_scans}
            labels = [label for label, scan_id in choices.items() if scan_id in currently_linked]
            selected_scan_labels = st.multiselect("Linked scans", list(choices), default=labels, key=f"inv_scans_{detail[0]}")
            if st.button("Save investigation", type="primary", icon=":material/save:"):
                update_investigation(DB, user, int(detail[0]), incident_status, incident_owner, incident_notes)
                attach_investigation_scans(DB, user, int(detail[0]), [choices[label] for label in selected_scan_labels])
                st.success("Investigation saved.")
                st.rerun()
        ui.section("Linked scan evidence")
        if linked_scans:
            frame = pd.DataFrame(linked_scans, columns=["Scan", "Type", "Target", "Risk", "Created"])
            ui.dataframe(frame, hide_index=True,
                         column_config={"Risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d")})
            linked_ids = {r[0] for r in linked_scans}
            evidence = [scan for scan in load_user_scans(DB, user) if scan["id"] in linked_ids]
            export_record = {"investigation": {"id": detail[0], "name": detail[1], "status": detail[2], "owner": detail[3], "notes": detail[4], "updated_at": detail[6]}, "scans": evidence}
            st.download_button("Export investigation evidence (JSON)", json.dumps(export_record, indent=2, default=str, ensure_ascii=False),
                               file_name=f"investigation_{detail[0]}.json", mime="application/json", icon=":material/download:")
        else:
            ui.empty("No linked scans", "Add scans in the Linked scans field above to keep related evidence together.")
    else:
        ui.empty("No investigations yet", "Create one above to group related scans and response notes.")

# ------------------------------------------------------------------ model evaluation
elif page == "Model Evaluation":
    metadata_path = Path(__file__).parent / "ml" / "model_metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text())
    except Exception:
        metadata = {}
    metrics = metadata.get("metrics", {})
    real_dataset = metadata.get("dataset") == "PhiUSIIL Phishing URL (Website) Dataset"
    if metrics and real_dataset:
        ui.stat_strip([
            ("Accuracy", f"{metrics.get('accuracy', 0):.3f}"),
            ("Phishing precision", f"{metrics.get('precision_phishing', 0):.3f}"),
            ("Phishing recall", f"{metrics.get('recall_phishing', 0):.3f}"),
            ("Phishing F1", f"{metrics.get('f1_phishing', 0):.3f}"),
            ("False positive rate", f"{metrics.get('false_positive_rate', 0):.3f}"),
            ("ROC-AUC", f"{metrics.get('roc_auc', 0):.3f}"),
        ])
        matrix = metrics.get("confusion_matrix", {})
        ui.section("Confusion matrix", "Rows are actual classes; columns are predicted classes.")
        ui.dataframe(pd.DataFrame([[matrix.get("true_negative", 0), matrix.get("false_positive", 0)],
                                   [matrix.get("false_negative", 0), matrix.get("true_positive", 0)]],
                                  index=["Actual legitimate", "Actual phishing"],
                                  columns=["Predicted legitimate", "Predicted phishing"]))
        ui.section("Dataset and limitations")
        ui.key_values([("Dataset", metadata.get("dataset", "Unknown")),
                       ("License", metadata.get("license", "See dataset source")),
                       ("Test examples", metrics.get("test_samples", "n/a")),
                       ("Split", metadata.get("split", "n/a"))])
        ui.indicator_list(metadata.get("limitations", []), "No limitations were recorded.", warn=True)
    else:
        synthetic_metrics = metrics or metadata.get("synthetic_demo_metrics", {})
        ui.stat_strip([
            ("Synthetic accuracy", str(synthetic_metrics.get("accuracy", metadata.get("held_out_accuracy", "unavailable")))),
            ("Synthetic ROC-AUC", str(synthetic_metrics.get("roc_auc", metadata.get("held_out_auc", "unavailable")))),
            ("Synthetic samples", str(metadata.get("dataset_samples", metadata.get("n_samples", "unavailable")))),
        ])
        st.warning("These are synthetic demo metrics, not real-world phishing accuracy. Run python ml/train_url_model.py on the bundled UCI PhiUSIIL dataset to replace them with real-data metrics.")
        ui.key_values([("Dataset", metadata.get("dataset", metadata.get("trained_on", synthetic_metrics.get("dataset", "Metadata unavailable"))))])
    synthetic = metadata.get("synthetic_demo_metrics", {})
    if synthetic.get("accuracy") is not None:
        with st.expander("Synthetic demo baseline"):
            st.caption(f"Accuracy {synthetic.get('accuracy')} · ROC-AUC {synthetic.get('roc_auc')} · {synthetic.get('dataset', 'synthetic examples')}. Not a measure of real-world performance.")
    if metadata.get("feature_importances"):
        ui.section("Most influential model features")
        st.bar_chart(pd.Series(metadata["feature_importances"]).sort_values(ascending=False).head(10), color="#2f6fed")
    ui.section("Analyst review feedback", "Analyst labels are subjective review signals, not independently verified ground truth. Review them before using them to tune a detector.")
    review_rows = feedback_frame(DB, user, admin=False)
    if review_rows:
        review_counts = pd.Series([row[2] for row in review_rows]).value_counts()
        ui.dataframe(pd.DataFrame({"Assessment": review_counts.index, "Count": review_counts.values}), hide_index=True)
    else:
        ui.empty("No analyst feedback yet", "Assessments you save from Scan History are summarized here.")

# ------------------------------------------------------------------ scan history
elif page == "Scan History":
    history = get_history(user)
    if history.empty:
        ui.empty("No scans yet", "Run an analysis from the Analyze section. Saved scans can be reviewed, compared, and exported here.")
    else:
        with st.container(border=True):
            filtered = filter_history_controls(history, "scan_history")
        if filtered.empty:
            ui.empty("No scans match these filters", "Widen the date range or reset the risk tier.")
        else:
            ui.history_table(filtered)
            labels = {int(r.id): f"#{r.id} · {r.scan_type} · {r.target}" for r in filtered.itertuples()}
            selected = st.selectbox("Select a scan", list(labels), format_func=labels.get)
            row = filtered[filtered.id == selected].iloc[0]
            current_status, current_owner, current_note, updated_at = workflow_for(DB, user, int(selected))
            ui.section(f"Scan #{selected}")
            ui.stat_strip([
                ("Type", row.scan_type),
                ("Target", row.target),
                ("Risk score", f"{row.score:.0f}/100", None, ui.tier_of(row.score)),
                ("Investigation status", current_status),
            ])
            tab_work, tab_review, tab_compare = st.tabs(["Investigation", "Assessment and report", "Compare"])
            with tab_work:
                s1, s2 = st.columns(2)
                new_status = s1.selectbox("Status", WORKFLOW_STATUSES, index=WORKFLOW_STATUSES.index(current_status), key=f"workflow_status_{selected}")
                new_owner = s2.text_input("Owner", value=current_owner, key=f"workflow_owner_{selected}")
                new_note = st.text_area("Investigation notes", value=current_note, key=f"workflow_note_{selected}")
                if st.button("Save investigation update", type="primary", icon=":material/save:"):
                    if set_scan_workflow(DB, user, int(selected), new_status, new_owner, new_note):
                        st.success("Investigation update saved to the audit history.")
                        st.rerun()
                ui.note(f"Last updated: {updated_at}")
            with tab_review:
                feedback_label = st.selectbox("Analyst assessment", ["Useful", "False positive", "Missed threat"], key=f"feedback_label_{selected}")
                feedback_note = st.text_input("Feedback note (optional)", key=f"feedback_note_{selected}")
                if st.button("Save assessment"):
                    add_feedback(DB, user, int(selected), feedback_label, feedback_note)
                    st.success("Assessment saved for future review.")
                st.divider()
                if st.button("Generate PDF report", icon=":material/picture_as_pdf:"):
                    con = sqlite3.connect(DB)
                    raw = con.execute("SELECT result FROM scans WHERE id=? AND username=?",
                                      (int(selected), user)).fetchone()
                    con.close()
                    path = REPORT_DIR / f"report_{selected}.pdf"
                    workflow = {"status": current_status, "owner": current_owner, "note": current_note}
                    create_pdf_report(user, row.scan_type, row.target, float(row.score), raw[0], str(path), workflow=workflow)
                    st.download_button("Download report", path.read_bytes(),
                                       file_name=path.name, mime="application/pdf", icon=":material/download:")
            with tab_compare:
                if len(filtered) > 1:
                    other = st.selectbox("Compare with scan", [int(x) for x in filtered["id"] if int(x) != int(selected)])
                    rows = compare_scans(DB, user, int(selected), other)
                    if len(rows) == 2:
                        left, right = st.columns(2, gap="large")
                        for col, item in zip((left, right), rows):
                            with col:
                                st.markdown(f"**Scan {item[0]} · {item[1]} · {item[2]}**")
                                ui.stat_strip([("Risk", f"{item[3]}/100", None, ui.tier_of(item[3]))])
                                with st.expander("Result details"):
                                    st.json(item[4])
                else:
                    ui.empty("Nothing to compare", "At least two scans are needed. Widen the filters above if you have more.")
    with st.expander("Data retention"):
        st.caption("Remove your own scans and their workflow and feedback records after a chosen age. This cannot be undone.")
        retention_days = st.number_input("Delete scans older than this many days", min_value=30, max_value=3650, value=365, step=30)
        cutoff = pd.Timestamp.now() - pd.Timedelta(days=int(retention_days))
        eligible = int((pd.to_datetime(history["created_at"], errors="coerce") < cutoff).sum()) if len(history) else 0
        st.write(f"{eligible} scans currently meet this retention rule.")
        confirm_delete = st.checkbox("I understand these scans and their attached records will be permanently deleted", key="retention_confirm")
        if st.button("Delete expired scans", disabled=not confirm_delete or eligible == 0, icon=":material/delete:"):
            removed = delete_old_scans(DB, user, int(retention_days))
            st.success(f"Deleted {removed} expired scans.")
            st.rerun()

# ------------------------------------------------------------------ feedback & audit
elif page == "Feedback & Audit":
    is_admin = role == "admin"
    tab_feedback, tab_audit = st.tabs(["Analyst feedback", "Activity history"])
    with tab_feedback:
        feedback = feedback_frame(DB, user, admin=is_admin)
        if feedback:
            ui.dataframe(pd.DataFrame(feedback, columns=["User", "Scan", "Label", "Note", "Created"]), hide_index=True)
        else:
            ui.empty("No feedback recorded", "Assessments saved from Scan History appear here.")
    with tab_audit:
        audit = audit_frame(DB, user, admin=is_admin)
        if audit:
            ui.dataframe(pd.DataFrame(audit, columns=["User", "Action", "Detail", "Created"]), hide_index=True)
        else:
            ui.empty("No activity recorded")

# ------------------------------------------------------------------ admin
elif page == "Admin":
    if role != "admin":
        st.error("Administrator role required.")
        st.stop()
    con = sqlite3.connect(DB)
    users = pd.read_sql_query("SELECT username,role,created_at FROM users ORDER BY username", con)
    con.close()
    ui.dataframe(users.rename(columns={"username": "Username", "role": "Role", "created_at": "Created"}), hide_index=True)
    if len(users):
        ui.section("Change a role")
        with st.container(border=True):
            a1, a2 = st.columns(2)
            target_user = a1.selectbox("Account", users["username"].tolist())
            target_role = a2.selectbox("Role", ["analyst", "admin"])
            if st.button("Update role", type="primary"):
                if set_role(DB, user, target_user, target_role):
                    st.success("Role updated.")
                    st.rerun()
                else:
                    st.warning("Role unchanged, account missing, or changing your own role is not allowed.")
