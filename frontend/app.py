from __future__ import annotations

import pandas as pd
import streamlit as st
import json
from datetime import datetime
from urllib.parse import urlsplit

from frontend.client import (
    API_BASE,
    APIError,
    analyze_batch,
    analyze_file,
    delete_analysis,
    health,
    history,
    model_info,
)
from frontend.report import build_html_report
from frontend.theme import apply_theme

YARA_EXPLANATIONS = {
    "Suspicious_Registry_Persistence": "The file contains several Windows registry terms. Many installers use these too, so this alone does not mean the file is harmful.",
    "Suspicious_Packer_UPX": "The file has a marker used by UPX, a program that compresses files. Safe and harmful files can both use it.",
    "Suspicious_Ransomware_Note": "The file contains several phrases often seen in ransom notes. Check the file and other findings before deciding.",
    "Suspicious_Process_Injection_APIs": "The file mentions tools that can affect another running program. Some safe system and security tools use them too.",
    "Suspicious_Anti_Debug": "The file mentions tools that can detect when it is being inspected. Safe and harmful programs can both do this.",
    "Suspicious_Network_Indicators": "The file contains words linked to network or download activity. Check the addresses and other findings.",
}
RULE_TITLES = {
    "Suspicious_Registry_Persistence": "Windows registry activity",
    "Suspicious_Packer_UPX": "File compressed with UPX",
    "Suspicious_Ransomware_Note": "Ransom note phrases",
    "Suspicious_Process_Injection_APIs": "Tools that can affect other programs",
    "Suspicious_Anti_Debug": "Tools that can detect inspection",
    "Suspicious_Network_Indicators": "Network or download terms",
}


def display_signal(label: str) -> str:
    return {
        "MALICIOUS": "Alert raised",
        "BENIGN": "No alert found",
        "UNKNOWN": "No result",
    }.get(label, label)


def explain_findings(score: float | None, rule_count: int) -> str:
    if score is None:
        summary = "The model did not return a score that can be used."
    else:
        summary = f"The model score is {float(score):.1%}. A higher score means it found more signs linked to harmful files. This is a clue, not proof."
    if rule_count:
        summary += f" {rule_count} file rule(s) matched. Safe programs can match these rules too."
    else:
        summary += " No file rules matched. This does not prove the file is safe."
    return summary


def format_review_level(level: str) -> str:
    return {"CRITICAL": "Urgent", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Not available"}.get(str(level).upper(), str(level).title())


def format_time(value: str) -> str:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().strftime("%b %d, %Y · %I:%M %p")
    except (AttributeError, TypeError, ValueError):
        return str(value)


def status_summary(prediction: dict, threat: dict, warnings: list[str] | None = None) -> tuple[str, str, str, str]:
    """Return a plain-language triage color and explanation without claiming certainty."""
    label = str(prediction.get("binary_label", "UNKNOWN")).upper()
    has_rules = bool(threat.get("yara_matches"))
    score = prediction.get("malware_probability")
    unverified = any("synthetic" in str(note).lower() for note in warnings or [])
    if unverified:
        return ("review", "Check this result yourself", "This report used a demo model that has not been checked for real files. Do not rely on its score.", "?")
    if score is not None and float(score) >= 0.75:
        return ("review", "High model score — review this file", "The model saw signs it links with harmful files. This is a reason to investigate, not proof that the file is infected.", "!")
    if score is not None and float(score) <= 0.25 and label == "BENIGN" and not has_rules:
        return ("safe", "No warning found", "The model and file checks found no warning. This does not prove the file is safe.", "✓")
    if has_rules:
        return ("review", "Check this file more closely", "A file pattern matched. Safe programs can contain the same pattern, so check the details.", "?")
    if score is not None:
        return ("review", "The result is unclear", "The model score is in the middle. Check where the file came from and read the other findings.", "?")
    return ("review", "Could not check this file", "A reliable model result is not available. Review the file details and any rule matches.", "?")


def render_status_banner(prediction: dict, threat: dict, warnings: list[str] | None = None) -> None:
    color, title, description, icon = status_summary(prediction, threat, warnings)
    st.markdown(
        f'<div class="status-banner status-{color}" role="status"><span class="status-icon">{icon}</span>'
        f'<div><strong>{title}</strong><p>{description}</p></div></div>',
        unsafe_allow_html=True,
    )


def render_view_intro(title: str, description: str) -> None:
    st.markdown(
        f'<div class="view-intro"><h2>{title}</h2><p>{description}</p></div>',
        unsafe_allow_html=True,
    )


def render_score_meter(score: float | None) -> None:
    st.markdown('<div class="score-meter-heading"><strong>Model score</strong><span>A model signal, not a chance that the file is harmful</span></div>', unsafe_allow_html=True)
    if score is None:
        st.info("The model did not return a score for this file.")
        return
    value = min(max(float(score), 0.0), 1.0)
    st.markdown(
        f'<div class="risk-meter" role="img" aria-label="Model score: {value:.0%}">'
        f'<div class="risk-meter-track"><span class="meter-marker" style="left:{value * 100:.2f}%"></span></div>'
        f'<div class="risk-meter-labels"><span>Lower</span><strong>{value:.0%} model score</strong><span>Higher</span></div>'
        f'<div class="risk-meter-legend"><span><i class="legend-green"></i>Lower</span><span><i class="legend-yellow"></i>Uncertain</span><span><i class="legend-red"></i>Higher</span></div></div>',
        unsafe_allow_html=True,
    )
    st.caption("A higher score means the model saw more signs it has learned to link with harmful files. It is not the chance that this file is harmful.")


DEFAULT_EXTENSIONS = [".exe", ".dll", ".sys", ".bin"]


def upload_config() -> tuple[list[str], int | None]:
    """Read accepted file types and size from the running service."""
    try:
        config = model_info()
    except APIError:
        return DEFAULT_EXTENSIONS, None
    extensions = [str(item).lower() for item in config.get("allowed_extensions", DEFAULT_EXTENSIONS)]
    limit = config.get("max_upload_mb")
    return extensions or DEFAULT_EXTENSIONS, int(limit) if isinstance(limit, (int, float)) else None


def _open_view(name: str) -> None:
    st.session_state["active_view"] = name


def _analyze_dashboard_upload() -> None:
    upload = st.session_state.get("dashboard_upload")
    if upload is None:
        return
    try:
        st.session_state["latest_analysis"] = analyze_file(upload.name, upload.getvalue())
        st.session_state["dashboard_error"] = ""
        st.session_state["active_view"] = "Analyze a File"
    except APIError as exc:
        st.session_state["dashboard_error"] = str(exc)


st.set_page_config(
    page_title="IntelliStatic | File Intelligence",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
    menu_items={},
)
apply_theme()

for old_name, new_name in {
    "Overview": "Dashboard",
    "Check one file": "Analyze a File",
    "Check several files": "Batch Analysis",
    "Past reports": "Analysis History",
}.items():
    if st.session_state.get("active_view") == old_name:
        st.session_state["active_view"] = new_name

api_host = urlsplit(API_BASE).hostname
workspace_label = "LOCAL DEVICE" if api_host in {"localhost", "127.0.0.1", "::1"} else "CONNECTED SERVICE"

st.markdown(
    f"""
    <div class="topbar">
      <div class="brand-lockup">
        <div class="brand-mark" role="img" aria-label="IntelliStatic logo">
          <svg class="brand-symbol" viewBox="0 0 48 48" aria-hidden="true" focusable="false">
            <path d="M24 3.5 40 10v12.2c0 10.2-6.6 18-16 22.3C14.6 40.2 8 32.4 8 22.2V10L24 3.5Z" fill="none" stroke="currentColor" stroke-width="3" stroke-linejoin="round"/>
            <path d="M17 17h14M17 23h14M17 29h8" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
            <circle cx="31" cy="32" r="5" fill="#fff" stroke="currentColor" stroke-width="2.5"/>
            <path d="m34.5 35.5 4 4" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
          </svg>
        </div>
        <div class="brand-copy">
          <div class="brand-name-row"><div class="brand-name">IntelliStatic</div>
            <div class="topbar-note"><span class="status-dot"></span> {workspace_label}</div>
          </div>
          <div class="brand-caption">WINDOWS FILE ANALYSIS</div>
        </div>
      </div>
    </div>
    <section class="page-heading"><h1>Windows File Analysis</h1>
      <p>Inspect files for suspicious signs without running them.</p></section>
    """,
    unsafe_allow_html=True,
)

view = st.radio(
    "Workspace",
    ["Dashboard", "Analyze a File", "Batch Analysis", "Analysis History"],
    horizontal=True,
    label_visibility="collapsed",
    key="active_view",
)
st.markdown('<div class="view-divider"></div>', unsafe_allow_html=True)


def render_dashboard() -> None:
    extensions, max_upload_mb = upload_config()
    service_status, model_status = "Unavailable", "Unavailable"
    service_error = model_error = None
    recent = {"total": 0, "items": []}
    history_available = False
    try:
        service = health()
        service_status = "Operational" if service.get("status") == "ok" else "Needs attention"
    except APIError as exc:
        service_error = str(exc)
    try:
        models = model_info()
        model_status = "Ready" if models.get("model_usable") else "Unavailable"
    except APIError as exc:
        models = {}
        model_error = str(exc)
    try:
        recent = history(1, 1)
        history_available = True
    except APIError:
        pass

    st.markdown('<div class="section-heading dashboard-section-title">Analyze a file</div>', unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown("#### Select a Windows program file")
        st.caption("Choose a file to review its structure and warning signs. The app does not run the file.")
        upload = st.file_uploader(
            "Choose a file", type=[item.lstrip(".") for item in extensions],
            label_visibility="collapsed", key="dashboard_upload",
        )
        size_note = f"Maximum file size: {max_upload_mb} MB." if max_upload_mb else "The service checks the configured file size limit."
        st.caption(f"Supported types: {', '.join(item.upper().lstrip('.') for item in extensions)} · {size_note}")
        if upload:
            if max_upload_mb and upload.size > max_upload_mb * 1024 * 1024:
                st.error(f"This file is larger than the {max_upload_mb} MB limit. Choose a smaller file.")
            else:
                st.button("Analyze file", type="primary", use_container_width=True,
                          key="dashboard_analyze", on_click=_analyze_dashboard_upload)
        if st.session_state.get("dashboard_error"):
            st.error(st.session_state.pop("dashboard_error"))

    st.markdown('<div class="section-heading dashboard-section-title">System overview</div>', unsafe_allow_html=True)
    service_col, model_col, files_col, reports_col = st.columns(4, gap="medium")
    service_col.metric("Analysis service", service_status)
    model_col.metric("Detection model", model_status)
    files_col.metric("Files analyzed", f"{recent['total']:,}" if history_available else "—")
    reports_col.metric("Recent reports", "Available" if history_available and recent.get("total", 0) else ("None yet" if history_available else "Unavailable"))
    if service_error or model_error:
        st.warning("Some live system details could not be loaded. Check that the analysis service is running.")
    recent_items = recent.get("items", [])
    if recent_items:
        latest = recent_items[0]
        latest_name = latest.get("file_info", {}).get("filename", "Most recent report")
        st.caption(f"Latest report: {latest_name} · {format_time(str(latest.get('created_at', '')))}")
    nav_col, _ = st.columns([1, 3])
    nav_col.button("View analysis history", on_click=_open_view, args=("Analysis History",), key="dashboard_history")
    with st.expander("Supported files and developer tools"):
        st.write("The app checks supported Windows program files without executing them.")
        st.markdown("**Supported file types:** " + ", ".join(item.upper().lstrip(".") for item in extensions))
        st.link_button("Open API documentation", f"{API_BASE}/docs")
    st.caption("A report can help with review, but no automated check can guarantee a file is safe.")


def render_analyze() -> None:
    extensions, max_upload_mb = upload_config()
    render_view_intro("Analyze a File", "Review one Windows program file and its warning signs.")
    with st.container(border=True):
        st.markdown("#### Choose a file")
        st.caption("The app reads the file but does not run it.")
        upload = st.file_uploader("Choose a Windows program file", type=[item.lstrip(".") for item in extensions], label_visibility="collapsed", key="single_upload")
        size_note = f"Maximum file size: {max_upload_mb} MB." if max_upload_mb else "The service checks the configured file size limit."
        st.caption(f"Supported types: {', '.join(item.upper().lstrip('.') for item in extensions)}. {size_note}")
        upload_too_large = bool(upload and max_upload_mb and upload.size > max_upload_mb * 1024 * 1024)
        if upload_too_large:
            st.error(f"This file is larger than the {max_upload_mb} MB limit. Choose a smaller file.")
        if upload and st.button("Analyze file", type="primary", use_container_width=True, key="analyze_single", disabled=upload_too_large):
            with st.spinner("Checking the file…"):
                try:
                    st.session_state["latest_analysis"] = analyze_file(upload.name, upload.getvalue())
                except APIError as exc:
                    st.error(str(exc))

    result = st.session_state.get("latest_analysis")
    if not result:
        st.info("Your report will appear here after the file is checked.")
        return
    info, prediction, threat = result["file_info"], result["prediction"], result["threat_assessment"]
    render_view_intro("File report", "See what the checks found. A warning is a reason to look closer, not proof that a file is harmful.")
    st.caption(f"{info['filename']}  ·  Checked {result['created_at']}  ·  Report ID {result['analysis_id']}")
    st.markdown('<div class="section-heading report-step">1 · Summary</div>', unsafe_allow_html=True)
    render_status_banner(prediction, threat, result.get("warnings", []))
    render_score_meter(prediction.get("malware_probability"))
    try:
        model_details = model_info()
    except APIError:
        model_details = {}
    if result.get("warnings"):
        with st.expander("About this result"):
            st.info("The model may not be reliable for this file. Treat its score as unknown and use the file details and rule matches as clues.")
    verdict, probability, level = st.columns(3, gap="medium")
    verdict.metric("Model result", display_signal(prediction["binary_label"]))
    probability.metric("Model score (not a chance)", "Not available" if prediction["malware_probability"] is None else f"{prediction['malware_probability']:.1%}")
    level.metric("Review level", format_review_level(threat["threat_level"]))
    st.caption("This score is not the chance that the file is harmful. Use it with the other findings.")

    st.markdown('<div class="section-heading report-step">2 · File details</div>', unsafe_allow_html=True)
    file_col, classification_col = st.columns([1, 1.35], gap="medium")
    with file_col:
        with st.container(border=True):
            st.markdown("#### File details")
            st.write(f"**Name:** {info['filename']}")
            st.write(f"**Type:** {info['file_type']} · **Size:** {info['size_bytes']:,} bytes")
            st.markdown(f'<div class="hash-value"><strong>SHA-256</strong><br>{info["sha256"]}</div>', unsafe_allow_html=True)
    with classification_col:
        with st.container(border=True):
            st.markdown('<div class="model-details-content"><h4>Model details</h4><p>This version checks whether a file needs review. It does not identify a malware family.</p><p>Use this score as one screening clue alongside the file structure and rule-based findings.</p></div>', unsafe_allow_html=True)
    st.markdown('<div class="section-heading report-step">3 · What we found</div>', unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown("#### File check results")
        st.write(explain_findings(prediction.get("malware_probability"), len(threat.get("yara_matches", []))))
        review_level = format_review_level(threat["threat_level"])
        st.caption(f"Review level: {review_level} · File was not run")
        st.markdown("**Rule matches**")
        if threat["yara_matches"]:
            for rule in threat["yara_matches"]:
                st.markdown(f"**{RULE_TITLES.get(rule, rule.replace('_', ' '))}** — {YARA_EXPLANATIONS.get(rule, 'A file pattern matched. This is a reason to look closer, not proof that the file is harmful.')}")
        else:
            st.write("No rule matches were found.")
        st.caption("Rule matches are clues. Safe files can match a rule, and no match does not prove a file is safe.")
    st.markdown('<div class="section-heading report-step">4 · Technical details</div>', unsafe_allow_html=True)
    with st.expander("About the model and its test results"):
        st.write(f"**Model name:** {model_details.get('model_name') or 'Not available'}")
        st.write("**What it checks:** It looks for signs that a file may need review. It does not name a malware family.")
        metrics = model_details.get("evaluation", {})
        if metrics:
            st.dataframe(pd.DataFrame([
                {"Test result": label, "Score": f"{metrics[key]:.1%}"}
                for key, label in (
                    ("balanced_accuracy", "Overall score on the test set"),
                    ("malware_precision", "How often alerts were correct"),
                    ("malware_recall", "Test malware files found"),
                    ("malware_roc_auc", "How well the test sorted files"),
                ) if key in metrics
            ]), hide_index=True, use_container_width=True)
        else:
            st.info("Test results are not available.")
        st.caption("These results come from test files used during development. They do not guarantee how the model will judge a new file.")
    with st.expander("File details checked by the app"):
        if result["top_features"]:
            st.markdown("##### Details that most affected the model score")
            st.dataframe(pd.DataFrame(result["top_features"]), hide_index=True, use_container_width=True)
        else:
            st.info("The app cannot show which details affected the score for this file.")
        st.markdown("##### All checked file details")
        st.dataframe(pd.DataFrame([result["static_features"]]).T.rename(columns={0: "Value"}), use_container_width=True)
    with st.expander("Full report data (technical)"):
        st.caption("This section contains the raw data used by the app. Most users can ignore it.")
        st.json(result)
    st.markdown('<div class="section-heading report-step">5 · Export report</div>', unsafe_allow_html=True)
    json_export, html_export = st.columns(2, gap="small")
    json_export.download_button(
        "Download data report (JSON)",
        data=json.dumps(result, indent=2, default=str),
        file_name=f"intellistatic_{info['sha256'][:12]}.json",
        mime="application/json",
        use_container_width=True,
        key="download_single_report_json",
    )
    html_export.download_button(
        "Download readable report (HTML)",
        data=build_html_report(result, model_details),
        file_name=f"intellistatic_{info['sha256'][:12]}.html",
        mime="text/html",
        use_container_width=True,
        key="download_single_report_html",
    )


def render_history() -> None:
    render_view_intro("Analysis History", "Find an earlier file check and open its report.")
    with st.form("history_filters"):
        search_col, verdict_col, threat_col, size_col = st.columns([2, 1, 1, 1], gap="small")
        search = search_col.text_input("File name")
        verdict = verdict_col.selectbox("Model result", ["All", "MALICIOUS", "BENIGN", "UNKNOWN"], format_func=lambda value: {"MALICIOUS": "Alert raised", "BENIGN": "No alert found", "UNKNOWN": "No result"}.get(value, value))
        threat = threat_col.selectbox("Review level", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], format_func=lambda value: {"CRITICAL": "Urgent", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Not available"}.get(value, value))
        page_size = size_col.selectbox("Reports per page", [10, 20, 50, 100], index=1)
        page = st.number_input("Page number", min_value=1, value=1, step=1)
        st.form_submit_button("Show reports", type="primary", use_container_width=True)
    try:
        result = history(int(page), int(page_size), search, verdict, threat)
        st.caption(f"{result['total']:,} report(s)")
        rows = result["items"]
        if not rows:
            st.info("No reports match those filters.")
            return
        has_unverified_history = any(
            any("synthetic" in warning.lower() for warning in item.get("warnings", []))
            for item in rows
        )
        if has_unverified_history:
            st.warning("Some past reports used a demo model that was not checked on real files. Do not rely on its old labels or scores.")
        table = []
        for item in rows:
            info, prediction, assessment = item["file_info"], item["prediction"], item["threat_assessment"]
            unverified = any("synthetic" in warning.lower() for warning in item.get("warnings", []))
            table.append({
                "Checked on": format_time(item["created_at"]), "File name": info["filename"],
                "Result": "Old demo result — not reliable" if unverified else display_signal(prediction["binary_label"]),
                "Model score (not infection chance)": "Not reliable" if unverified else ("Not available" if prediction["malware_probability"] is None else f"{prediction['malware_probability']:.1%}"),
                "Review level": "Not reliable" if unverified else format_review_level(assessment["threat_level"]),
            })
        st.dataframe(pd.DataFrame(table), hide_index=True, use_container_width=True)
        selected = st.selectbox("Choose a report to open", [item["analysis_id"] for item in rows], format_func=lambda value: next((item["file_info"]["filename"] for item in rows if item["analysis_id"] == value), value))
        chosen = next(item for item in rows if item["analysis_id"] == selected)
        with st.expander("View report data (technical)"):
            st.json(chosen)
        confirm = st.checkbox("I understand this will permanently delete the report")
        if st.button("Delete this report", disabled=not confirm):
            try:
                delete_analysis(selected)
                st.success("Report deleted.")
                st.rerun()
            except APIError as exc:
                st.error(str(exc))
    except APIError as exc:
        st.error(f"Unable to load report history. {exc}")


def render_batch() -> None:
    extensions, max_upload_mb = upload_config()
    render_view_intro("Batch Analysis", "Compare up to 20 Windows program files. The app checks each file without running it.")
    st.caption("Use Analyze a File for a detailed report on one file. Batch Analysis gives you a results table for several files.")
    with st.container(border=True):
        st.markdown("#### Choose files")
        uploads = st.file_uploader("Choose up to 20 files", type=[item.lstrip(".") for item in extensions], accept_multiple_files=True, label_visibility="collapsed", key="batch_upload")
        size_note = f"Maximum {max_upload_mb} MB per file." if max_upload_mb else "The service checks the configured size limit for each file."
        st.caption(f"Supported types: {', '.join(item.upper().lstrip('.') for item in extensions)}. Up to 20 files · {size_note}")
        oversized_files = [file.name for file in (uploads or []) if max_upload_mb and file.size > max_upload_mb * 1024 * 1024]
        if len(uploads or []) > 20:
            st.error("Choose 20 files or fewer.")
        elif oversized_files:
            st.error(f"These files exceed the {max_upload_mb} MB limit: {', '.join(oversized_files)}. Remove them or choose smaller files.")
        elif uploads and st.button("Check these files", type="primary", use_container_width=True, key="analyze_batch"):
            with st.spinner(f"Checking {len(uploads)} file(s)…"):
                try:
                    st.session_state["batch_results"] = analyze_batch([(file.name, file.getvalue()) for file in uploads])
                except APIError as exc:
                    st.error(str(exc))

    results = st.session_state.get("batch_results", [])
    if not results:
        st.info("Results will appear here after the files are checked.")
        return
    if any(any("synthetic" in warning.lower() for warning in item.get("warnings", [])) for item in results):
        st.warning("Some reports used a demo model that was not checked on real files. Its scores are turned off. Review the file details and rule matches instead.")
    st.markdown('<div class="section-heading">Results summary</div>', unsafe_allow_html=True)
    rule_hits = sum(bool(item["threat_assessment"].get("yara_matches")) for item in results)
    has_demo_results = any(any("synthetic" in str(note).lower() for note in item.get("warnings", [])) for item in results)
    high_score_count = sum((item["prediction"].get("malware_probability") or 0) >= .75 for item in results)
    review_score_count = sum(.25 < (item["prediction"].get("malware_probability") or 0) < .75 for item in results)
    unavailable_count = sum(item["prediction"].get("malware_probability") is None for item in results)
    one, two, three = st.columns(3, gap="medium")
    one.metric("Files scanned", len(results))
    two.metric("High model scores", high_score_count)
    three.metric("Files to review", review_score_count + rule_hits + unavailable_count)
    if has_demo_results:
        st.markdown('<div class="status-banner status-review"><span class="status-icon">?</span><div><strong>Check these results yourself</strong><p>Some reports use a demo model that was not checked on real files. Do not rely on its scores.</p></div></div>', unsafe_allow_html=True)
    elif high_score_count:
        st.markdown('<div class="status-banner status-review"><span class="status-icon">!</span><div><strong>Some files need a closer look</strong><p>Open those reports and read the findings. A high model score is a warning, not proof that a file is harmful.</p></div></div>', unsafe_allow_html=True)
    elif rule_hits or review_score_count or unavailable_count:
        st.markdown('<div class="status-banner status-review"><span class="status-icon">?</span><div><strong>Check the listed matches</strong><p>Some files match patterns that can appear in safe programs too. Open the reports to see details.</p></div></div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-banner status-safe"><span class="status-icon">✓</span><div><strong>No warnings found</strong><p>The checks found no warning. This does not prove the files are safe.</p></div></div>', unsafe_allow_html=True)
    rows = []
    for item in results:
        info, prediction, threat = item["file_info"], item["prediction"], item["threat_assessment"]
        rows.append({
            "File name": info["filename"], "Result": display_signal(prediction["binary_label"]),
            "Model score (not infection chance)": "Not available" if prediction["malware_probability"] is None else f"{prediction['malware_probability']:.1%}",
            "Review level": format_review_level(threat["threat_level"]),
        })
    frame = pd.DataFrame(rows)
    st.dataframe(frame, hide_index=True, use_container_width=True)
    st.download_button("Download results table (CSV)", frame.to_csv(index=False).encode("utf-8"), file_name="intellistatic_batch_report.csv", mime="text/csv")


if view == "Dashboard":
    render_dashboard()
elif view == "Analyze a File":
    render_analyze()
elif view == "Batch Analysis":
    render_batch()
else:
    render_history()
