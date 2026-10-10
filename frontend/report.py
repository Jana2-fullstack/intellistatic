"""Create a self-contained, printable HTML analysis report."""
from __future__ import annotations

from html import escape
from typing import Any


METRIC_LABELS = {
    "balanced_accuracy": "Overall result on test files",
    "malware_precision": "Alerts that were correct",
    "malware_recall": "Test malware files found",
    "malware_roc_auc": "How well the test sorted files",
}

RULE_NOTES = {
    "Suspicious_Registry_Persistence": "The file contains several Windows registry terms. Safe installers can use them too.",
    "Suspicious_Packer_UPX": "The file has a marker used by UPX, a file compression tool. Safe and harmful files can both use it.",
    "Suspicious_Ransomware_Note": "The file contains phrases often seen in ransom notes. Check the file and other findings.",
    "Suspicious_Process_Injection_APIs": "The file mentions tools that can affect another running program. Some safe tools use them too.",
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


def build_html_report(report: dict[str, Any], model: dict[str, Any] | None = None) -> str:
    model = model or {}
    info = report.get("file_info", {})
    prediction = report.get("prediction", {})
    threat = report.get("threat_assessment", {})
    label = str(prediction.get("binary_label", "UNKNOWN"))
    signal = {"MALICIOUS": "Alert raised", "BENIGN": "No alert found", "UNKNOWN": "No result"}.get(label, label)
    yara_matches = threat.get("yara_matches", [])
    score = prediction.get("malware_probability")
    score_value = None if score is None else min(max(float(score), 0.0), 1.0)
    unverified = any("synthetic" in str(note).lower() for note in report.get("warnings", []))
    if unverified:
        status_class, status_title = "review", "Check this result yourself"
        status_text = "This report used a demo model that was not checked on real files. Do not rely on its score."
    elif score_value is not None and score_value >= .75:
        status_class, status_title = "review", "High model score — review this file"
        status_text = "The model saw signs it links with harmful files. This is a reason to investigate, not proof that the file is infected."
    elif score_value is not None and score_value <= .25 and label == "BENIGN" and not yara_matches:
        status_class, status_title = "safe", "No warning found"
        status_text = "The model and file checks found no warning. This does not prove the file is safe."
    elif yara_matches:
        status_class, status_title = "review", "Check this file more closely"
        status_text = "A file pattern matched. Safe programs can contain the same pattern, so check the details."
    elif score_value is not None:
        status_class, status_title = "review", "The result is unclear"
        status_text = "The model score is in the middle. Check where the file came from and read the other findings."
    else:
        status_class, status_title = "review", "Could not check this file"
        status_text = "A reliable model result is not available. Review the file details and rule matches."
    score_text = "Not available" if score is None else f"{float(score):.1%} (not infection chance)"
    meter_html = "<p class='muted'>The model did not return a score for this file.</p>" if score_value is None else (
        f"<div class='risk-meter'><div class='track'><span style='left:{score_value * 100:.2f}%'></span></div>"
        f"<div class='meter-labels'><span>Lower</span><strong>{score_value:.0%} model score</strong><span>Higher</span></div>"
        "<div class='meter-legend'><span><i class='green-dot'></i>Lower score</span><span><i class='yellow-dot'></i>Uncertain</span><span><i class='red-dot'></i>Higher score</span></div></div>"
    )
    eval_rows = "".join(
        f"<tr><th>{escape(label_text)}</th><td>{float(model['evaluation'][key]):.1%}</td></tr>"
        for key, label_text in METRIC_LABELS.items()
        if isinstance(model.get("evaluation", {}).get(key), (int, float))
    )
    if not eval_rows:
        eval_rows = '<tr><td colspan="2">Evaluation metrics are unavailable.</td></tr>'

    if yara_matches:
        yara_rows = "".join(
            f"<li><strong>{escape(RULE_TITLES.get(str(rule), str(rule).replace('_', ' ')))}</strong><br>"
            f"{escape(RULE_NOTES.get(str(rule), 'A file rule matched. This is a clue, not proof that the file is harmful.'))}</li>"
            for rule in yara_matches
        )
    else:
        yara_rows = "<li>No file rules matched.</li>"

    feature_rows = "".join(
        f"<tr><th>{escape(str(name))}</th><td>{escape(str(value))}</td></tr>"
        for name, value in report.get("static_features", {}).items()
    ) or '<tr><td colspan="2">No extracted features were recorded.</td></tr>'
    warning_html = (
        '<aside><strong>About this result</strong><p>The model may not be reliable for this file. Treat its score as unknown and use the file details and rule matches as clues.</p></aside>'
        if report.get("warnings") else ""
    )
    escaped_reason = escape(explain_findings(score, len(yara_matches)))
    review_level = {"CRITICAL": "Urgent", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Not available"}.get(str(threat.get("threat_level", "UNKNOWN")).upper(), str(threat.get("threat_level", "UNKNOWN")).title())
    file_type = "Windows program file" if info.get("file_type") == "Windows PE" else str(info.get("file_type", "Not available"))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IntelliStatic Report — {escape(str(info.get('filename', 'sample')))}</title>
<style>
:root{{font-family:'Segoe UI Variable','Segoe UI',Inter,Arial,sans-serif;color:#111827;background:#F8FAFC}}
*{{box-sizing:border-box}}body{{margin:0;padding:36px 18px;background:#f3f6fb}}
.sheet{{max-width:1120px;margin:auto;padding:36px;background:#fff;border:1px solid #E2E8F0;border-radius:16px;box-shadow:0 4px 14px #0f172a08}}
.top{{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #e5eaf2;padding-bottom:20px}}
.brand{{color:#111827;font-size:18px;font-weight:700}}.kicker{{color:#2563EB;font-size:10px;font-weight:700;letter-spacing:1.5px}}
h1{{font-size:34px;letter-spacing:-1px;margin:28px 0 7px}}.sub{{color:#68758b;margin:0 0 24px;line-height:1.55}}
.summary{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:20px 0 30px}}
.metric{{padding:17px;border:1px solid #e2e8f1;border-radius:12px;background:#fbfcff}}
.metric span{{display:block;color:#68758b;font-size:12px;margin-bottom:8px}}.metric strong{{font-size:20px}}
.status{{display:flex;gap:14px;align-items:flex-start;padding:18px 20px;margin:20px 0;border:1px solid;border-left-width:6px;border-radius:11px}}
.status .icon{{display:grid;place-items:center;flex:0 0 32px;width:32px;height:32px;border-radius:50%;font-weight:800}}
.status strong{{display:block;margin:2px 0 5px}}.status p{{margin:0;font-size:13px;line-height:1.55}}
.danger{{color:#842327;background:#fff1f1;border-color:#f4c8ca;border-left-color:#c9373d}}.danger .icon{{background:#fbdadd;color:#a8242b}}
.safe{{color:#135d43;background:#eef9f3;border-color:#ccebd9;border-left-color:#21845a}}.safe .icon{{background:#d5f0e1;color:#176a4a}}
.review{{color:#76520a;background:#fff8e7;border-color:#f0dfb2;border-left-color:#d49a16}}.review .icon{{background:#f8e9bd;color:#875e06}}
.risk-meter{{margin:18px 0 26px;padding:18px 20px;border:1px solid #e2e8f1;border-radius:12px;background:#fbfcff}}
.track{{position:relative;height:12px;border-radius:99px;background:linear-gradient(90deg,#45a779 0%,#a8cf75 25%,#e6c64d 50%,#e69a46 75%,#d85b58 100%);margin:12px 4px 8px}}
.track span{{position:absolute;top:50%;width:18px;height:18px;border:3px solid white;border-radius:50%;background:#172033;box-shadow:0 1px 5px #10182866;transform:translate(-50%,-50%)}}
.meter-labels,.meter-legend{{display:flex;justify-content:space-between;gap:10px;align-items:center;font-size:12px;color:#64748B}}.meter-labels strong{{color:#111827;font-size:15px}}.meter-legend{{margin-top:12px;font-size:11px}}.meter-legend span{{display:inline-flex;align-items:center;gap:6px}}.meter-legend i{{display:inline-block;width:8px;height:8px;border-radius:50%}}.green-dot{{background:#16A34A}}.yellow-dot{{background:#D97706}}.red-dot{{background:#DC2626}}
section{{margin:28px 0}}h2{{font-size:18px;margin:0 0 12px}}p{{line-height:1.6}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #e8edf4;vertical-align:top}}
th{{width:34%;color:#53627a;font-weight:650}}td{{color:#172033;overflow-wrap:anywhere}}
code{{color:#2457d6;background:#f0f4ff;padding:8px 10px;border-radius:7px;display:block;overflow-wrap:anywhere}}
li{{margin:9px 0;line-height:1.55}}aside{{padding:14px 17px;border-left:3px solid #2457d6;background:#f3f7ff;border-radius:7px}}
.muted{{color:#68758b;font-size:12px}}footer{{border-top:1px solid #e5eaf2;margin-top:32px;padding-top:15px;color:#68758b;font-size:12px}}
@media(max-width:650px){{body{{padding:10px}}.sheet{{padding:22px}}.summary{{grid-template-columns:1fr}}h1{{font-size:28px}}}}
@media print{{body{{padding:0;background:#fff}}.sheet{{max-width:none;border:0;box-shadow:none;padding:18px;border-radius:0}}}}
</style></head><body><main class="sheet">
<div class="top"><div class="brand">IntelliStatic</div><div class="kicker">WINDOWS FILE CHECK</div></div>
<h1>File report</h1><p class="sub">Checked {escape(str(report.get('created_at', '')))} · Report number {escape(str(report.get('analysis_id', '')))}</p>
{warning_html}
<section><h2>1. Summary</h2>
<div class="status {status_class}"><span class="icon">{"!" if status_class == "danger" else "✓" if status_class == "safe" else "?"}</span><div><strong>{escape(status_title)}</strong><p>{escape(status_text)}</p></div></div>
<p class="muted">A higher score means the model saw more signs it links with harmful files. It is not the chance that this file is harmful.</p>{meter_html}
<div class="summary"><div class="metric"><span>Model result</span><strong>{escape(signal)}</strong></div>
<div class="metric"><span>Model score</span><strong>{escape(score_text)}</strong></div>
<div class="metric"><span>Review level</span><strong>{escape(review_level)}</strong></div></div>
</section>
<section><h2>2. File details</h2><table>
<tr><th>Filename</th><td>{escape(str(info.get('filename', '')))}</td></tr>
<tr><th>Type</th><td>{escape(file_type)}</td></tr>
<tr><th>Size</th><td>{int(info.get('size_bytes', 0)):,} bytes</td></tr>
<tr><th>File ID (SHA-256)</th><td><code>{escape(str(info.get('sha256', '')))}</code></td></tr></table><p class="muted">This long ID helps you confirm that two files are the same.</p></section>
<section><h2>3. What we found</h2><p>{escaped_reason}</p><ul>{yara_rows}</ul><p class="muted">A rule match is a clue, not proof. Safe files can match a rule, and no match does not prove a file is safe.</p></section>
<section><h2>4. About the model</h2><table>
<tr><th>Model name</th><td>{escape(str(model.get('model_name', 'Not available')))}</td></tr>
<tr><th>Training data</th><td>{escape(str(model.get('training_dataset', 'Not recorded')))}</td></tr>
<tr><th>What it checks</th><td>It checks whether a file needs review. It does not name a malware family.</td></tr>
{eval_rows}</table><p class="muted">These test results come from files used during development. They do not guarantee how the model will judge a new file.</p></section>
<section><h2>5. File details checked</h2><table>{feature_rows}</table></section>
<footer>Files are checked without being run. Keep this report with the file ID if you need to review it later.</footer>
</main></body></html>"""
