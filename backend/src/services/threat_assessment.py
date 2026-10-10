from typing import Any


def assess_threat(prediction: dict[str, Any], yara_matches: list[str]) -> dict[str, Any]:
    label = prediction["binary_label"]
    malware_probability = prediction["malware_probability"]

    if label == "UNKNOWN" or malware_probability is None:
        return {
            "threat_level": "UNKNOWN", "composite_score": None, "analysis_type": "STATIC",
            "file_executed": False, "yara_matches": yara_matches,
            "reasoning": "A reliable model score is not available for this file. Check the file details and any rule matches below.",
        }

    if label == "BENIGN":
        level = "MEDIUM" if yara_matches else "LOW"
        reasoning = (
            f"The model score is low ({malware_probability:.1%}), but a file rule matched. Please review the specific rule evidence below. Safe programs can match rules too."
            if yara_matches else
            f"The model score is low ({malware_probability:.1%}), and no file rules matched. This does not prove the file is safe."
        )
        return {
            "threat_level": level, "composite_score": 0.15 if yara_matches else 0.0,
            "analysis_type": "STATIC", "file_executed": False,
            "yara_matches": yara_matches, "reasoning": reasoning,
        }

    score = malware_probability
    if score >= 0.90:
        level = "CRITICAL"
    elif score >= 0.75:
        level = "HIGH"
    elif score >= 0.55:
        level = "MEDIUM"
    else:
        level = "LOW"
    if yara_matches and level == "LOW":
        level = "MEDIUM"
    reasoning = (
        f"The model score is high ({malware_probability:.1%}). This is not proof of malicious behavior. "
        "Review the file and the other evidence before deciding."
    )
    if yara_matches:
        reasoning += f" {len(yara_matches)} file rule(s) also matched."
    return {
        "threat_level": level, "composite_score": score, "analysis_type": "STATIC",
        "file_executed": False, "yara_matches": yara_matches, "reasoning": reasoning,
    }
