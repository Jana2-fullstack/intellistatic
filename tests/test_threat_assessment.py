from src.services.threat_assessment import assess_threat


def test_unknown_model_never_becomes_benign() -> None:
    assessment = assess_threat({
        "binary_label": "UNKNOWN", "malware_probability": None,
        "threat_family": "Unknown", "threat_family_confidence": None,
    }, [])
    assert assessment["threat_level"] == "UNKNOWN"
    assert assessment["composite_score"] is None


def test_benign_yara_short_circuit_is_medium() -> None:
    assessment = assess_threat({
        "binary_label": "BENIGN", "malware_probability": .02,
        "threat_family": "Benign", "threat_family_confidence": .95,
    }, ["Suspicious_Anti_Debug"])
    assert assessment["threat_level"] == "MEDIUM"
    assert "review the specific rule evidence" in assessment["reasoning"]


def test_malicious_triage_score_includes_yara_evidence() -> None:
    prediction = {
        "binary_label": "MALICIOUS", "malware_probability": .9,
        "threat_family": "Ransomware", "threat_family_confidence": .9,
    }
    assessment = assess_threat(prediction, ["Suspicious_Ransomware_Note"])
    assert assessment["threat_level"] == "CRITICAL"
    assert abs(assessment["composite_score"] - .9) < 1e-9
    assert "not proof of malicious behavior" in assessment["reasoning"]
