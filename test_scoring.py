import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detector import calculate_risk


def test_internet_only_is_low():
    assert calculate_risk(["android.permission.INTERNET"])[:2] == (5, "LOW RISK")


def test_accessibility_plus_internet_is_high_with_multiplier():
    score, level, pattern = calculate_risk([
        "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.INTERNET"])
    assert score == 75 and level == "HIGH THREAT"
    assert "Accessibility" in pattern


def test_mic_plus_internet_flagged():
    score, level, pattern = calculate_risk(["android.permission.RECORD_AUDIO", "android.permission.INTERNET"])
    assert score == 25 and level == "MEDIUM RISK" and "Mic Snooping" in pattern


def test_score_capped_at_100():
    perms = ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "RECORD_AUDIO", "CAMERA", "INTERNET"]
    assert calculate_risk(perms)[0] == 100


def test_no_substring_false_positive():
    assert calculate_risk(["com.x.CAMERA_ACCESS_FAKE"])[0] == 0


def test_sms_plus_internet_flagged_medium():
    score, level, pattern = calculate_risk(["android.permission.READ_SMS", "android.permission.INTERNET"])
    assert level == "MEDIUM RISK" and "OTP" in pattern
