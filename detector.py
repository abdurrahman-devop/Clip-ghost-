#!/usr/bin/env python3
"""CLIPGHOST - Automated mobile anti-spyware & privacy auditing framework.

Audits third-party apps on an Android device connected over ADB and scores
them with a heuristic permission-risk model.

Usage:
    python3 detector.py --cli            # terminal report of a connected device
    python3 detector.py --cli --demo     # same, with built-in sample data (no device needed)
    python3 detector.py --gui            # PyQt5 desktop interface
    python3 detector.py --cli --json out.json
"""
import argparse
import json
import re
import shutil
import subprocess
import sys

# ---------------------------------------------------------------- scoring model
# Weights follow the project report (Chapter 3.2).
WEIGHTS = {
    "BIND_ACCESSIBILITY_SERVICE": 45,
    "SYSTEM_ALERT_WINDOW": 25,
    "RECORD_AUDIO": 20,
    "CAMERA": 15,
    "READ_SMS": 20,
    "RECEIVE_SMS": 20,
    "INTERNET": 5,
}
EXFIL_MULTIPLIER = 1.5     # accessibility + internet
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 25


def short(perm: str) -> str:
    """'android.permission.CAMERA' -> 'CAMERA'."""
    return perm.rsplit(".", 1)[-1]


def calculate_risk(permissions):
    """Return (score 0-100, risk level, threat pattern text)."""
    perms = {short(p) for p in permissions}
    score = sum(w for name, w in WEIGHTS.items() if name in perms)

    has_net = "INTERNET" in perms
    patterns = []
    if "BIND_ACCESSIBILITY_SERVICE" in perms and has_net:
        score = int(score * EXFIL_MULTIPLIER)
        patterns.append("Accessibility + Exfiltration")
    if "RECORD_AUDIO" in perms and has_net:
        patterns.append("Mic Snooping + Exfiltration")
    if {"READ_SMS", "RECEIVE_SMS"} & perms and has_net:
        patterns.append("OTP Interception + Exfiltration")

    score = min(score, 100)
    if score >= HIGH_THRESHOLD:
        level = "HIGH THREAT"
    elif score >= MEDIUM_THRESHOLD:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"
    return score, level, " | ".join(patterns) or "No Active Spyware Patterns"


# ---------------------------------------------------------------- ADB layer
def adb(*args, timeout=30):
    """Run an adb command and return stdout. Raises RuntimeError on failure."""
    if shutil.which("adb") is None:
        raise RuntimeError("adb not found. Install it: sudo apt install adb")
    try:
        r = subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"adb {' '.join(args)} timed out")
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "adb command failed")
    return r.stdout


def check_device():
    lines = adb("devices").strip().splitlines()[1:]
    ready = [l for l in lines if l.endswith("\tdevice")]
    if not ready:
        raise RuntimeError("No authorised device found. Enable USB debugging and accept the prompt on the phone.")


def list_third_party_packages():
    out = adb("shell", "pm", "list", "packages", "-3")
    return sorted(l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("package:"))


def get_permissions(package):
    """Parse the 'requested permissions' block of `dumpsys package`."""
    out = adb("shell", "dumpsys", "package", package)
    perms, in_block = [], False
    for line in out.splitlines():
        stripped = line.strip()
        if stripped == "requested permissions:":
            in_block = True
            continue
        if in_block:
            if re.match(r"^[\w.]+(\.[\w]+)+(:.*)?$", stripped):
                perms.append(stripped.split(":")[0])
            else:
                in_block = False
    return perms


def audit_device():
    check_device()
    results = []
    for pkg in list_third_party_packages():
        try:
            perms = get_permissions(pkg)
        except RuntimeError:
            continue
        score, level, pattern = calculate_risk(perms)
        results.append({"package": pkg, "permissions": len(perms),
                        "score": score, "level": level, "pattern": pattern})
    return sorted(results, key=lambda r: r["score"], reverse=True)


def demo_audit():
    sample = {
        "com.example.notes": ["android.permission.INTERNET"],
        "com.example.flashlight": ["android.permission.CAMERA", "android.permission.INTERNET"],
        "com.example.voicechat": ["android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
        "com.example.otpreader": ["android.permission.READ_SMS", "android.permission.INTERNET"],
        "com.sample.suspicious.app": ["android.permission.BIND_ACCESSIBILITY_SERVICE",
                                      "android.permission.SYSTEM_ALERT_WINDOW",
                                      "android.permission.INTERNET"],
    }
    rows = []
    for pkg, perms in sample.items():
        s, l, p = calculate_risk(perms)
        rows.append({"package": pkg, "permissions": len(perms), "score": s, "level": l, "pattern": p})
    return sorted(rows, key=lambda r: r["score"], reverse=True)


def uninstall(package):
    return "Success" in adb("uninstall", package)


# ---------------------------------------------------------------- CLI
COLORS = {"HIGH THREAT": "\033[91m", "MEDIUM RISK": "\033[93m", "LOW RISK": "\033[92m"}


def print_report(rows):
    print(f"\n{'APP PACKAGE':<45}{'PERMS':>6}{'SCORE':>7}  {'LEVEL':<13}PATTERN")
    print("-" * 110)
    for r in rows:
        c = COLORS[r["level"]]
        print(f"{r['package']:<45}{r['permissions']:>6}{r['score']:>7}  "
              f"{c}{r['level']:<13}\033[0m{r['pattern']}")
    high = sum(r["level"] == "HIGH THREAT" for r in rows)
    med = sum(r["level"] == "MEDIUM RISK" for r in rows)
    print(f"\n{len(rows)} apps audited | {high} high threat | {med} medium risk")


def run_cli(args):
    print("[*] CLIPGHOST Engine: initialising CLI audit mode ...")
    try:
        rows = demo_audit() if args.demo else audit_device()
    except RuntimeError as e:
        sys.exit(f"[!] {e}")
    print_report(rows)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(rows, f, indent=2)
        print(f"[+] Report saved to {args.json}")


# ---------------------------------------------------------------- GUI
def run_gui(args):
    try:
        from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QTableWidget,
                                     QTableWidgetItem, QVBoxLayout, QWidget, QLabel,
                                     QHBoxLayout, QMessageBox)
        from PyQt5.QtGui import QColor
        from PyQt5.QtCore import Qt
    except ImportError:
        sys.exit("[!] PyQt5 missing. Run: pip install PyQt5   (or sudo apt install python3-pyqt5)")

    level_color = {"HIGH THREAT": "#ff6b6b", "MEDIUM RISK": "#ffd43b", "LOW RISK": "#90ee90"}

    class Window(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("CLIPGHOST - Mobile Anti-Spyware Engine")
            self.resize(1000, 600)
            self.table = QTableWidget(0, 5)
            self.table.setHorizontalHeaderLabels(
                ["Package Name", "Permissions", "Score", "Threat Level", "Detected Threat Patterns"])
            self.table.setSelectionBehavior(QTableWidget.SelectRows)
            self.table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.setColumnWidth(0, 320)
            scan = QPushButton("1. Initiate Full Privacy Audit (ADB)")
            scan.clicked.connect(self.scan)
            remove = QPushButton("2. Remove Selected App")
            remove.clicked.connect(self.remove)
            self.status = QLabel("Ready")
            bar = QHBoxLayout()
            bar.addWidget(scan)
            bar.addWidget(remove)
            lay = QVBoxLayout()
            lay.addLayout(bar)
            lay.addWidget(self.table)
            lay.addWidget(self.status)
            box = QWidget()
            box.setLayout(lay)
            self.setCentralWidget(box)

        def scan(self):
            self.status.setText("Scanning device ...")
            QApplication.processEvents()
            try:
                rows = demo_audit() if args.demo else audit_device()
            except RuntimeError as e:
                self.status.setText("Error")
                QMessageBox.critical(self, "Scan failed", str(e))
                return
            self.table.setRowCount(len(rows))
            for i, r in enumerate(rows):
                vals = [r["package"], r["permissions"], r["score"], r["level"], r["pattern"]]
                for j, v in enumerate(vals):
                    item = QTableWidgetItem(str(v))
                    if j == 3:
                        item.setBackground(QColor(level_color[r["level"]]))
                        item.setForeground(QColor("black"))
                    self.table.setItem(i, j, item)
            self.status.setText(f"{len(rows)} apps audited")

        def remove(self):
            row = self.table.currentRow()
            if row < 0:
                return
            pkg = self.table.item(row, 0).text()
            if QMessageBox.question(self, "Confirm", f"Uninstall {pkg} from the device?") != QMessageBox.Yes:
                return
            try:
                ok = uninstall(pkg)
            except RuntimeError as e:
                QMessageBox.critical(self, "Failed", str(e))
                return
            self.status.setText(f"{pkg} removed" if ok else f"Could not remove {pkg}")
            if ok:
                self.table.removeRow(row)

    app = QApplication(sys.argv[:1])
    w = Window()
    w.show()
    sys.exit(app.exec_())


def main():
    p = argparse.ArgumentParser(description="CLIPGHOST - Android privacy auditor over ADB")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--cli", action="store_true", help="terminal mode (default)")
    mode.add_argument("--gui", action="store_true", help="PyQt5 GUI mode")
    p.add_argument("--demo", action="store_true", help="use sample data, no device needed")
    p.add_argument("--json", metavar="FILE", help="save CLI results as JSON")
    args = p.parse_args()
    run_gui(args) if args.gui else run_cli(args)


if __name__ == "__main__":
    main()
