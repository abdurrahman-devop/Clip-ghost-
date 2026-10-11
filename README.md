# 👻 CLIPGHOST

**Automated mobile anti-spyware & privacy auditing framework for Linux (Kali) — powered by ADB.**

CLIPGHOST connects to an Android device over the Android Debug Bridge, reads the permissions each third-party app requests, and scores them with a heuristic risk model. No APK decompiling, no emulator, nothing installed on the phone.

![CLI](docs/screenshots/cli.png)

## Features

- **Zero-compilation** – pure Python 3 on the host, uses the `adb` binary
- **Heuristic risk scoring** – weighted permissions, score 0–100, classified as LOW / MEDIUM / HIGH
- **Compound threat detection** – flags combinations, not just single permissions:
  - Accessibility + Internet → exfiltration (score × 1.5)
  - Microphone + Internet → mic snooping
  - SMS + Internet → OTP interception
- **CLI and PyQt5 GUI**, with one-click uninstall of a flagged app
- **JSON export** of results

## Risk model

| Permission | Points |
|---|---|
| `BIND_ACCESSIBILITY_SERVICE` | 45 |
| `SYSTEM_ALERT_WINDOW` | 25 |
| `RECORD_AUDIO` | 20 |
| `READ_SMS` / `RECEIVE_SMS` | 20 |
| `CAMERA` | 15 |
| `INTERNET` | 5 |

Accessibility + Internet multiplies the total by 1.5. Score ≥ 60 = **HIGH THREAT**, ≥ 25 = **MEDIUM RISK**, otherwise **LOW RISK**.

## Requirements

- Kali Linux / any Linux, Python 3.10+
- `adb` → `sudo apt install adb`
- PyQt5 (GUI only) → `pip install -r requirements.txt`
- Android phone with **USB debugging** enabled

## Usage

```bash
git clone https://github.com/<your-username>/clipghost.git
cd clipghost

python3 detector.py --cli --demo        # try it without a phone
python3 detector.py --cli               # audit connected device
python3 detector.py --cli --json report.json
python3 detector.py --gui               # desktop interface
```

Run `adb devices` first and accept the debugging prompt on the phone.

## How it works

1. `adb shell pm list packages -3` lists installed third-party apps
2. `adb shell dumpsys package <pkg>` returns each app's requested permissions
3. The scoring engine adds weights, applies compound rules, and classifies the app
4. Results are shown in the terminal or GUI

![ADB architecture](docs/screenshots/adb-architecture.png)

## GUI

![GUI](docs/screenshots/gui-results.png)

## Project report

Full report (theory, architecture, results): [`docs/Clipghost-Project-Report.pdf`](docs/Clipghost-Project-Report.pdf)

## Limitations

- Scores are based on **requested permissions only** — a high score means "worth investigating", not "confirmed malware"
- Does not inspect network traffic or app code yet
- Legitimate apps (chat, banking) can score as medium because they genuinely need these permissions

## Roadmap

- [ ] PCAP / TShark traffic correlation
- [ ] Process memory inspection
- [ ] Multi-device parallel auditing
- [ ] PDF report export

## Tests

```bash
pip install pytest && pytest tests
```

## Disclaimer

For education and auditing **your own devices** or devices you have permission to test.

## Author

**Abdur Rahman R** — Cyber Security project (Batch CPT)
