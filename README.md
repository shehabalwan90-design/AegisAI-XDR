 # 🛡️ AegisAI-XDR - AI-Powered SOC

**AI-Powered Extended Detection & Response with Behavioral Engine, Threat Intelligence & SOC Dashboard.**

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Accuracy](https://img.shields.io/badge/Accuracy-96.43%25-green)
![Tests](https://img.shields.io/badge/Tests-19%2F19_Passed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

> First project by **Shehab Alwan** - Cybersecurity Student, Mukalla, Hadhramaut, Yemen

---

## ✨ What is this?

AegisAI-XDR is a full SOC system that monitors your PC in real-time, detects attacks with AI, checks threats with free public feeds, and shows everything in a professional dashboard.

It doesn't just use signatures. It uses **Behavioral AI (Isolation Forest)** to detect strange behavior.

## 🚀 Features

- **LIVE Mode:** Real-time monitoring of processes, network & files
- **SIMULATE Mode:** 5 attack scenarios for safe training (Ransomware, Reverse Shell, Exfiltration, Miner, Port Scan)
- **Behavioral Engine:** Isolation Forest trained on your own baseline
- **Threat Intel:** Free public feeds only - No API key required. Abuse.ch key is optional.
- **AI Assistant:** Explains alerts in plain language
- **SOC Dashboard:** Professional GUI with live charts

## 🖥️ How to Run

```bash
pip install -r requirements.txt
python main.py --gui