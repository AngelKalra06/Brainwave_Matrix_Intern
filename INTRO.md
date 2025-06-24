# 🛡️ Phishing Link Scanner using Python

🎯 **Project Goal: Build a basic Phishing Link Scanner with a simple Python-based frontend**

---

## 📌 Project Overview

The goal is to develop a **Phishing Link Scanner** using **Python** with a simple frontend. The scanner analyzes a given URL and returns basic insights into whether the link may be potentially suspicious or safe.

---

## 🚀 Features

- ✅ Simple GUI using `tkinter` (no external frontend frameworks)
- 🔍 Scans URLs for common phishing indicators:
  - Use of IP addresses in domain
  - Suspicious TLDs (like `.tk`, `.ml`)
  - Hyphen-abuse in domain names
  - Missing HTTPS
- 📄 Displays basic scan result summary with color-coded feedback
- 🗂️ Logs scanned URLs with timestamps into a local file
- 🔁 Option to clear and scan again

---

## 🧰 Technologies Used

- `Python 3.x`
- `tkinter` for frontend GUI
- `re`, `urlparse`, and `requests` for URL parsing and analysis
- No third-party frontend or database


