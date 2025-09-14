# GuardianEye - Real-time Security Monitoring System 🔐👁️

## Overview
GuardianEye is a comprehensive security monitoring system designed to detect and alert on suspicious authentication attempts in real-time.

## ✨ Key Features
- 🔍 Real-time Monitoring with watchdog
- 🚨 Brute Force & Blacklist Detection
- 📊 Web Dashboard (Flask) for reports
- 💾 SQLite for persistence
- 📱 Telegram alerts

## 🖥️ Architecture
- `monitor.py` → Log monitoring engine
- `ip_manager.py` → Manage whitelist/blacklist
- `dashboard.py` → Flask security dashboard
- `user_manager.py` → (optional) Flask login
- SQLite DB for persistence

## 📊 Dashboard
- Top attacker IPs
- Attack reason breakdown
- Time-based trends

## 🚀 Setup
1. Clone repo:
   ```bash
   git clone https://github.com/yourusername/GuardianEye.git
   cd GuardianEye
