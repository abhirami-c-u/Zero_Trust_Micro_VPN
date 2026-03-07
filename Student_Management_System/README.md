# Student Management System with Zero Trust VPN

A comprehensive school management portal featuring Student, Parent, Faculty, and Admin dashboards, secured with Zero Trust architecture and an encrypted VPN tunnel.

## 🚀 Key Features
- **Zero Trust Security**: Continuous authentication and trust score assessment.
- **Adaptive MFA**: Context-aware OTP login.
- **VPN Tunneling**: Secure communication between the portal and service endpoints.
- **Encrypted Logging**: All sensitive actions are logged with AES-GCM encryption.
- **Anomaly Detection**: Impossible travel and time-of-day login monitoring.

---

## 🛠️ Step-by-Step Setup

### 1. Prerequisites
- Python 3.8+
- SQLite3

### 2. Environment Setup
Create a virtual environment and install dependencies:
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configuration
Copy the `.env.example` to `.env` and update your settings:
```bash
cp .env.example .env
```
- **Gmail Setup**: To use SMTP for OTP, create an "App Password" in your Google Account Security settings.
- **Secrets**: Update `SECRET_KEY` and `JWT_SECRET` with random strings.

### 4. Zero Trust VPN Keys
Generate the cryptographic keys required for the VPN tunnel and log encryption:
```bash
python zero_trust_vpn/generate_keys.py
```
*This will create the `zero_trust_vpn/keys/` directory.*

### 5. Database Initialization
The database will automatically initialize upon first run. If you need to reset it:
```bash
python app.py  # Run and stop it once
```
*Default login: `admin` / `admin123`*

---

## 🏃 How to Run

### Part 1: Start the VPN Server
Open a terminal and run the Zero Trust policy enforcement server:
```bash
python zero_trust_vpn/vpn_server.py
```

### Part 2: Start the Web Portal
Open another terminal and run the main Flask application:
```bash
python app.py
```
Access the portal at: `http://127.0.0.1:5000`

---

## 🛡️ Security Note
This project uses `.gitignore` to prevent committing your `.env` secrets, your `.db` database, and your private `.pem` keys. **Never commit these files to a public repository.**
