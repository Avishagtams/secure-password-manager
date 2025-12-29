🔐 Secure Password Manager

A secure password management application built using Python (Flask), focusing on secure password storage, encryption, and session-based access control.

The system demonstrates a practical implementation of modern cryptographic principles and secure authentication flows.

📌 Project Overview

This application allows users to securely manage their credentials by storing all passwords in an encrypted vault.

Key capabilities include:

Secure user registration and authentication

Encrypted storage of application passwords

View, copy, update, and delete stored access credentials

Enforce strong password policies

Session-based encryption keys stored only in memory

At no point are passwords stored or transmitted in plain text.

🛠 Technologies Used

Python 3.10

Flask

SQLite

AES-GCM (verified encryption)

PBKDF2 key derivation

HTML / CSS / JavaScript

🔐 Security Design

The system follows security best practices, including:

Password hashing for user authentication

Random salt per user for key derivation

AES-GCM encryption for all stored passwords

Encryption keys derived at login and stored only in memory

Automatic session expiration after inactivity

Login rate limiting and temporary account lockout

HttpOnly cookies for session IDs

🔄 Application Flow

User signs up with a strong master password

Password hashed and securely stored

At login:

Password hash verified

AES encryption key derived from master password

Vault passwords encrypted before Reserved

Passwords are decrypted only on demand while the session is active

🖥 Running the application locally
1️⃣ Clone the repository
git clone https://github.com/Avishagtams/secure-password-manager.git
cd secure-password-manager

2️⃣ Create and activate a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate # Windows

3️⃣ Install dependencies
pip install -r requirements.txt

4️⃣ Run the application
python app_web.py

5️⃣ Open in browser
http://127.0.0.1:5000

📂 Project structure
Secure_Password_Manager/
- app_web.py # Main Flask application
- crypto_utils.py # Cryptographic utilities
- db.py # Database access layer
- emplates/ # HTML templates
- static/ # CSS and frontend assets
- passwords.db # Database SQLite data (automatically generated)
- README.md

🧪 Tests

The project includes automated tests using pytest.

To run tests:

python -m pytest

👤 Author

Avishag Tamsut and Sahar Emmuna
Bachelor of Science in Software Engineering
Sami Shimon College of Engineering (SCE)
