<img width="1917" height="886" alt="Screenshot 2025-04-19 162815" src="https://github.com/user-attachments/assets/9e406c55-8a23-4271-923b-d09584b54c50" />


# Secure Code 🔒
A comprehensive security analysis platform that combines Static Application Security Testing (SAST), Dynamic Application Security Testing (DAST), and advanced genetic algorithm-based vulnerability exploitation testing to identify and assess security vulnerabilities in source code.

# Features
## 🔍 SAST Module (Static Analysis)
CNN-Based Vulnerability Detection: Utilizes Convolutional Neural Networks to statically analyze source code for security vulnerabilities

Multiple Vulnerability Types Detected:

Injection attacks (SQL, NoSQL, OS command, etc.)

Cross-Site Scripting (XSS) vulnerabilities

Insecure API usage and cryptographic practices

Remote Code Execution vulnerabilities

Hard-coded credentials and sensitive information

Security misconfigurations

## 🚀 DAST Module (Dynamic Analysis)
Safe Execution Environment: Code execution within isolated Docker containers for security

OWASP ZAP Integration: Comprehensive runtime vulnerability scanning using industry-standard tools

Runtime Vulnerability Detection: Identifies vulnerabilities that only manifest during execution

Real-time Security Monitoring: Dynamic analysis of application behavior during runtime

## 🧬 Genetic Algorithm Testing
Adaptive Payload Generation: Evolves test payloads using genetic algorithms to maximize vulnerability discovery

Exploitability Assessment: Quantifies the exploitability level of identified vulnerabilities

Intelligent Fuzzing: Generates and tests increasingly effective attack vectors

Risk Prioritization: Ranks vulnerabilities based on actual exploit potential


# Clone the repository
git clone https://github.com/AdeenIlyas/Secure-Code.git

# Navigate to project directory
cd SecureCode-AI

# Install dependencies
pip install -r requirements.txt

# Run
python app.py

