# ❤️ LoL Attack Detection Recipes

A practical detection guide for **Living off the Land (LoL) attacks** across Windows and Linux environments.

This project focuses on how attackers abuse legitimate system binaries and how defenders can detect that abuse using native system logs and SIEM queries.

---

## 💀 What This Project Covers

This repository contains structured detection recipes for:

- 🪟 **Windows LOLBins**
- 🐧 **Linux GTFOBins**

Each section includes:

- 📖 Clear explanation of the abuse technique  
- 🧠 Detection logic breakdown  
- 🗂 Relevant Event IDs  
- 🔎 Log-level analysis  
- 📊 Sample Splunk queries for quick implementation  

The goal is to move from theory → to practical detection.

---

## 🪟 Windows – LOLBins

Covers detection strategies for commonly abused binaries such as:

- `powershell.exe`
- `certutil.exe`
- `mshta.exe`
- `rundll32.exe`
- `wmic.exe`

Focus areas:

- Process creation events  
- Command-line arguments  
- Parent-child relationships  
- Network correlation  
- Pre-built detection queries  

---

## 🐧 Linux – GTFOBins

Focuses on detecting abuse of legitimate Unix binaries, especially in cases involving:

- Misconfigured `sudo`
- Shell escapes
- Privilege escalation
- Unexpected process chains

Detection is built using:

- Native system logs  
- `auditd` telemetry  
- Process execution patterns  
- Privilege transition visibility  

---

## 🐳 Project Goal

This project is built to:

- Help security analysts understand LoL attacks clearly  
- Provide ready-to-use detection logic  
- Encourage log-level visibility before SIEM abstraction  
- Serve as a practical reference for blue teams  

Living off the Land attacks hide in plain sight.  
Detection requires context, behavior analysis, and proper logging — not just signatures.

---

## 🧸 Who Is This For?

- SOC Analysts  
- Threat Hunters  
- Blue Team Engineers  
- Security Researchers  
- Anyone learning detection engineering  

---

## 🪳 Contributing

Feel free to fork, suggest improvements, or add more detection recipes.

More platforms and techniques may be added in the future.
