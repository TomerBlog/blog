---
title: "Projects"
layout: "list"
---

I’ve had the opportunity to develop several open-source tools.

This page gives an overview of three such tools, each built for red teamers, blue teamers, and researchers looking to explore and simulate real-world attack vectors in identity environments.

---

## 🔐 [EntraGoat](https://github.com/semperis/entragoat)

> A deliberately vulnerable Microsoft Entra ID environment for simulating real-world identity security misconfigurations.

EntraGoat is designed for security professionals who want to **train**, **test**, or **demonstrate attacks** in a controlled hybrid identity setup. It introduces common misconfigurations in a test tenant and supports:

- **Privilege escalation paths** in Microsoft Entra ID (formerly Azure AD)
- An **interactive web UI** for challenge management
- Deployment via **PowerShell + Microsoft Graph API**

🛠️ GitHub: [https://github.com/Semperis/Entragoat](https://github.com/semperis/entragoat)

---

## 🔨 [SilverSAMLForger](https://github.com/Semperis/SilverSamlForger)

> A tool for forging SAML tokens in Silver SAML attacks when the private key is compromised.

**SilverSAML** refers to attacks where the attacker abuses knowledge of a SAML private key to forge authentication tokens, even in federated environments.

SilverSAMLForger makes it easy to:

- Craft custom **forged SAML assertions**
- Simulate SAML-based impersonation
- Support red team exercises or blue team testing

🛡️ It's ideal for understanding and testing **SAML token abuse** in hybrid identity environments.

🔗 GitHub: [https://github.com/Semperis/SilverSamlForger](https://github.com/semperis/silversamlforger)

---

## 🧰 [SAMLSmith](https://github.com/Semperis/SAMLSmith)

> A versatile SAML manipulation toolkit for red teamers and researchers.

SAMLSmith is a **lightweight but powerful** tool that allows manipulation of SAML assertions for testing a variety of misconfigurations and weaknesses:

- Modify SAML attributes (NameID, Role, Group, etc.)

It’s great for both **educational labs** and advanced testing of **SAML processing logic** in enterprise apps.

🔗 GitHub: [https://github.com/semperis/SAMLSmith](https://github.com/semperis/SAMLSmith)



