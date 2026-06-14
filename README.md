# HYDRA

### Hybrid Dual-Server Reactive Encryption Architecture

HYDRA is a threat-driven cryptographic storage system designed to eliminate single points of failure and automatically respond to security breaches. Unlike conventional systems that rotate encryption keys on fixed schedules, HYDRA continuously monitors system behavior and triggers autonomous key evolution only when a breach is detected.

The project demonstrates how modern cryptographic primitives, distributed trust, autonomous breach response, and secure failover mechanisms can be combined into a resilient encrypted storage architecture.

---

## Overview

HYDRA distributes encrypted data across two independent servers. Neither server possesses enough information to decrypt stored records on its own.

When suspicious activity is detected:

1. A new encryption key is derived using HKDF.
2. All records are re-encrypted.
3. The previous key is cryptographically destroyed.
4. The standby server is promoted to primary.
5. The compromised server is isolated.
6. Every action is recorded in a tamper-evident audit log.

All of this occurs automatically without human intervention.

---

## Key Features

### Cryptographic Features

* XChaCha20 authenticated encryption
* Shamir (3,2) Secret Sharing
* HKDF-BLAKE2s key ratcheting
* Fiat-Shamir Zero-Knowledge Proofs
* Immutable hash-chained audit logs
* Forward secrecy through key evolution
* Cryptographic key destruction

### Security Features

* Threat-driven breach detection
* Autonomous breach response
* Automatic failover
* Server isolation
* Tamper-evident logging
* Dual-server architecture
* Secure key distribution

### System Features

* Real-time monitoring dashboard
* Heartbeat-based server synchronization
* Automatic record mirroring
* Encrypted medical records demonstration
* SQLite-backed storage
* REST API architecture

---

# Architecture

```text
                     ┌──────────────────┐
                     │      Client      │
                     │     Share S3     │
                     └────────┬─────────┘
                              │
                              │
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼

      ┌────────────────┐         ┌────────────────┐
      │    Server A    │ <-----> │    Server B    │
      │    Primary     │ Heart   │    Standby     │
      │    Share S1    │ Beat    │    Share S2    │
      └────────────────┘         └────────────────┘
              │                               │
              └───────────Mirrored────────────┘
                       Encrypted Records

```

---

# Core Cryptographic Components

## 1. XChaCha20 Stream Cipher

HYDRA uses a custom implementation of XChaCha20.

Features:

* 256-bit encryption key
* 192-bit nonce
* ARX (Add-Rotate-XOR) design
* Resistance to timing attacks
* Large nonce space
* High performance

Provides:

* Confidentiality
* Integrity
* Authenticated encryption

---

## 2. Shamir Secret Sharing

The master key is split into three shares.

```text
S1 → Server A
S2 → Server B
S3 → Client Token
```

Threshold:

```text
(3,2)
```

Any two shares reconstruct the key.

Benefits:

* No single point of failure
* Distributed trust
* Secure key recovery

---

## 3. HKDF Ratchet

Key evolution uses HKDF-BLAKE2s.

```text
K(n)  →  HKDF  →  K(n+1)
```

Properties:

* One-way derivation
* Forward secrecy
* Domain separation
* Cryptographic key rotation

---

## 4. Fiat-Shamir Zero-Knowledge Proof

Before failover:

* Standby server proves possession of a valid share.
* No key material is disclosed.
* Prevents fake server promotion.

---

## 5. Immutable Audit Log

Every security event is recorded.

```text
Hash(i) = BLAKE2s(
    EventData +
    Hash(i-1)
)
```

Benefits:

* Tamper evidence
* Event accountability
* Chain verification

---

# Breach Detection Engine

HYDRA continuously computes an anomaly score using five independent signals.

| Signal                  | Weight |
| ----------------------- | ------ |
| Request Rate            | 0.25   |
| Geographic Deviation    | 0.30   |
| Timing Drift            | 0.20   |
| Authentication Failures | 0.15   |
| Peer Gossip Delta       | 0.10   |

Formula:

```text
Score =
0.25R +
0.30G +
0.20T +
0.15A +
0.10P
```

Threshold:

```text
θ = 0.55
```

If exceeded:

```text
Ratchet Triggered
```

---

# Autonomous Ratchet Sequence

When a breach occurs:

### Step 1

Detect anomaly.

```text
Score ≥ 0.55
```

### Step 2

Derive new key.

```text
K(n+1)
```

### Step 3

Destroy previous key.

```text
K(n) → 000000...
```

### Step 4

Re-encrypt all records.

### Step 5

Promote standby server.

### Step 6

Isolate compromised server.

### Step 7

Resume operation.

No manual intervention is required.

---

# Repository Structure

```text
CRP_PROJECT/

├── client/
│   ├── cli.py
│   ├── token.py
│   └── token.json
│
├── core/
│   ├── audit.py
│   ├── hkdf.py
│   ├── shamir.py
│   ├── xchacha20.py
│   └── zkp.py
│
├── dashboard/
│   ├── index.html
│   ├── app.js
│   ├── style.css
│   └── pages/
│
├── data/
│   ├── raw/
│   ├── processed/
│   └── preprocess.py
│
├── server_a/
│   ├── app.py
│   ├── breach.py
│   ├── store.py
│   └── audit_a.json
│
├── server_b/
│   ├── app.py
│   ├── breach.py
│   ├── store.py
│   └── audit_b.json
│
├── heartbeat.py
├── reencrypt.py
├── run.py
├── token_creation.py
├── test_breach_cycle.py
└── requirements.txt
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/Arjun-m-b/CRP_PROJECT.git
cd CRP_PROJECT
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Running HYDRA

Start the complete system:

```bash
python run.py
```

This will:

* Start Server A
* Start Server B
* Perform key ceremony
* Generate key shares
* Load encrypted records
* Start heartbeat monitoring

---

# API Endpoints

| Endpoint         | Method | Purpose                |
| ---------------- | ------ | ---------------------- |
| /status          | GET    | Server health          |
| /init            | POST   | Key ceremony           |
| /store           | POST   | Store encrypted record |
| /fetch/<id>      | GET    | Retrieve record        |
| /fetch/all       | GET    | Record metadata        |
| /heartbeat       | POST   | Peer synchronization   |
| /score           | GET    | Breach score           |
| /ratchet         | POST   | Trigger ratchet        |
| /promote         | POST   | Promote standby        |
| /isolate         | POST   | Isolate server         |
| /simulate_breach | POST   | Demo breach            |
| /audit           | GET    | Audit log              |
| /audit/summary   | GET    | Event summary          |
| /audit/verify    | GET    | Verify chain           |
| /reset           | POST   | Reset system           |

---

# Dashboard

The dashboard provides:

* Live server status
* Current epoch
* Breach score visualization
* Audit log inspection
* Cryptography inspector
* Patient record explorer
* Breach simulation controls

---

# Demonstration Dataset

HYDRA uses synthetic healthcare records generated using Synthea.

Benefits:

* Realistic patient data
* No personal information
* Open-source dataset
* Suitable for security demonstrations

---

# Security Goals

HYDRA addresses:

### Single Server Compromise

No server possesses the complete key.

### Delayed Human Response

Security response is autonomous.

### Key Persistence

Old keys are destroyed immediately after ratcheting.

### Failover Spoofing

Zero-knowledge proofs validate server promotion.

### Log Tampering

Hash chaining makes modifications detectable.

---

# Future Enhancements

* Hardware security module integration
* Distributed deployment
* Byzantine fault tolerance
* Secure enclave support
* Threshold signatures
* Multi-region replication
* Post-quantum cryptography support

---

# Authors

* Amith Aravind Pai
* Arjun Mallikarjun Banappanavar
* Asad Arshadali Gove
* Hareesh Shankar Bhat

B.M.S. College of Engineering
Department of Computer Science and Engineering

---

# License

This project was developed as part of the Cryptography course project at B.M.S. College of Engineering.

For academic and educational purposes.
