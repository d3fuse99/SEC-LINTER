# SEC-LINTER ⚡
<img width="1881" height="988" alt="image" src="https://github.com/user-attachments/assets/670bf54a-7b10-412b-a133-559e1ded71b9" />


**Advanced AST-based Static Application Security Testing (SAST) engine with an interactive cyberpunk-inspired Web Console.**

SEC-LINTER is a lightweight, modular, and zero-dependency local code security scanner and pre-commit guard designed to analyze, score, and visualize code vulnerabilities in real-time. Instead of executing code, it leverages a high-fidelity Python Abstract Syntax Tree (AST) parser to dissect execution semantics, combines it with a high-performance regex signature engine to intercept leaked secrets, and presents threat vectors on an interactive, cyberpunk-inspired web dashboard featuring recursive directory uploads and dynamic tabbed file-by-file navigation.

---

## Features

* **High-Fidelity AST Parser**: Recursively dissects Python source files into syntax trees without execution, mapping node calls to identify dangerous constructs such as dynamic evaluation, unsafe shell subprocess forks, insecure deserialization (Pickle/PyYAML), vulnerable XML parsers, and weak cryptography.
* **Declarative JSON Rules Engine**: Expand the scanner's detection capabilities dynamically by adding rules to `rules.json`. Define custom AST pattern checks or regex-based API signature decoders on the fly without modifying a single line of Python backend code.
* **Heuristic Obfuscation Decoders**: Uses recursive constant folding to resolve complex AST concatenations, reversed slices (`[::-1]`), generators (`"".join(...)`), and normalized string methods (`.lower()`, `.strip()`), intercepting advanced obfuscation bypass vectors.
* **Entropy-Weighted Secret Analyzer**: Computes Shannon entropy on the fly to distinguish high-entropy cryptographic credentials (AWS, Slack, Telegram, Google API) from standard low-entropy configuration placeholders.
* **Recursive Folder Ingestion**: Ingests entire projects recursively directly from the browser using the HTML5 FileSystem API and directory reader loops, filtering out build noise and virtual environments in memory.
* **Tabbed Threat Visualization HUD**: Groups discovered vulnerabilities file-by-file, rendering an interactive horizontal navigation bar. Clean files get a green status indicator, while flagged files receive glowing, pulsating red threat counters.
* **Platform-Independent Git Hygiene Audit**: Parses and processes `.gitignore` files to verify whether high-risk project artifacts (like `.env`, logs, or private keys) are properly excluded, preventing accidental credentials leakage before pushing code.
* **Reactive Real-Time Auditing**: Initiates the security audit instantly upon dropping directories or files, or automatically triggers scans with a built-in 800ms debounce timer as soon as you stop typing in the manual console.
* **Multi-Threaded WAL Database Engine**: Leverages SQLite's Write-Ahead Logging (WAL), connection timeouts, and `auto_vacuum=FULL` disk optimization to support highly concurrent local write actions with zero file bloating.
* **Stateless Rate Limiting & Payload Limits**: Employs an IP-based sliding window rate limiter (60 req/min) and strict payload validation (10MB body / 2MB files) to prevent Denial of Service (DoS) and out-of-memory (OOM) failures.

---

## Architecture

```
[Source Files] ---> [Folder Drag & Drop / Input] ---> [Fetch API (POST)]
                                                            |
                                                            v
[Web Dashboard UI] <--- [JSON Threat Schema] <--- [server.py (CORS Router)]
                                                            |
                                      +---------------------+---------------------+
                                      |                                           |
                                      v                                           v
                              [AST Parser Engine]                        [Regex Signature Engine]
                              (ast.NodeVisitor)                          (re.compile Patterns)
```

---

## Directory Structure

```
SEC-LINTER/
│
├── server.py         # Multi-threaded HTTP server & core SAST engine
├── rules.json        # Extensible declarative JSON rules database
├── index.html        # Cyberpunk dashboard structural layout
├── style.css         # Cyberpunk dashboard visual styling & glow animations
└── script.js         # Reactive UI, directory traversal & AJAX router
```

---

## Quick Start

Start the local security server:

```bash
python server.py
```

Access the local interactive dashboard at:

```
http://localhost:5006
```
