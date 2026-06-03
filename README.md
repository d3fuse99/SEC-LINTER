# SEC-LINTER ⚡

<img width="1882" height="985" alt="image" src="https://github.com/user-attachments/assets/a2b47105-8b1b-4244-8413-9f43b7cb7585" />


**Advanced AST-based Static Application Security Testing (SAST) engine and interactive vulnerability visualizer.**

SEC-LINTER is a lightweight, modular, and zero-dependency local code security scanner and pre-commit guard designed to analyze, score, and visualize code vulnerabilities in real-time. Instead of executing code, it leverages a high-fidelity Python Abstract Syntax Tree (AST) parser to dissect execution semantics, combines it with a high-performance regex signature engine to intercept leaked secrets, and presents threat vectors on an interactive, cyberpunk-inspired web dashboard.

---

## Features

* **High-Fidelity AST Parser**: Recursively dissects Python source files into syntax trees without execution, mapping node calls to identify dangerous constructs such as dynamic evaluation, unsafe shell subprocess forks, and weak cryptography.
* **Multi-Format Regex Engine**: Scans text files, logs, and frontend assets for high-entropy secrets—including AWS access keys, Telegram bot tokens, and raw private keys—using optimized heuristics to filter out benign placeholders.
* **Client-Side Vulnerability Detector**: Inspects JavaScript and HTML files for DOM-based Cross-Site Scripting (XSS) indicators such as unescaped innerHTML injections, dangerous document.write invocations, and hardcoded client-side credentials.
* **Interactive Cyberpunk Dashboard**: Visualizes discovered threat vectors on a responsive, dark-mode terminal HUD featuring real-time system logs, drag-and-drop file ingestion, and animated, color-coded severity cards.
* **DevSecOps Pipeline Integration**: Integrates into local Git hook workflows as a blocking pre-commit guard, exiting with non-zero codes to prevent vulnerable code from leaving the local workstation.
* **CORS-Enabled Multi-Threaded Server**: Runs on a robust, lightweight, and standard-library-only ThreadingHTTPServer, handling concurrent analysis requests in isolated system threads.

---

## Architecture

```
[Source Files] ---> [Drag & Drop Interface] ---> [Fetch API (POST)]
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

## Quick Start

Start the local security server:

```bash
python server.py
```

Access the local interactive dashboard at:

```
http://localhost:5006
```
---
## Project structure


<img width="302" height="121" alt="image" src="https://github.com/user-attachments/assets/011dfe78-503e-4205-930e-b9ddd1dbcf49" />

---
