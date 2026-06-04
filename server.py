import sys
import os
import json
import ast
import re
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def get_const_value(node):
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Str):
        return node.s
    elif isinstance(node, ast.Num):
        return node.n
    elif isinstance(node, ast.NameConstant):
        return node.value
    return None

def load_rules():
    rules_path = 'rules.json'
    if os.path.exists(rules_path):
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {'ast_call_rules': [], 'regex_rules': []}

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename, call_rules):
        self.filename = filename
        self.call_rules = call_rules
        self.issues = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in ('eval', 'exec'):
                self.issues.append({
                    'file': self.filename,
                    'line': node.lineno,
                    'class': 'Unsafe Function Evaluation',
                    'severity': 'HIGH',
                    'remediation': f"Avoid using {node.func.id}(). Use safer alternatives like json.loads() or ast.literal_eval()."
                })
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                val_id = node.func.value.id
                if val_id == 'subprocess' and node.func.attr in ('run', 'Popen', 'call', 'check_output', 'check_call'):
                    for kw in node.keywords:
                        if kw.arg == 'shell':
                            val = get_const_value(kw.value)
                            if val is True:
                                self.issues.append({
                                    'file': self.filename,
                                    'line': node.lineno,
                                    'class': 'Insecure Subprocess Execution',
                                    'severity': 'HIGH',
                                    'remediation': "Set shell=False and pass arguments as a list to prevent command injection."
                                })
                elif val_id == 'os' and node.func.attr in ('system', 'popen'):
                    self.issues.append({
                        'file': self.filename,
                        'line': node.lineno,
                        'class': 'Insecure Subprocess Execution',
                        'severity': 'HIGH',
                        'remediation': "Avoid os.system() and os.popen(). Use subprocess.run() with shell=False."
                    })
                elif val_id == 'hashlib':
                    if node.func.attr in ('md5', 'sha1'):
                        self.issues.append({
                            'file': self.filename,
                            'line': node.lineno,
                            'class': 'Weak Cryptographic Hash',
                            'severity': 'MEDIUM',
                            'remediation': f"Avoid using hashlib.{node.func.attr}(). Use hashlib.sha256() or stronger."
                        })
                    elif node.func.attr == 'new':
                        if node.args:
                            val = get_const_value(node.args[0])
                            if isinstance(val, str) and val.lower() in ('md5', 'sha1'):
                                self.issues.append({
                                    'file': self.filename,
                                    'line': node.lineno,
                                    'class': 'Weak Cryptographic Hash',
                                    'severity': 'MEDIUM',
                                    'remediation': f"Avoid using weak hash '{val}'. Use sha256 or stronger."
                                })
                elif val_id == 'pickle' and node.func.attr in ('load', 'loads'):
                    self.issues.append({
                        'file': self.filename,
                        'line': node.lineno,
                        'class': 'Insecure Deserialization (Pickle)',
                        'severity': 'HIGH',
                        'remediation': "Avoid using pickle for untrusted data. Use safer serialization like json."
                    })
                elif val_id == 'yaml' and node.func.attr == 'unsafe_load':
                    self.issues.append({
                        'file': self.filename,
                        'line': node.lineno,
                        'class': 'Insecure Deserialization (PyYAML)',
                        'severity': 'HIGH',
                        'remediation': "Avoid yaml.unsafe_load(). Use yaml.safe_load() instead."
                    })
                elif val_id == 'random' and node.func.attr in ('randint', 'choice', 'randrange', 'random', 'uniform'):
                    self.issues.append({
                        'file': self.filename,
                        'line': node.lineno,
                        'class': 'Weak Pseudo-Random Number Generator',
                        'severity': 'LOW',
                        'remediation': "Do not use standard random module for security-sensitive purposes. Use secrets module instead."
                    })
            if node.func.attr in ('parse', 'fromstring'):
                module_path = []
                curr = node.func.value
                while isinstance(curr, ast.Attribute):
                    module_path.append(curr.attr)
                    curr = curr.value
                if isinstance(curr, ast.Name):
                    module_path.append(curr.id)
                module_path.reverse()
                module_str = '.'.join(module_path)
                if 'xml' in module_str:
                    self.issues.append({
                        'file': self.filename,
                        'line': node.lineno,
                        'class': 'Insecure XML Parser (Potential XXE)',
                        'severity': 'MEDIUM',
                        'remediation': "Standard xml module is vulnerable to XML External Entity (XXE) attacks. Use defusedxml package."
                    })
        if isinstance(node.func, ast.Attribute) and node.func.attr in ('execute', 'raw'):
            if node.args:
                first_arg = node.args[0]
                is_unsafe = False
                if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                    is_unsafe = True
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == 'format':
                    is_unsafe = True
                if is_unsafe:
                    self.issues.append({
                        'file': self.filename,
                        'line': node.lineno,
                        'class': 'Potential SQL Injection',
                        'severity': 'HIGH',
                        'remediation': "Do not use string formatting or f-strings for SQL queries. Use parameterized queries."
                    })
        for rule in self.call_rules:
            names = rule.get('names', [])
            module_owner = rule.get('module_owner', None)
            if isinstance(node.func, ast.Name):
                if not module_owner and node.func.id in names:
                    self.issues.append({
                        'file': self.filename,
                        'line': node.lineno,
                        'class': rule.get('class', 'Security Flaw'),
                        'severity': rule.get('severity', 'MEDIUM'),
                        'remediation': rule.get('remediation', '')
                    })
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    val_id = node.func.value.id
                    if module_owner and val_id == module_owner and node.func.attr in names:
                        self.issues.append({
                            'file': self.filename,
                            'line': node.lineno,
                            'class': rule.get('class', 'Security Flaw'),
                            'severity': rule.get('severity', 'MEDIUM'),
                            'remediation': rule.get('remediation', '')
                        })
                    elif not module_owner and node.func.attr in names:
                        self.issues.append({
                            'file': self.filename,
                            'line': node.lineno,
                            'class': rule.get('class', 'Security Flaw'),
                            'severity': rule.get('severity', 'MEDIUM'),
                            'remediation': rule.get('remediation', '')
                        })
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module == 'hashlib':
            for alias in node.names:
                if alias.name in ('md5', 'sha1'):
                    self.issues.append({
                        'file': self.filename,
                        'line': node.lineno,
                        'class': 'Weak Cryptographic Hash Import',
                        'severity': 'MEDIUM',
                        'remediation': f"Avoid importing {alias.name} from hashlib. Use sha256 instead."
                    })
        self.generic_visit(node)

def scan_regex_string(code_str, filename, regex_rules):
    issues = []
    lines = code_str.splitlines()
    is_js_or_html = filename.endswith(('.js', '.html'))

    aws_rx = re.compile(r"AKIA[0-9A-Z]{16}")
    tg_rx = re.compile(r"[0-9]{9,10}:[a-zA-Z0-9_-]{35}")
    pk_rx = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
    slack_rx = re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9_]{8}/B[A-Z0-9_]{8}/[A-Za-z0-9_]{24}")
    google_rx = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
    secret_rx = re.compile(r"(?i)(?:key|secret|token|password|passwd|auth|api_key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-+]{16,})['\"]")

    inner_html_rx = re.compile(r"\.innerHTML\s*=")
    doc_write_rx = re.compile(r"document\.write\s*\(")
    js_eval_rx = re.compile(r"\beval\s*\(")
    open_redirect_rx = re.compile(r"location\.(?:href|hash)\s*=\s*(?!['\"])")
    frontend_secret_rx = re.compile(r"(?i)(?:const|let|var)\s+([a-zA-Z0-9_-]*(?:secret|key|token|passwd|password)[a-zA-Z0-9_-]*)\s*=\s*['\"]([a-zA-Z0-9_\-+]{8,})['\"]")

    for idx, line in enumerate(lines, 1):
        line_str = line.strip()
        if aws_rx.search(line_str):
            issues.append({
                'file': filename,
                'line': idx,
                'class': 'Leaked AWS Access Key',
                'severity': 'HIGH',
                'remediation': 'Revoke the AWS access key immediately and move it to an environment variable or secrets manager.'
            })
        if tg_rx.search(line_str):
            issues.append({
                'file': filename,
                'line': idx,
                'class': 'Leaked Telegram Bot Token',
                'severity': 'HIGH',
                'remediation': 'Revoke the Telegram bot token and store it securely.'
            })
        if pk_rx.search(line_str):
            issues.append({
                'file': filename,
                'line': idx,
                'class': 'Leaked Private Key Block',
                'severity': 'HIGH',
                'remediation': 'Remove the private key from source control and revoke it immediately.'
            })
        if slack_rx.search(line_str):
            issues.append({
                'file': filename,
                'line': idx,
                'class': 'Leaked Slack Webhook URL',
                'severity': 'HIGH',
                'remediation': 'Revoke the Slack Webhook immediately and move it to an environment variable.'
            })
        if google_rx.search(line_str):
            issues.append({
                'file': filename,
                'line': idx,
                'class': 'Leaked Google API Key',
                'severity': 'HIGH',
                'remediation': 'Revoke or restrict the Google API key immediately in the GCP console.'
            })
        m = secret_rx.search(line_str)
        if m:
            val = m.group(1)
            if not any(x in val.lower() for x in ('placeholder', 'your_', 'template', 'dummy', 'test_key', 'example')):
                issues.append({
                    'file': filename,
                    'line': idx,
                    'class': 'Potential Hardcoded Secret',
                    'severity': 'HIGH',
                    'remediation': 'Remove hardcoded credential. Use environment variables or a secure vault.'
                })
        for rule in regex_rules:
            extensions = rule.get('file_extensions', None)
            if extensions:
                matched_ext = False
                for ext in extensions:
                    if filename.endswith(ext):
                        matched_ext = True
                        break
                if not matched_ext:
                    continue
            pattern_str = rule.get('pattern', '')
            if not pattern_str:
                continue
            rx = re.compile(pattern_str)
            if rx.search(line_str):
                issues.append({
                    'file': filename,
                    'line': idx,
                    'class': rule.get('class', 'Potential Secret Leak'),
                    'severity': rule.get('severity', 'HIGH'),
                    'remediation': rule.get('remediation', '')
                })
        if is_js_or_html:
            if inner_html_rx.search(line_str):
                issues.append({
                    'file': filename,
                    'line': idx,
                    'class': 'Unsanitized HTML Injection (innerHTML)',
                    'severity': 'MEDIUM',
                    'remediation': 'Replace innerHTML with textContent or use a safe sanitization library.'
                })
            if doc_write_rx.search(line_str):
                issues.append({
                    'file': filename,
                    'line': idx,
                    'class': 'Dangerous Document Write Usage',
                    'severity': 'HIGH',
                    'remediation': 'Avoid using document.write() as it is highly vulnerable to XSS and blocks page rendering.'
                })
            if js_eval_rx.search(line_str):
                issues.append({
                    'file': filename,
                    'line': idx,
                    'class': 'Client-Side Eval Execution',
                    'severity': 'HIGH',
                    'remediation': 'Never use eval() in client-side JavaScript. Parse structured data using JSON.parse().'
                })
            if open_redirect_rx.search(line_str):
                issues.append({
                    'file': filename,
                    'line': idx,
                    'class': 'Potential DOM-based Open Redirect',
                    'severity': 'MEDIUM',
                    'remediation': 'Avoid assigning dynamic untrusted values to location.href. Sanitize or validate input.'
                })
            m_fe = frontend_secret_rx.search(line_str)
            if m_fe:
                val = m_fe.group(2)
                if not any(x in val.lower() for x in ('placeholder', 'your_', 'template', 'dummy', 'test_key', 'example')):
                    issues.append({
                        'file': filename,
                        'line': idx,
                        'class': 'Frontend Hardcoded Credential',
                        'severity': 'HIGH',
                        'remediation': 'Do not store sensitive credentials in client-side code. Use a secure backend proxy.'
                    })
    return issues

class ScannerHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            self.serve_file('index.html', 'text/html')
        elif self.path == '/style.css':
            self.serve_file('style.css', 'text/css')
        elif self.path == '/script.js':
            self.serve_file('script.js', 'application/javascript')
        else:
            self.send_response(404)
            self.end_headers()

    def serve_file(self, filename, content_type):
        if os.path.exists(filename):
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.end_headers()
            with open(filename, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/analyze':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode('utf-8'))
                
                files_list = payload.get('files', [])
                if not files_list:
                    code = payload.get('code', '')
                    filename = payload.get('filename', 'input.py')
                    files_list = [{'filename': filename, 'code': code}]
                
                rules = load_rules()
                all_issues = []
                gitignore_content = ""
                for file_entry in files_list:
                    if os.path.basename(file_entry.get('filename', '')) == '.gitignore':
                        gitignore_content = file_entry.get('code', '')
                        break

                ignore_patterns = []
                if gitignore_content:
                    for line in gitignore_content.splitlines():
                        p = line.strip()
                        if p and not p.startswith(chr(35)):
                            ignore_patterns.append(p)

                high_risk_files = ('.env', 'secrets.json', 'debug.log')
                for file_entry in files_list:
                    filename = file_entry.get('filename', '')
                    basename = os.path.basename(filename)
                    if basename in high_risk_files or filename.endswith(('.pem', '.key')):
                        ignored = False
                        for pattern in ignore_patterns:
                            if pattern == basename or pattern == filename:
                                ignored = True
                                break
                            if pattern.startswith('*') and filename.endswith(pattern[1:]):
                                ignored = True
                                break
                            if pattern.endswith('*') and filename.startswith(pattern[:-1]):
                                ignored = True
                                break
                            if pattern in filename:
                                ignored = True
                                break
                        if not ignored:
                            all_issues.append({
                                'file': filename,
                                'line': 'N/A',
                                'class': 'Untracked Sensitive File (.gitignore exclusion missing)',
                                'severity': 'HIGH',
                                'remediation': f"Add '{basename}' or its pattern to your local .gitignore file to avoid committing secrets."
                            })

                for file_entry in files_list:
                    code = file_entry.get('code', '')
                    filename = file_entry.get('filename', 'input.py')
                    if filename.endswith('.py'):
                        try:
                            tree = ast.parse(code, filename=filename)
                            visitor = SecurityVisitor(filename, rules.get('ast_call_rules', []))
                            visitor.visit(tree)
                            all_issues.extend(visitor.issues)
                        except Exception as e:
                            all_issues.append({
                                'file': filename,
                                'line': 1,
                                'class': 'Syntax Error / Parse Failure',
                                'severity': 'LOW',
                                'remediation': f"Check syntax: {str(e)}"
                            })
                    all_issues.extend(scan_regex_string(code, filename, rules.get('regex_rules', [])))
                
                response_data = json.dumps({'issues': all_issues})
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(response_data.encode('utf-8'))
            except Exception as e:
                traceback.print_exc()
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                error_info = f"{type(e).__name__}: {str(e)}"
                self.wfile.write(json.dumps({'error': error_info}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def main():
    port = 5006
    server = ThreadingHTTPServer(('0.0.0.0', port), ScannerHandler)
    print(f"Server running at http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()