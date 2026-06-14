const filesInput = document.getElementById('files-input');
const folderInput = document.getElementById('folder-input');
const selectFilesBtn = document.getElementById('select-files-btn');
const selectFolderBtn = document.getElementById('select-folder-btn');
const codeInput = document.getElementById('code-input');
const consoleLogs = document.getElementById('console-logs');
const fileTabs = document.getElementById('file-tabs');

let uploadedFiles = [];
let debounceTimer;

selectFilesBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    filesInput.click();
});

selectFolderBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    folderInput.click();
});

filesInput.addEventListener('change', async (e) => {
    const files = e.target.files;
    if (files.length > 0) {
        if (files.length > 50) {
            appendSystemLog('ERROR: MAXIMUM 50 FILES ALLOWED PER SCAN.');
            return;
        }
        const fileList = [];
        const allowed = ['py', 'js', 'html', 'txt', 'json', 'env', 'yml', 'yaml', 'conf', 'ini', 'gitignore'];
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            if (file.size > 2 * 1024 * 1024) {
                appendSystemLog(`SKIPPED: [${file.name}] - FILE EXCEEDS 2MB LIMIT.`);
                continue;
            }
            const ext = file.name.split('.').pop().toLowerCase();
            const isGitIgnore = file.name === '.gitignore';
            if (allowed.includes(ext) || isGitIgnore) {
                const text = await file.text();
                fileList.push({ filename: file.name, code: text });
            }
        }
        if (fileList.length > 0) {
            uploadedFiles = fileList;
            codeInput.value = '';
            appendSystemLog(`LOADED ${fileList.length} FILE(S).`);
            triggerAudit();
        } else {
            appendSystemLog('NO COMPATIBLE FILES FOUND.');
        }
    }
});

folderInput.addEventListener('change', async (e) => {
    const files = e.target.files;
    if (files.length > 0) {
        if (files.length > 50) {
            appendSystemLog('ERROR: MAXIMUM 50 FILES ALLOWED PER SCAN.');
            return;
        }
        const fileList = [];
        const allowed = ['py', 'js', 'html', 'txt', 'json', 'env', 'yml', 'yaml', 'conf', 'ini', 'gitignore'];
        const ignored = ['.git', 'node_modules', 'venv', 'env', '__pycache__', '.idea', '.vscode'];
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            if (file.size > 2 * 1024 * 1024) {
                appendSystemLog(`SKIPPED: [${file.name}] - FILE EXCEEDS 2MB LIMIT.`);
                continue;
            }
            const relativePath = file.webkitRelativePath || file.name;
            const pathParts = relativePath.split('/');
            const isIgnored = pathParts.some(part => ignored.includes(part));
            if (isIgnored) continue;
            const ext = file.name.split('.').pop().toLowerCase();
            const isGitIgnore = file.name === '.gitignore';
            if (allowed.includes(ext) || isGitIgnore) {
                const text = await file.text();
                fileList.push({ filename: relativePath, code: text });
            }
        }
        if (fileList.length > 0) {
            uploadedFiles = fileList;
            codeInput.value = '';
            appendSystemLog(`LOADED ${fileList.length} FILES FROM DIRECTORY.`);
            triggerAudit();
        } else {
            appendSystemLog('NO COMPATIBLE FILES FOUND.');
        }
    }
});

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const items = e.dataTransfer.items;
    const fileList = [];
    appendSystemLog('SCANNING DROPPED ITEMS...');
    for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.kind === 'file') {
            const entry = item.webkitGetAsEntry();
            if (entry) {
                await traverseDirectory(entry, fileList);
            }
        }
    }
    if (fileList.length > 0) {
        if (fileList.length > 50) {
            appendSystemLog('ERROR: MAXIMUM 50 FILES ALLOWED PER SCAN.');
            return;
        }
        uploadedFiles = fileList;
        codeInput.value = '';
        appendSystemLog(`LOADED ${fileList.length} FILES RECURSIVELY.`);
        triggerAudit();
    } else {
        appendSystemLog('NO COMPATIBLE FILES DETECTED.');
    }
});

async function traverseDirectory(entry, fileList) {
    if (entry.isFile) {
        const file = await new Promise((resolve) => entry.file(resolve));
        if (file.size > 2 * 1024 * 1024) {
            appendSystemLog(`SKIPPED: [${file.name}] - FILE EXCEEDS 2MB LIMIT.`);
            return;
        }
        const ext = file.name.split('.').pop().toLowerCase();
        const isGitIgnore = file.name === '.gitignore';
        const allowed = ['py', 'js', 'html', 'txt', 'json', 'env', 'yml', 'yaml', 'conf', 'ini', 'gitignore'];
        if (allowed.includes(ext) || isGitIgnore) {
            const text = await file.text();
            fileList.push({ filename: entry.fullPath.substring(1), code: text });
        }
    } else if (entry.isDirectory) {
        const ignored = ['.git', 'node_modules', 'venv', 'env', '__pycache__', '.idea', '.vscode'];
        if (ignored.includes(entry.name)) return;
        const reader = entry.createReader();
        const entries = await new Promise((resolve) => {
            reader.readEntries(resolve);
        });
        for (const childEntry of entries) {
            await traverseDirectory(childEntry, fileList);
        }
    }
}

function appendSystemLog(message) {
    const div = document.createElement('div');
    div.className = 'log-entry system-log';
    div.textContent = `[SYSTEM] ${message}`;
    consoleLogs.appendChild(div);
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
}

codeInput.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
        uploadedFiles = [];
        triggerAudit();
    }, 800);
});

async function triggerAudit() {
    const code = codeInput.value.trim();
    if (uploadedFiles.length === 0 && !code) {
        return;
    }
    const dropText = document.querySelector('.drop-zone-text');
    const originalText = dropText.textContent;
    dropText.textContent = '[ SYSTEM SCANNING... ]';
    dropText.style.color = '#ff007f';
    dropText.style.animation = 'pulseGlow 1s infinite alternate';
    appendSystemLog('INITIATING AUTO AUDIT...');
    let payload = {};
    if (uploadedFiles.length > 0) {
        payload = { files: uploadedFiles };
    } else {
        payload = {
            code: code,
            filename: 'input.py'
        };
    }
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        if (!response.ok) {
            let errorMsg = 'SERVER RESPONDED WITH AN ERROR';
            try {
                const errData = await response.json();
                if (errData.error) {
                    errorMsg = errData.error;
                }
            } catch (e) {}
            throw new Error(errorMsg);
        }
        const data = await response.json();
        processAuditResults(data.issues);
    } catch (error) {
        fileTabs.textContent = '';
        fileTabs.style.display = 'none';
        consoleLogs.textContent = '';
        appendSystemLog(`AUDIT FAILED: ${error.message}`);
        const div = document.createElement('div');
        div.className = 'log-entry system-log';
        div.style.color = '#ff0055';
        div.textContent = `[FATAL ERROR] Audit process stopped. ${error.message}. Please resolve the server side issue or scale down the payload size.`;
        consoleLogs.appendChild(div);
    } finally {
        dropText.textContent = originalText;
        dropText.style.color = '#00f0ff';
        dropText.style.animation = 'none';
    }
}

function processAuditResults(issues) {
    fileTabs.textContent = '';
    consoleLogs.textContent = '';
    const scannedFiles = uploadedFiles.length > 0 ? uploadedFiles.map(f => f.filename) : ['input.py'];
    const fileIssues = {};
    scannedFiles.forEach(f => {
        fileIssues[f] = [];
    });
    issues.forEach(issue => {
        const matchingFile = scannedFiles.find(f => f === issue.file || issue.file.endsWith(f));
        if (matchingFile) {
            fileIssues[matchingFile].push(issue);
        } else {
            if (!fileIssues[issue.file]) {
                fileIssues[issue.file] = [];
            }
            fileIssues[issue.file].push(issue);
            if (!scannedFiles.includes(issue.file)) {
                scannedFiles.push(issue.file);
            }
        }
    });
    if (scannedFiles.length <= 1) {
        fileTabs.style.display = 'none';
        renderThreatsForFile(scannedFiles[0], fileIssues[scannedFiles[0]] || []);
        return;
    }
    fileTabs.style.display = 'flex';
    let firstActiveFile = scannedFiles[0];
    for (const file of scannedFiles) {
        if (fileIssues[file] && fileIssues[file].length > 0) {
            firstActiveFile = file;
            break;
        }
    }
    scannedFiles.forEach(file => {
        const btn = document.createElement('button');
        btn.className = 'tab-btn';
        if (file === firstActiveFile) btn.classList.add('active');
        const displayName = file.split('/').pop();
        btn.title = file;
        const nameSpan = document.createElement('span');
        nameSpan.textContent = displayName;
        const badge = document.createElement('span');
        const count = (fileIssues[file] || []).length;
        badge.className = `tab-badge ${count === 0 ? 'clean' : 'dirty'}`;
        badge.textContent = count;
        btn.appendChild(nameSpan);
        btn.appendChild(badge);
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderThreatsForFile(file, fileIssues[file]);
        });
        fileTabs.appendChild(btn);
    });
    renderThreatsForFile(firstActiveFile, fileIssues[firstActiveFile] || []);
}

function renderThreatsForFile(file, issues) {
    consoleLogs.textContent = '';
    appendSystemLog(`DISPLAYING AUDIT LOGS FOR: [ ${file} ]`);
    if (issues.length === 0) {
        const div = document.createElement('div');
        div.className = 'log-entry system-log';
        div.textContent = `[SUCCESS] FILE IS CLEAN. NO SECURITY THREATS DETECTED IN THIS PATH.`;
        consoleLogs.appendChild(div);
        return;
    }
    issues.forEach((issue) => {
        const card = document.createElement('div');
        card.className = `threat-card ${issue.severity}`;
        const header = document.createElement('div');
        header.className = 'threat-header';
        const severitySpan = document.createElement('span');
        severitySpan.textContent = issue.severity;
        severitySpan.style.color = getSeverityColor(issue.severity);
        const classSpan = document.createElement('span');
        classSpan.className = 'threat-class';
        classSpan.textContent = issue.class;
        header.appendChild(classSpan);
        header.appendChild(severitySpan);
        const meta = document.createElement('div');
        meta.className = 'threat-meta';
        meta.textContent = `Location: ${issue.file} (Line ${issue.line})`;
        const remediation = document.createElement('div');
        remediation.className = 'threat-remediation';
        remediation.textContent = `REMEDIATION: ${issue.remediation}`;
        card.appendChild(header);
        card.appendChild(meta);
        card.appendChild(remediation);
        consoleLogs.appendChild(card);
    });
    consoleLogs.scrollTop = 0;
}

function getSeverityColor(severity) {
    if (severity === 'HIGH') return '#ff0055';
    if (severity === 'MEDIUM') return '#ffea00';
    return '#39ff14';
}