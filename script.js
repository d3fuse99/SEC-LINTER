const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const codeInput = document.getElementById('code-input');
const auditBtn = document.getElementById('audit-btn');
const consoleLogs = document.getElementById('console-logs');

let currentFilename = 'input.py';

dropZone.addEventListener('click', () => {
    fileInput.click();
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
    }
});

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        handleFile(e.dataTransfer.files[0]);
    }
});

function handleFile(file) {
    currentFilename = file.name;
    const reader = new FileReader();
    reader.onload = (e) => {
        codeInput.value = e.target.result;
        appendSystemLog(`FILE LOADED: ${file.name}`);
    };
    reader.readAsText(file);
}

function appendSystemLog(message) {
    const div = document.createElement('div');
    div.className = 'log-entry system-log';
    div.textContent = `[SYSTEM] ${message}`;
    consoleLogs.appendChild(div);
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
}

auditBtn.addEventListener('click', async () => {
    const code = codeInput.value.trim();
    if (!code) {
        appendSystemLog('ERROR: CODE CONTAINER IS EMPTY.');
        return;
    }
    appendSystemLog('INITIATING SECURITY AUDIT...');
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                code: code,
                filename: currentFilename
            })
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
        renderThreats(data.issues);
    } catch (error) {
        appendSystemLog(`AUDIT FAILED: ${error.message}`);
    }
});

function renderThreats(issues) {
    consoleLogs.innerHTML = '';
    if (issues.length === 0) {
        appendSystemLog('AUDIT COMPLETE: NO CRITICAL THREATS DETECTED.');
        return;
    }
    appendSystemLog(`AUDIT COMPLETE: ${issues.length} ISSUES FOUND.`);
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
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
}

function getSeverityColor(severity) {
    if (severity === 'HIGH') return '#ff0055';
    if (severity === 'MEDIUM') return '#ffea00';
    return '#39ff14';
}