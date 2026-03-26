// ==================== 配置 ====================
const API_BASE = 'https://myscan-henna.vercel.app';  // 修改为你的 Vercel 项目域名
const API_SCAN = `${API_BASE}/api/scan`;
const API_PROGRESS = `${API_BASE}/api/progress`;

// ==================== 国际化文本 ====================
const i18n = {
    en: {
        scanning: 'Scanning...',
        errorPrefix: 'Error: ',
        basicInfo: 'Basic Information',
        urlLabel: 'URL',
        statusLabel: 'HTTP Status',
        titleLabel: 'Page Title',
        headersLabel: 'Response Headers',
        securityHeaders: 'Missing Security Headers',
        sensitiveFiles: 'Sensitive Files Discovered',
        xss: 'XSS (Cross-Site Scripting)',
        sql: 'SQL Injection',
        threatIntel: 'Threat Intelligence (VirusTotal)',
        vulnerable: 'Vulnerable',
        notVulnerable: 'Not Vulnerable',
        parameter: 'Parameter',
        note: 'Note',
        noMissingHeaders: 'No missing security headers (good!)',
        noSensitiveFiles: 'No sensitive files found.',
        noXss: 'No reflected XSS detected.',
        noSql: 'No SQL injection detected.',
        unknown: 'Unknown',
        errorFetch: 'Failed to fetch scan results.',
        pleaseEnterUrl: 'Please enter a URL.',
        disclaimer: '⚠️ This tool is for authorized security testing only. Use responsibly.',
        export: 'Export as JSON',
        progressPending: 'Waiting to start...',
        progressRunning: 'Scanning...',
        progressCompleted: 'Scan completed!',
        progressError: 'Scan failed'
    },
    zh: {
        scanning: '扫描中...',
        errorPrefix: '错误：',
        basicInfo: '基本信息',
        urlLabel: '目标网址',
        statusLabel: 'HTTP 状态码',
        titleLabel: '页面标题',
        headersLabel: '响应头',
        securityHeaders: '缺失的安全响应头',
        sensitiveFiles: '发现的敏感文件',
        xss: '跨站脚本 (XSS)',
        sql: 'SQL 注入',
        threatIntel: '威胁情报 (VirusTotal)',
        vulnerable: '存在漏洞',
        notVulnerable: '未发现漏洞',
        parameter: '参数',
        note: '备注',
        noMissingHeaders: '未缺失重要安全头（良好）',
        noSensitiveFiles: '未发现敏感文件。',
        noXss: '未检测到反射型 XSS。',
        noSql: '未检测到 SQL 注入。',
        unknown: '未知',
        errorFetch: '获取扫描结果失败。',
        pleaseEnterUrl: '请输入网址。',
        disclaimer: '⚠️ 本工具仅供授权的安全测试使用，请合法使用。',
        export: '导出 JSON',
        progressPending: '等待开始...',
        progressRunning: '扫描中...',
        progressCompleted: '扫描完成！',
        progressError: '扫描失败'
    }
};

let currentLang = 'en';
let currentTaskId = null;
let pollInterval = null;

// DOM 元素
const targetInput = document.getElementById('target');
const scanBtn = document.getElementById('scan-btn');
const resultContainer = document.getElementById('result-container');
const errorContainer = document.getElementById('error-container');
const loadingDiv = document.getElementById('loading');
const progressContainer = document.getElementById('progress-container');
const progressFill = document.getElementById('progress-fill');
const progressMessage = document.getElementById('progress-message');
const exportContainer = document.getElementById('export-container');
const exportBtn = document.getElementById('export-btn');

const langEnBtn = document.getElementById('lang-en');
const langZhBtn = document.getElementById('lang-zh');

// ==================== 辅助函数 ====================
function t(key) {
    return i18n[currentLang][key] || key;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    });
}

function createCard(title, contentHtml, extraClass = '') {
    const card = document.createElement('div');
    card.className = `result-card ${extraClass}`;
    card.innerHTML = `
        <div class="card-header">📋 ${escapeHtml(title)}</div>
        <div class="card-body">${contentHtml}</div>
    `;
    return card;
}

// 渲染扫描结果
function renderResult(data) {
    resultContainer.innerHTML = '';
    errorContainer.style.display = 'none';

    // 1. 基础信息卡片
    const basicCard = createCard(t('basicInfo'), `
        <div class="info-row"><span class="info-label">${t('urlLabel')}:</span><span class="info-value">${escapeHtml(data.url)}</span></div>
        <div class="info-row"><span class="info-label">${t('statusLabel')}:</span><span class="info-value">${data.basic.status || '?'}</span></div>
        <div class="info-row"><span class="info-label">${t('titleLabel')}:</span><span class="info-value">${escapeHtml(data.basic.title || '')}</span></div>
        <div class="info-row"><span class="info-label">${t('headersLabel')}:</span><span class="info-value"><pre>${escapeHtml(JSON.stringify(data.basic.headers, null, 2))}</pre></span></div>
    `);

    // 2. 安全头部缺失卡片
    const missing = data.security?.missingHeaders || [];
    let securityHtml = missing.length === 0
        ? `<div class="info-value">${t('noMissingHeaders')}</div>`
        : `<div class="info-value">${missing.map(h => `<span class="badge">${escapeHtml(h)}</span>`).join('')}</div>`;
    const securityCard = createCard(t('securityHeaders'), securityHtml);

    // 3. 敏感文件卡片
    const sensitive = data.sensitiveFiles || [];
    let sensitiveHtml = sensitive.length === 0
        ? `<div class="info-value">${t('noSensitiveFiles')}</div>`
        : `<div class="info-value">${sensitive.map(f => `<span class="badge vuln-badge">${escapeHtml(f)}</span>`).join('')}</div>`;
    const sensitiveCard = createCard(t('sensitiveFiles'), sensitiveHtml);

    // 4. XSS 卡片
    let xssHtml = '';
    if (data.xss?.vulnerable) {
        xssHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.xss.param)}<br>URL: ${escapeHtml(data.xss.url)}</div>`;
    } else {
        xssHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noXss')}</div>`;
    }
    const xssCard = createCard(t('xss'), xssHtml);

    // 5. SQL 注入卡片
    let sqlHtml = '';
    if (data.sqlInjection?.vulnerable) {
        sqlHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.sqlInjection.param)}<br>URL: ${escapeHtml(data.sqlInjection.url)}${data.sqlInjection.note ? `<br>${t('note')}: ${escapeHtml(data.sqlInjection.note)}` : ''}</div>`;
    } else {
        sqlHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noSql')}</div>`;
    }
    const sqlCard = createCard(t('sql'), sqlHtml);

    // 6. 威胁情报卡片
    let threatHtml = '';
    if (data.threatIntel && !data.threatIntel.error) {
        threatHtml = `
            <div class="info-row"><span class="info-label">Malicious:</span><span class="info-value">${data.threatIntel.malicious}</span></div>
            <div class="info-row"><span class="info-label">Suspicious:</span><span class="info-value">${data.threatIntel.suspicious}</span></div>
            <div class="info-row"><span class="info-label">Harmless:</span><span class="info-value">${data.threatIntel.harmless}</span></div>
            <div class="info-row"><span class="info-label">Undetected:</span><span class="info-value">${data.threatIntel.undetected}</span></div>
        `;
    } else {
        threatHtml = `<div class="info-value">${data.threatIntel?.error || '情报不可用'}</div>`;
    }
    const threatCard = createCard(t('threatIntel'), threatHtml);

    // 7. 免责声明卡片
    const disclaimerCard = createCard('', `<div style="font-size:14px;">${t('disclaimer')}</div>`, 'disclaimer-card');
    disclaimerCard.querySelector('.card-header').innerHTML = `⚠️ ${t('disclaimer')}`;
    disclaimerCard.querySelector('.card-body').style.padding = '12px 20px';

    // 按顺序添加
    resultContainer.appendChild(basicCard);
    resultContainer.appendChild(securityCard);
    resultContainer.appendChild(sensitiveCard);
    resultContainer.appendChild(xssCard);
    resultContainer.appendChild(sqlCard);
    resultContainer.appendChild(threatCard);
    resultContainer.appendChild(disclaimerCard);

    resultContainer.style.display = 'block';
    exportContainer.style.display = 'block';
    window.lastScanData = data;
}

// 导出报告
function exportReport() {
    if (!window.lastScanData) return;
    const dataStr = JSON.stringify(window.lastScanData, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_report_${new Date().toISOString()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}
exportBtn.addEventListener('click', exportReport);

// 轮询进度
async function pollProgress(taskId) {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(async () => {
        try {
            const response = await fetch(`${API_PROGRESS}?taskId=${taskId}`);
            const data = await response.json();
            if (data.status === 'completed') {
                clearInterval(pollInterval);
                loadingDiv.style.display = 'none';
                progressContainer.style.display = 'none';
                renderResult(data.result);
            } else if (data.status === 'error') {
                clearInterval(pollInterval);
                loadingDiv.style.display = 'none';
                progressContainer.style.display = 'none';
                errorContainer.textContent = t('errorPrefix') + data.message;
                errorContainer.style.display = 'block';
            } else {
                // 更新进度条
                progressFill.style.width = `${data.progress}%`;
                let msg = data.message;
                if (data.status === 'running') msg = `${t('progressRunning')} ${msg}`;
                else if (data.status === 'pending') msg = t('progressPending');
                progressMessage.textContent = msg;
            }
        } catch (err) {
            console.error(err);
        }
    }, 1000);
}

// 扫描主函数
async function scan() {
    const url = targetInput.value.trim();
    if (!url) {
        errorContainer.textContent = t('pleaseEnterUrl');
        errorContainer.style.display = 'block';
        return;
    }

    // 重置界面
    resultContainer.innerHTML = '';
    resultContainer.style.display = 'none';
    errorContainer.style.display = 'none';
    exportContainer.style.display = 'none';
    progressContainer.style.display = 'block';
    progressFill.style.width = '0%';
    progressMessage.textContent = t('progressPending');
    loadingDiv.style.display = 'block';

    try {
        const response = await fetch(API_SCAN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unknown error');
        currentTaskId = data.taskId;
        pollProgress(currentTaskId);
    } catch (err) {
        loadingDiv.style.display = 'none';
        progressContainer.style.display = 'none';
        errorContainer.textContent = t('errorPrefix') + err.message;
        errorContainer.style.display = 'block';
    }
}

// 语言切换
function setLanguage(lang) {
    currentLang = lang;
    langEnBtn.classList.toggle('active', lang === 'en');
    langZhBtn.classList.toggle('active', lang === 'zh');
    if (window.lastScanData) renderResult(window.lastScanData);
    // 更新输入框占位符
    targetInput.placeholder = lang === 'en' ? 'https://example.com' : 'https://example.com';
    scanBtn.textContent = lang === 'en' ? 'Start Scan' : '开始扫描';
    exportBtn.textContent = t('export');
    loadingDiv.textContent = t('scanning');
    // 如果有进度显示，更新进度文本
    if (progressContainer.style.display === 'block' && progressMessage.textContent) {
        // 简单更新当前消息
        const oldMsg = progressMessage.textContent;
        if (oldMsg.includes('Scanning...') || oldMsg.includes('扫描中...')) {
            progressMessage.textContent = t('progressRunning');
        }
    }
}

// 事件绑定
scanBtn.addEventListener('click', scan);
targetInput.addEventListener('keypress', (e) => e.key === 'Enter' && scan());
langEnBtn.addEventListener('click', () => setLanguage('en'));
langZhBtn.addEventListener('click', () => setLanguage('zh'));