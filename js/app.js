// ==================== 配置 ====================
const API_BASE = 'https://neteye.vercel.app'; // 已更新为您的域名

// 模块定义（合并 basic 模块，其他保持不变）
const FREE_MODULES = [
    { key: 'basic', endpoint: '/api/scan/basic', resultKey: 'basic', transform: (data) => data.basic }
];

const PAID_MODULES = [
    ...FREE_MODULES,
    { key: 'sensitive', endpoint: '/api/scan/sensitive-files', resultKey: 'sensitiveFiles', transform: (data) => data },
    { key: 'xss', endpoint: '/api/scan/xss', resultKey: 'xss', transform: (data) => data },
    { key: 'sql', endpoint: '/api/scan/sql', resultKey: 'sqlInjection', transform: (data) => data },
    { key: 'dir', endpoint: '/api/scan/dir-traversal', resultKey: 'directoryTraversal', transform: (data) => data },
    { key: 'http', endpoint: '/api/scan/http-methods', resultKey: 'httpMethods.allowed', transform: (data) => ({ allowed: data }) },
    { key: 'info', endpoint: '/api/scan/info-leakage', resultKey: 'infoLeakage', transform: (data) => data },
    { key: 'cors', endpoint: '/api/scan/cors', resultKey: 'cors', transform: (data) => data },
    { key: 'cms', endpoint: '/api/scan/cms', resultKey: 'cms', transform: (data) => data },
    { key: 'ssrf', endpoint: '/api/scan/ssrf', resultKey: 'ssrf', transform: (data) => data }
];

// ==================== 国际化文本库（新增法律免责和关于NetEye文本） ====================
const i18n = {
    en: {
        scanning: 'Scanning...',
        errorPrefix: 'Error: ',
        invalidUrl: 'Please enter a valid URL (e.g., https://example.com)',
        basicInfo: 'Basic Information',
        urlLabel: 'URL',
        statusLabel: 'HTTP Status',
        titleLabel: 'Page Title',
        headersLabel: 'Response Headers',
        securityHeaders: 'Missing Security Headers',
        sensitiveFiles: 'Sensitive Files Discovered',
        xss: 'XSS (Cross-Site Scripting)',
        sql: 'SQL Injection',
        directoryTraversal: 'Directory Traversal',
        httpMethods: 'HTTP Methods',
        infoLeakage: 'Information Leakage',
        csp: 'CSP Analysis',
        cors: 'CORS Configuration',
        cms: 'CMS Fingerprint',
        ssl: 'SSL/TLS Configuration',
        ssrf: 'SSRF (Server-Side Request Forgery)',
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
        responseNotJson: 'Server returned non-JSON response: ',
        remediationTitle: 'Remediation',
        copy: 'Copy',
        copied: 'Copied!',
        scanTime: 'Scan completed in {time}s',
        foundSensitive: 'Sensitive information found',
        noSensitiveInfo: 'No obvious information leakage',
        dangerousMethods: 'Dangerous methods allowed',
        noDangerousMethods: 'No dangerous HTTP methods found',
        dirTraversalNone: 'No directory traversal detected.',
        pdfExport: 'Export as PDF',
        htmlExport: 'Export as HTML',
        infoButton: 'Info',
        close: 'Close',
        detailedTitle: 'Detailed Information',
        corsSafe: 'CORS policy is restrictive (good).',
        cmsUnknown: 'Unable to detect CMS.',
        quickScan: 'Quick Scan',
        deepScan: 'Deep Scan',
        upgradeFreeNotice: 'Deep scan is currently free, but will become a paid feature in the future.',
        phaseBasic: 'Fetching basic info...',
        phaseSecurity: 'Checking security headers...',
        phaseSensitive: 'Scanning sensitive files...',
        phaseXss: 'Testing XSS...',
        phaseSql: 'Testing SQL injection...',
        phaseDir: 'Testing directory traversal...',
        phaseHttp: 'Checking HTTP methods...',
        phaseInfo: 'Analyzing information leakage...',
        phaseCors: 'Checking CORS...',
        phaseCms: 'Detecting CMS...',
        phaseSsl: 'Analyzing SSL/TLS...',
        phaseSsrf: 'Testing SSRF...',
        phaseComplete: 'Complete!',
        collapse: 'Collapse',
        expand: 'Expand',
        legalNoticeTitle: 'Legal Disclaimer',
        legalNoticeText: '⚠️ This tool is for authorized security testing only. Unauthorized scanning is prohibited. By using this tool, you agree that you have explicit permission to test the target. Any illegal use is strictly forbidden. Users are responsible for complying with all applicable laws and regulations.',
        aboutTitle: 'About NetEye',
        aboutText: [
            'NetEye is a professional web vulnerability scanner designed for security researchers, developers, and IT professionals. It helps you identify common security flaws in your own websites or authorized targets.',
            '⚠️ Responsible Use: Always ensure you have explicit permission before scanning any website. Use this tool for educational purposes, internal security testing, and improving your own systems.',
            '🔍 Learning Resource: NetEye provides detailed remediation suggestions for each detected vulnerability, helping you understand the attack principle and how to fix it.',
            '🛡️ Compliance: NetEye does not store any scan results permanently. All data is processed in real-time and never shared with third parties.'
        ],
        firstTimeDisclaimer: 'By using NetEye, you confirm that you have obtained explicit authorization to scan the target website. Unauthorized scanning may be illegal. Do you agree?',
        remediation: {
            // ... 原有修复建议内容保持不变 ...
        },
        detailed: {
            // ... 原有详细解说内容保持不变 ...
        },
        detailedLabels: {
            principle: 'Attack Principle',
            scenario: 'Attack Scenario',
            remediation: 'Remediation'
        }
    },
    zh: {
        scanning: '扫描中...',
        errorPrefix: '错误：',
        invalidUrl: '请输入有效的网址（例如 https://example.com）',
        basicInfo: '基本信息',
        urlLabel: '目标网址',
        statusLabel: 'HTTP 状态码',
        titleLabel: '页面标题',
        headersLabel: '响应头',
        securityHeaders: '缺失的安全响应头',
        sensitiveFiles: '发现的敏感文件',
        xss: '跨站脚本 (XSS)',
        sql: 'SQL 注入',
        directoryTraversal: '目录遍历',
        httpMethods: 'HTTP 方法',
        infoLeakage: '信息泄露',
        csp: 'CSP 策略分析',
        cors: 'CORS 配置',
        cms: 'CMS 指纹',
        ssl: 'SSL/TLS 配置',
        ssrf: 'SSRF (服务端请求伪造)',
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
        responseNotJson: '服务器返回了非 JSON 数据：',
        remediationTitle: '修复建议',
        copy: '复制',
        copied: '已复制！',
        scanTime: '扫描完成，耗时 {time} 秒',
        foundSensitive: '发现敏感信息',
        noSensitiveInfo: '未发现明显信息泄露',
        dangerousMethods: '允许的危险方法',
        noDangerousMethods: '未发现危险 HTTP 方法',
        dirTraversalNone: '未检测到目录遍历漏洞。',
        pdfExport: '导出 PDF',
        htmlExport: '导出 HTML',
        infoButton: '详解',
        close: '关闭',
        detailedTitle: '详细说明',
        corsSafe: 'CORS 策略严格（良好）。',
        cmsUnknown: '无法识别 CMS。',
        quickScan: '快速扫描',
        deepScan: '深度扫描',
        upgradeFreeNotice: '深度扫描目前免费开放，未来将转为付费功能。',
        phaseBasic: '获取基础信息...',
        phaseSecurity: '检测安全头...',
        phaseSensitive: '扫描敏感文件...',
        phaseXss: '测试 XSS...',
        phaseSql: '测试 SQL 注入...',
        phaseDir: '测试目录遍历...',
        phaseHttp: '检查 HTTP 方法...',
        phaseInfo: '分析信息泄露...',
        phaseCors: '检查 CORS...',
        phaseCms: '识别 CMS...',
        phaseSsl: '分析 SSL/TLS...',
        phaseSsrf: '测试 SSRF...',
        phaseComplete: '完成！',
        collapse: '折叠',
        expand: '展开',
        legalNoticeTitle: '法律免责声明',
        legalNoticeText: '⚠️ 本工具仅供授权的安全测试使用。未经授权扫描他人网站属违法行为。使用本工具即表示您已获得目标网站的明确授权。任何非法使用将被严格禁止。用户需自行遵守所有适用法律法规。',
        aboutTitle: '关于 NetEye',
        aboutText: [
            'NetEye 是一款专业的网页漏洞扫描器，专为安全研究人员、开发者和 IT 专业人士设计。帮助您识别自己网站或授权目标中的常见安全漏洞。',
            '⚠️ 负责任使用：扫描任何网站前，请务必获得明确授权。本工具仅用于教育目的、内部安全测试和改善自身系统。',
            '🔍 学习资源：NetEye 为每个检测到的漏洞提供详细的修复建议，帮助您理解攻击原理及修复方法。',
            '🛡️ 合规性：NetEye 不永久存储任何扫描结果。所有数据实时处理，绝不与第三方共享。'
        ],
        firstTimeDisclaimer: '使用 NetEye 即表示您确认已获得扫描目标网站的明确授权。未经授权的扫描可能违法。您是否同意？',
        remediation: {
            // ... 原有修复建议内容保持不变 ...
        },
        detailed: {
            // ... 原有详细解说内容保持不变 ...
        },
        detailedLabels: {
            principle: '攻击原理',
            scenario: '攻击场景',
            remediation: '修复建议'
        }
    }
};

let currentLang = 'en';
let scanStartTime = null;
let currentTheme = 'light';
let phaseInterval = null;

// DOM 元素引用
let targetInput, scanBtn, resultContainer, errorContainer, loadingDiv, exportContainer;
let langEnBtn, langZhBtn, themeToggle, scanTimeDiv, progressContainer, progressFill, progressMessage;
let exportMenuBtn, exportModal, exportJsonBtn, exportPdfBtn, exportHtmlBtn;
let emailReportBtn, emailModal, emailClose, emailCancel, emailSend, emailInput, emailError;
let noticeTitle, noticeText, noticeCollapseBtn, noticeContent;
let aboutCollapseBtn, aboutContent;

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

function createCard(title, contentHtml, extraClass = '', vulnerabilityType = null, defaultCollapsed = false) {
    const card = document.createElement('div');
    card.className = `result-card ${extraClass}`;
    const copyBtnHtml = `<button class="copy-btn" data-copy="${escapeHtml(contentHtml).replace(/"/g, '&quot;')}">${t('copy')}</button>`;
    const infoBtnHtml = vulnerabilityType ? `<button class="info-btn" data-type="${vulnerabilityType}" data-title="${escapeHtml(title)}">${t('infoButton')}</button>` : '';
    const collapseIcon = defaultCollapsed ? '▶' : '▼';
    card.innerHTML = `
        <div class="card-header">
            <span><span class="collapse-icon">${collapseIcon}</span> 📋 ${escapeHtml(title)}</span>
            <div class="card-actions">
                ${infoBtnHtml}
                ${copyBtnHtml}
            </div>
        </div>
        <div class="card-body ${defaultCollapsed ? 'collapsed' : ''}">${contentHtml}</div>
    `;
    const header = card.querySelector('.card-header');
    const body = card.querySelector('.card-body');
    const icon = header.querySelector('.collapse-icon');
    header.addEventListener('click', (e) => {
        if (e.target.classList.contains('copy-btn') || e.target.classList.contains('info-btn')) return;
        const isCollapsed = body.classList.toggle('collapsed');
        icon.textContent = isCollapsed ? '▶' : '▼';
    });
    const copyBtn = card.querySelector('.copy-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const textToCopy = copyBtn.dataset.copy.replace(/<br>/g, '\n').replace(/<[^>]*>/g, '');
            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalText = copyBtn.textContent;
                copyBtn.textContent = t('copied');
                setTimeout(() => copyBtn.textContent = originalText, 1500);
            });
        });
    }
    const infoBtn = card.querySelector('.info-btn');
    if (infoBtn) {
        infoBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const type = infoBtn.dataset.type;
            const cardTitle = infoBtn.dataset.title;
            showDetailedInfo(type, cardTitle);
        });
    }
    return card;
}

function showDetailedInfo(vulnerabilityType, title) {
    const details = i18n[currentLang].detailed?.[vulnerabilityType];
    if (!details) {
        console.warn('No detailed info for', vulnerabilityType);
        return;
    }
    const labels = i18n[currentLang].detailedLabels || {
        principle: 'Attack Principle',
        scenario: 'Attack Scenario',
        remediation: 'Remediation'
    };
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>${escapeHtml(t('detailedTitle'))}: ${escapeHtml(title)}</h3>
                <span class="modal-close">&times;</span>
            </div>
            <div class="modal-body">
                <h4>🔍 ${escapeHtml(labels.principle)}</h4>
                <p>${escapeHtml(details.principle)}</p>
                <h4>⚠️ ${escapeHtml(labels.scenario)}</h4>
                <p>${escapeHtml(details.scenario)}</p>
                <h4>🛠️ ${escapeHtml(labels.remediation)}</h4>
                <pre>${escapeHtml(details.fix)}</pre>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    modal.style.display = 'flex';
    const closeSpan = modal.querySelector('.modal-close');
    closeSpan.onclick = () => modal.remove();
    window.onclick = (event) => {
        if (event.target === modal) modal.remove();
    };
}

async function safeFetchJson(url, options) {
    const response = await fetch(url, options);
    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
        const text = await response.text();
        throw new Error(t('responseNotJson') + (text.substring(0, 200) || '(empty)'));
    }
    return await response.json();
}

function getRemediationText(category, detail = null) {
    const rem = i18n[currentLang].remediation;
    if (!rem) return '';
    if (category === 'missingHeaders') return rem[detail] || '';
    if (category === 'sensitiveFiles') return rem[detail] || '';
    if (category === 'xss') return rem.xss || '';
    if (category === 'sql') return rem.sql || '';
    if (category === 'dirTraversal') return rem.dirTraversal || '';
    if (category === 'httpMethods') return typeof rem.httpMethods === 'function' ? rem.httpMethods(detail) : rem.httpMethods || '';
    if (category === 'infoLeakage') return rem.infoLeakage || '';
    if (category === 'cors') return rem.cors || '';
    if (category === 'cspUnsafeInline') return rem.cspUnsafeInline || '';
    if (category === 'cspMissingDefaultSrc') return rem.cspMissingDefaultSrc || '';
    if (category === 'cms') return rem.cmsOutdated || '';
    if (category === 'ssrf') return rem.ssrf || '';
    return '';
}

function renderResult(data) {
    if (!resultContainer) return;
    resultContainer.innerHTML = '';
    errorContainer.style.display = 'none';
    if (scanStartTime) {
        const elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(2);
        scanTimeDiv.textContent = t('scanTime').replace('{time}', elapsed);
        scanTimeDiv.style.display = 'block';
    }

    // 基础信息卡片（始终展开）
    const basicCard = createCard(t('basicInfo'), `
        <div class="info-row"><span class="info-label">${t('urlLabel')}:</span><span class="info-value">${escapeHtml(data.url)}</span></div>
        <div class="info-row"><span class="info-label">${t('statusLabel')}:</span><span class="info-value">${data.basic?.status || '?'}</span></div>
        <div class="info-row"><span class="info-label">${t('titleLabel')}:</span><span class="info-value">${escapeHtml(data.basic?.title || '')}</span></div>
        <div class="info-row"><span class="info-label">${t('headersLabel')}:</span><span class="info-value"><pre>${escapeHtml(JSON.stringify(data.basic?.headers || {}, null, 2))}</pre></span></div>
    `, '', null, false);

    // 安全头部卡片
    const missing = data.security?.missingHeaders || [];
    let securityHtml = '';
    if (missing.length === 0) {
        securityHtml = `<div class="info-value">${t('noMissingHeaders')}</div>`;
    } else {
        securityHtml = `<div class="info-value">${missing.map(h => `<span class="badge">${escapeHtml(h)}</span>`).join('')}</div>`;
        securityHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong><br>${missing.map(h => `• ${escapeHtml(h)}: ${getRemediationText('missingHeaders', h)}`).join('<br>')}</div>`;
    }
    const securityCard = createCard(t('securityHeaders'), securityHtml, '', 'securityHeaders', missing.length === 0);

    // 敏感文件卡片
    const sensitive = data.sensitiveFiles || [];
    let sensitiveHtml = '';
    if (sensitive.length === 0) {
        sensitiveHtml = `<div class="info-value">${t('noSensitiveFiles')}</div>`;
    } else {
        sensitiveHtml = `<div class="info-value">${sensitive.map(f => `<span class="badge vuln-badge">${escapeHtml(f)}</span>`).join('')}</div>`;
        sensitiveHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong><br>${sensitive.map(f => `• ${escapeHtml(f)}: ${getRemediationText('sensitiveFiles', f)}`).join('<br>')}</div>`;
    }
    const sensitiveCard = createCard(t('sensitiveFiles'), sensitiveHtml, '', 'sensitiveFiles', sensitive.length === 0);

    // XSS 卡片
    let xssHtml = '';
    if (data.xss?.vulnerable) {
        xssHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.xss.param)}<br>URL: ${escapeHtml(data.xss.url)}</div>`;
        xssHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('xss')}</div>`;
    } else {
        xssHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noXss')}</div>`;
    }
    const xssCard = createCard(t('xss'), xssHtml, '', 'xss', !data.xss?.vulnerable);

    // SQL 注入卡片
    let sqlHtml = '';
    if (data.sqlInjection?.vulnerable) {
        sqlHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.sqlInjection.param)}<br>URL: ${escapeHtml(data.sqlInjection.url)}${data.sqlInjection.note ? `<br>${t('note')}: ${escapeHtml(data.sqlInjection.note)}` : ''}</div>`;
        sqlHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('sql')}</div>`;
    } else {
        sqlHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noSql')}</div>`;
    }
    const sqlCard = createCard(t('sql'), sqlHtml, '', 'sql', !data.sqlInjection?.vulnerable);

    // 目录遍历卡片
    let dirHtml = '';
    if (data.directoryTraversal?.vulnerable) {
        dirHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.directoryTraversal.param)}<br>Payload: ${escapeHtml(data.directoryTraversal.payload)}</div>`;
        dirHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('dirTraversal')}</div>`;
    } else {
        dirHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('dirTraversalNone')}</div>`;
    }
    const dirCard = createCard(t('directoryTraversal'), dirHtml, '', 'directoryTraversal', !data.directoryTraversal?.vulnerable);

    // HTTP 方法卡片
    const allowed = data.httpMethods?.allowed || [];
    let httpHtml = '';
    if (allowed.length > 0) {
        httpHtml = `<div class="info-value"><span class="badge vuln-badge">${t('dangerousMethods')}</span> ${allowed.join(', ')}</div>`;
        httpHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('httpMethods', allowed)}</div>`;
    } else {
        httpHtml = `<div class="info-value"><span class="badge safe-badge">${t('noDangerousMethods')}</span></div>`;
    }
    const httpCard = createCard(t('httpMethods'), httpHtml, '', 'httpMethods', allowed.length === 0);

    // 信息泄露卡片
    const leaks = data.infoLeakage || {};
    let infoHtml = '';
    if (Object.keys(leaks).length > 0) {
        infoHtml = `<div class="info-value"><span class="badge vuln-badge">${t('foundSensitive')}</span><br>`;
        for (const [type, items] of Object.entries(leaks)) {
            infoHtml += `<strong>${type}:</strong> ${items.join(', ')}<br>`;
        }
        infoHtml += `</div><div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('infoLeakage')}</div>`;
    } else {
        infoHtml = `<div class="info-value"><span class="badge safe-badge">${t('noSensitiveInfo')}</span></div>`;
    }
    const infoCard = createCard(t('infoLeakage'), infoHtml, '', 'infoLeakage', Object.keys(leaks).length === 0);

    // CORS 卡片
    let corsHtml = '';
    if (data.cors?.vulnerable) {
        corsHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${data.cors.details}</div>`;
        corsHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cors')}</div>`;
    } else {
        corsHtml = `<div class="info-value"><span class="badge safe-badge">${t('corsSafe')}</span> ${data.cors?.details || ''}</div>`;
    }
    const corsCard = createCard(t('cors'), corsHtml, '', 'cors', !data.cors?.vulnerable);

    // CMS 卡片
    let cmsHtml = '';
    if (data.cms?.detected) {
        cmsHtml = `<div class="info-value">Detected CMS: <strong>${escapeHtml(data.cms.name)}</strong> ${data.cms.version ? `(v${data.cms.version})` : ''}</div>`;
        cmsHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cms')}</div>`;
    } else {
        cmsHtml = `<div class="info-value">${t('cmsUnknown')}</div>`;
    }
    const cmsCard = createCard(t('cms'), cmsHtml, '', 'cms', !data.cms?.detected);

    // CSP 卡片
    let cspCard = null;
    if (data.security?.csp) {
        const csp = data.security.csp;
        let cspHtml = `<div class="info-value"><pre>${escapeHtml(JSON.stringify(csp.directives, null, 2))}</pre></div>`;
        const hasIssue = csp.issues.unsafeInline || csp.issues.missingDefaultSrc;
        if (csp.issues.unsafeInline) {
            cspHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cspUnsafeInline')}</div>`;
        }
        if (csp.issues.missingDefaultSrc) {
            cspHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cspMissingDefaultSrc')}</div>`;
        }
        cspCard = createCard(t('csp'), cspHtml, '', 'csp', !hasIssue);
    }

    // SSL 卡片
    let sslCard = null;
    if (data.ssl) {
        let sslHtml = '';
        let hasVuln = false;
        if (data.ssl.error) {
            sslHtml = `<div class="info-value">Error: ${escapeHtml(data.ssl.error)}</div>`;
            hasVuln = true;
        } else {
            sslHtml = `
                <div class="info-row"><span class="info-label">Protocol:</span><span class="info-value">${escapeHtml(data.ssl.protocol)}</span></div>
                <div class="info-row"><span class="info-label">Cipher:</span><span class="info-value">${escapeHtml(data.ssl.cipher)}</span></div>
                <div class="info-row"><span class="info-label">Certificate:</span><span class="info-value"><pre>${escapeHtml(JSON.stringify(data.ssl.certificate, null, 2))}</pre></span></div>
                <div class="info-row"><span class="info-label">Weak Protocol:</span><span class="info-value">${data.ssl.weakProtocol ? 'Yes' : 'No'}</span></div>
            `;
            hasVuln = data.ssl.weakProtocol || data.ssl.vulnerabilities?.expiredCert || data.ssl.vulnerabilities?.notYetValid;
            if (data.ssl.vulnerabilities?.weakProtocol) {
                sslHtml += `<div class="remediation-box"><strong>⚠️ Weak protocol detected. Upgrade to TLSv1.2 or higher.</strong></div>`;
            }
            if (data.ssl.vulnerabilities?.expiredCert) {
                sslHtml += `<div class="remediation-box"><strong>⚠️ Certificate expired. Renew immediately.</strong></div>`;
            }
            if (data.ssl.vulnerabilities?.notYetValid) {
                sslHtml += `<div class="remediation-box"><strong>⚠️ Certificate not yet valid. Check system date.</strong></div>`;
            }
        }
        sslCard = createCard(t('ssl'), sslHtml, '', 'ssl', !hasVuln);
    }

    // 威胁情报卡片
    if (data.threatIntel) {
        const intel = data.threatIntel;
        let intelHtml = '';
        if (intel.is_malicious) {
            intelHtml = `<div class="info-value"><span class="badge vuln-badge">⚠️ 该 IP 被标记为恶意</span><br>`;
            intelHtml += `风险评分: ${intel.risk_score}<br>`;
            if (intel.malware_families && intel.malware_families.length) {
                intelHtml += `关联恶意软件: ${intel.malware_families.join(', ')}<br>`;
            }
            if (intel.open_ports && intel.open_ports.length) {
                intelHtml += `开放端口: ${intel.open_ports.join(', ')}`;
            }
            intelHtml += `</div><div class="remediation-box"><strong>🔧 建议：</strong> 该主机可能存在风险，请进一步检查。`;
        } else {
            intelHtml = `<div class="info-value"><span class="badge safe-badge">IP 信誉良好</span></div>`;
        }
        const intelCard = createCard('🔍 外部威胁情报', intelHtml, '', 'threatIntel', true);
        resultContainer.appendChild(intelCard);
    }

    // SSRF 卡片
    let ssrfHtml = '';
    if (data.ssrf?.vulnerable) {
        ssrfHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.ssrf.param)}<br>URL: ${escapeHtml(data.ssrf.url)}${data.ssrf.note ? `<br>${t('note')}: ${escapeHtml(data.ssrf.note)}` : ''}</div>`;
        ssrfHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('ssrf')}</div>`;
    } else {
        ssrfHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> 未检测到 SSRF 漏洞。</div>`;
    }
    const ssrfCard = createCard(t('ssrf'), ssrfHtml, '', 'ssrf', true);

    // 免责声明卡片（扫描结果中不再重复显示法律声明，因为已在页面顶部显示）
    // 只保留一个额外的提示卡片？为了不重复，这里不再添加 disclaimerCard，因为已在页面顶部有法律声明区域。

    // 按顺序添加
    resultContainer.appendChild(basicCard);
    resultContainer.appendChild(securityCard);
    resultContainer.appendChild(sensitiveCard);
    resultContainer.appendChild(xssCard);
    resultContainer.appendChild(sqlCard);
    resultContainer.appendChild(dirCard);
    resultContainer.appendChild(httpCard);
    resultContainer.appendChild(infoCard);
    resultContainer.appendChild(corsCard);
    resultContainer.appendChild(cmsCard);
    if (cspCard) resultContainer.appendChild(cspCard);
    if (sslCard) resultContainer.appendChild(sslCard);
    resultContainer.appendChild(ssrfCard);

    resultContainer.style.display = 'block';
    exportContainer.style.display = 'block';
    window.lastScanData = data;
}

function exportReport() {
    if (!window.lastScanData) return;
    const exportData = JSON.parse(JSON.stringify(window.lastScanData));
    exportData._note = {
        disclaimer: "⚠️ This report is for authorized security testing only. Unauthorized scanning is prohibited.",
        website: "https://neteye.vercel.app",
        contact: "zero6039@gmail.com"
    };
    const dataStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_report_${new Date().toISOString()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

async function exportPDF() {
    if (!window.lastScanData) return;
    const element = resultContainer.cloneNode(true);
    element.querySelectorAll('.copy-btn, .info-btn, .collapse-icon').forEach(btn => btn.remove());
    element.style.padding = '20px';
    element.style.backgroundColor = 'white';
    element.style.color = 'black';
    element.style.width = '800px';
    
    const footer = document.createElement('div');
    footer.style.marginTop = '30px';
    footer.style.padding = '10px';
    footer.style.borderTop = '1px solid #ccc';
    footer.style.fontSize = '12px';
    footer.style.color = '#666';
    footer.style.textAlign = 'center';
    footer.innerHTML = `
        <p>⚠️ This report is for authorized security testing only. Unauthorized scanning is prohibited.</p>
        <p>Report generated by <a href="https://neteye.vercel.app">NetEye Scanner</a> | Contact: zero6039@gmail.com</p>
    `;
    element.appendChild(footer);
    
    document.body.appendChild(element);
    try {
        const canvas = await html2canvas(element, { scale: 2 });
        const imgData = canvas.toDataURL('image/png');
        const { jsPDF } = window.jspdf;
        const pdf = new jsPDF('p', 'mm', 'a4');
        const imgWidth = 190;
        const pageHeight = 297;
        const imgHeight = (canvas.height * imgWidth) / canvas.width;
        let heightLeft = imgHeight;
        let position = 0;
        pdf.addImage(imgData, 'PNG', 10, position, imgWidth, imgHeight);
        heightLeft -= pageHeight;
        while (heightLeft > 0) {
            position = heightLeft - imgHeight;
            pdf.addPage();
            pdf.addImage(imgData, 'PNG', 10, position, imgWidth, imgHeight);
            heightLeft -= pageHeight;
        }
        pdf.save(`scan_report_${new Date().toISOString()}.pdf`);
    } finally {
        element.remove();
    }
}

async function exportHTML() {
    if (!window.lastScanData) return;
    const element = resultContainer.cloneNode(true);
    element.querySelectorAll('.copy-btn, .info-btn, .collapse-icon').forEach(btn => btn.remove());
    element.style.padding = '20px';
    element.style.backgroundColor = 'white';
    element.style.color = 'black';
    
    const footerHtml = `
        <div style="margin-top: 30px; padding: 10px; border-top: 1px solid #ccc; font-size: 12px; color: #666; text-align: center;">
            <p>⚠️ This report is for authorized security testing only. Unauthorized scanning is prohibited.</p>
            <p>Report generated by <a href="https://neteye.vercel.app">NetEye Scanner</a> | Contact: zero6039@gmail.com</p>
        </div>
    `;
    const fullHtml = `<!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"><title>NetEye Security Report</title>
    <style>body{font-family:sans-serif;padding:20px} .result-card{border:1px solid #ccc;margin-bottom:20px;padding:10px} .card-header{font-weight:bold}</style>
    </head>
    <body>${element.outerHTML}${footerHtml}</body>
    </html>`;
    const blob = new Blob([fullHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_report_${new Date().toISOString()}.html`;
    a.click();
    URL.revokeObjectURL(url);
}

// ==================== 邮件发送（右下角模态框） ====================
function showEmailModal() {
    if (!emailModal) return;
    emailModal.style.display = 'block';
    if (emailInput) emailInput.value = '';
    if (emailError) emailError.style.display = 'none';
}

function hideEmailModal() {
    if (emailModal) emailModal.style.display = 'none';
}

async function sendReportToEmail() {
    if (!window.lastScanData) {
        alert('No scan result available. Please scan a website first.');
        hideEmailModal();
        return;
    }

    const email = emailInput ? emailInput.value.trim() : '';
    if (!email) {
        if (emailError) {
            emailError.textContent = 'Please enter an email address.';
            emailError.style.display = 'block';
        }
        return;
    }
    const emailPattern = /^[^\s@]+@([^\s@]+\.)+[^\s@]+$/;
    if (!emailPattern.test(email)) {
        if (emailError) {
            emailError.textContent = 'Please enter a valid email address.';
            emailError.style.display = 'block';
        }
        return;
    }

    if (emailSend) {
        emailSend.disabled = true;
        emailSend.textContent = 'Sending...';
    }

    const reportElement = resultContainer.cloneNode(true);
    reportElement.querySelectorAll('.copy-btn, .info-btn, .collapse-icon').forEach(btn => btn.remove());
    const reportHtml = reportElement.innerHTML;

    try {
        const response = await fetch(`${API_BASE}/api/send-report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ toEmail: email, reportHtml })
        });
        if (response.ok) {
            alert('Report sent successfully!');
            hideEmailModal();
        } else {
            const err = await response.json();
            alert(`Failed to send report: ${err.error || 'Unknown error'}`);
        }
    } catch (err) {
        console.error(err);
        alert('An error occurred while sending the report.');
    } finally {
        if (emailSend) {
            emailSend.disabled = false;
            emailSend.textContent = 'Send';
        }
    }
}

// ==================== 扫描主函数 ====================
async function scan() {
    // 获取深度选择器中的所有单选按钮
    const depthRadios = document.querySelectorAll('input[name="depth"]');
    // 禁用它们（扫描期间不可切换）
    depthRadios.forEach(radio => radio.disabled = true);

    let url = targetInput.value.trim();
    if (!url) {
        errorContainer.textContent = t('pleaseEnterUrl');
        errorContainer.style.display = 'block';
        depthRadios.forEach(radio => radio.disabled = false);
        return;
    }

    if (/^javascript:/i.test(url) || /^data:/i.test(url) || /^vbscript:/i.test(url)) {
        errorContainer.textContent = t('errorPrefix') + 'Invalid URL protocol';
        errorContainer.style.display = 'block';
        depthRadios.forEach(radio => radio.disabled = false);
        return;
    }

    let testUrl = url;
    if (!/^https?:\/\//i.test(testUrl)) {
        testUrl = 'http://' + testUrl;
    }
    try {
        const parsed = new URL(testUrl);
        if (!parsed.hostname || parsed.hostname.length < 2) {
            throw new Error();
        }
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            throw new Error();
        }
    } catch (err) {
        errorContainer.textContent = t('errorPrefix') + t('invalidUrl');
        errorContainer.style.display = 'block';
        depthRadios.forEach(radio => radio.disabled = false);
        return;
    }

    if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
        targetInput.value = url;
    }

    const depthElem = document.querySelector('input[name="depth"]:checked');
    const depth = depthElem ? depthElem.value : 'deep';

    // 深度扫描免费开放，但弹出提示
    if (depth === 'deep') {
        alert(t('upgradeFreeNotice'));
    }

    const modules = depth === 'deep' ? PAID_MODULES : FREE_MODULES;

    scanBtn.disabled = true;
    scanBtn.textContent = t('scanning');
    loadingDiv.style.display = 'block';
    progressContainer.style.display = 'block';
    resultContainer.style.display = 'none';
    errorContainer.style.display = 'none';
    exportContainer.style.display = 'none';
    scanTimeDiv.style.display = 'none';

    let phaseIndex = 0;
    progressFill.style.width = '0%';
    progressMessage.textContent = modules[0].key === 'basic' ? t('phaseBasic') : t('phaseSecurity');

    if (phaseInterval) clearInterval(phaseInterval);
    phaseInterval = setInterval(() => {
        if (phaseIndex < modules.length - 1) {
            phaseIndex++;
            const phaseKey = modules[phaseIndex].key;
            const phaseText = t(`phase${phaseKey.charAt(0).toUpperCase() + phaseKey.slice(1)}`);
            progressMessage.textContent = phaseText;
        }
    }, 1000);

    scanStartTime = Date.now();

    const result = {
        url,
        basic: {},
        security: { missingHeaders: [], csp: null },
        sensitiveFiles: [],
        xss: { vulnerable: false },
        sqlInjection: { vulnerable: false },
        directoryTraversal: { vulnerable: false },
        httpMethods: { allowed: [] },
        infoLeakage: {},
        cors: { vulnerable: false, details: '' },
        cms: { detected: false },
        ssl: null,
        ssrf: { vulnerable: false }
    };

    try {
        for (const module of modules) {
            try {
                const response = await safeFetchJson(API_BASE + module.endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                if (module.key === 'basic') {
                    result.basic = response.basic;
                    result.security.missingHeaders = response.missingHeaders;
                    result.security.csp = response.csp;
                    result.ssl = response.ssl;
                } else {
                    const keys = module.resultKey.split('.');
                    let target = result;
                    for (let i = 0; i < keys.length - 1; i++) {
                        if (!target[keys[i]]) target[keys[i]] = {};
                        target = target[keys[i]];
                    }
                    const lastKey = keys[keys.length - 1];
                    target[lastKey] = module.transform(response);
                }
            } catch (err) {
                console.error(`模块 ${module.key} 失败:`, err);
            }
        }

        if (phaseInterval) clearInterval(phaseInterval);
        progressFill.style.width = '100%';
        progressMessage.textContent = t('phaseComplete');
        setTimeout(() => {
            progressContainer.style.display = 'none';
        }, 500);
        loadingDiv.style.display = 'none';
        renderResult(result);
    } catch (err) {
        if (phaseInterval) clearInterval(phaseInterval);
        loadingDiv.style.display = 'none';
        progressContainer.style.display = 'none';
        errorContainer.textContent = t('errorPrefix') + err.message;
        errorContainer.style.display = 'block';
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = currentLang === 'en' ? 'Start Scan' : '开始扫描';
        // 启用深度选择器
        depthRadios.forEach(radio => radio.disabled = false);
    }
}

function setLanguage(lang) {
    currentLang = lang;
    langEnBtn.classList.toggle('active', lang === 'en');
    langZhBtn.classList.toggle('active', lang === 'zh');
    if (window.lastScanData) renderResult(window.lastScanData);
    targetInput.placeholder = lang === 'en' ? 'https://example.com' : 'https://example.com';
    scanBtn.textContent = lang === 'en' ? 'Start Scan' : '开始扫描';
    if (exportMenuBtn) exportMenuBtn.textContent = lang === 'en' ? '📄 Report Export as' : '📄 导出报告';
    if (emailReportBtn) {
        emailReportBtn.title = lang === 'en' ? 'Send report via email' : '邮件发送报告';
    }

    // 更新法律声明文本
    if (noticeTitle) noticeTitle.textContent = t('legalNoticeTitle');
    if (noticeText) noticeText.textContent = t('legalNoticeText');
    // 更新关于NetEye内容
    if (aboutContent) {
        const aboutTextArray = t('aboutText');
        aboutContent.innerHTML = aboutTextArray.map(p => `<p>${escapeHtml(p)}</p>`).join('');
    }

    // 更新关于卡片标题（新增）
    const aboutHeaderSpan = document.querySelector('#about-card .card-header span');
    if (aboutHeaderSpan) aboutHeaderSpan.innerHTML = `📌 ${t('aboutTitle')}`;    

    const quickLabel = document.getElementById('quick-label');
    const deepLabel = document.getElementById('deep-label');
    if (quickLabel) quickLabel.innerHTML = `<input type="radio" name="depth" value="quick" checked /> ${t('quickScan')}`;
    if (deepLabel) deepLabel.innerHTML = `<input type="radio" name="depth" value="deep" /> ${t('deepScan')}`;

    const loadingSpan = loadingDiv.querySelector('span');
    if (loadingSpan) loadingSpan.textContent = t('scanning');
}

function toggleTheme() {
    currentTheme = currentTheme === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', currentTheme);
    themeToggle.textContent = currentTheme === 'light' ? '🌙' : '☀️';
}

// ==================== 折叠/展开功能 ====================
function setupCollapse(btn, content) {
    if (!btn || !content) return;
    const updateIcon = () => {
    btn.textContent = content.classList.contains('collapsed') ? '+' : '−';
    };
    btn.addEventListener('click', () => {
        content.classList.toggle('collapsed');
        updateIcon();
    });
    updateIcon();
}

// ==================== 首次访问确认弹窗 ====================
function checkFirstVisit() {
    const hasConfirmed = localStorage.getItem('neteye_consent');
    if (!hasConfirmed) {
        const userConfirmed = confirm(t('firstTimeDisclaimer'));
        if (userConfirmed) {
            localStorage.setItem('neteye_consent', 'true');
        } else {
            // 如果用户拒绝，可以禁用扫描按钮或跳转，这里我们仅记录，不强制
        }
    }
}

// ==================== 页面初始化 ====================
document.addEventListener('DOMContentLoaded', () => {
    targetInput = document.getElementById('target');
    scanBtn = document.getElementById('scan-btn');
    resultContainer = document.getElementById('result-container');
    errorContainer = document.getElementById('error-container');
    loadingDiv = document.getElementById('loading');
    exportContainer = document.getElementById('export-container');
    langEnBtn = document.getElementById('lang-en');
    langZhBtn = document.getElementById('lang-zh');
    themeToggle = document.getElementById('theme-toggle');
    scanTimeDiv = document.getElementById('scan-time');
    progressContainer = document.getElementById('progress-container');
    progressFill = document.getElementById('progress-fill');
    progressMessage = document.getElementById('progress-message');
    exportMenuBtn = document.getElementById('export-menu-btn');
    exportModal = document.getElementById('export-modal');
    exportJsonBtn = document.getElementById('export-json-btn');
    exportPdfBtn = document.getElementById('export-pdf-btn');
    exportHtmlBtn = document.getElementById('export-html-btn');
    emailReportBtn = document.getElementById('email-report-btn');
    emailModal = document.getElementById('email-modal');
    emailClose = document.querySelector('.email-modal-close');
    emailCancel = document.getElementById('email-cancel-btn');
    emailSend = document.getElementById('email-send-btn');
    emailInput = document.getElementById('report-email');
    emailError = document.getElementById('email-error');
    noticeTitle = document.getElementById('notice-title');
    noticeText = document.getElementById('notice-text');
    noticeCollapseBtn = document.getElementById('notice-collapse-btn');
    noticeContent = document.getElementById('notice-content');
    aboutCollapseBtn = document.getElementById('about-collapse-btn');
    aboutContent = document.getElementById('about-content');

    function hideTemporaryUI() {
        if (loadingDiv) loadingDiv.style.display = 'none';
        if (progressContainer) progressContainer.style.display = 'none';
        if (scanTimeDiv) scanTimeDiv.style.display = 'none';
        if (exportContainer) exportContainer.style.display = 'none';
        if (resultContainer) resultContainer.style.display = 'none';
        if (errorContainer) errorContainer.style.display = 'none';
    }
    hideTemporaryUI();

    // 设置折叠功能
    setupCollapse(noticeCollapseBtn, noticeContent);
    setupCollapse(aboutCollapseBtn, aboutContent);

    // 检查首次访问
    checkFirstVisit();

    if (scanBtn) scanBtn.addEventListener('click', scan);
    if (targetInput) targetInput.addEventListener('keypress', (e) => e.key === 'Enter' && scan());
    if (exportMenuBtn) exportMenuBtn.addEventListener('click', () => { if (exportModal) exportModal.style.display = 'flex'; });
    if (exportJsonBtn) exportJsonBtn.addEventListener('click', () => { if (exportModal) exportModal.style.display = 'none'; exportReport(); });
    if (exportPdfBtn) exportPdfBtn.addEventListener('click', () => { if (exportModal) exportModal.style.display = 'none'; exportPDF(); });
    if (exportHtmlBtn) exportHtmlBtn.addEventListener('click', () => { if (exportModal) exportModal.style.display = 'none'; exportHTML(); });
    if (langEnBtn) langEnBtn.addEventListener('click', () => setLanguage('en'));
    if (langZhBtn) langZhBtn.addEventListener('click', () => setLanguage('zh'));
    if (themeToggle) themeToggle.addEventListener('click', toggleTheme);
    if (emailReportBtn) emailReportBtn.addEventListener('click', showEmailModal);
    if (emailSend) emailSend.addEventListener('click', sendReportToEmail);
    if (emailClose) emailClose.addEventListener('click', hideEmailModal);
    if (emailCancel) emailCancel.addEventListener('click', hideEmailModal);
    window.addEventListener('click', (event) => {
        if (event.target === emailModal) hideEmailModal();
    });

    document.querySelectorAll('.modal-close').forEach(closeBtn => {
        closeBtn.addEventListener('click', () => {
            const modal = closeBtn.closest('.modal');
            if (modal) modal.style.display = 'none';
        });
    });
    window.addEventListener('click', (event) => {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
        }
    });

    setLanguage('en');
});
