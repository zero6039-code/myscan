// ==================== 配置 ====================
const API_BASE = 'https://myscan-henna.vercel.app'; // 替换为您的 Vercel 域名
const API_SCAN = `${API_BASE}/api/scan`;

// ==================== 国际化文本库 ====================
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
        phaseComplete: 'Complete!',
        collapse: 'Collapse',
        expand: 'Expand',
        remediation: {
            // 修复建议（完整内容见之前版本，此处为节省篇幅省略）
            'X-Frame-Options': 'Missing this header may lead to clickjacking attacks. Recommended: `X-Frame-Options: SAMEORIGIN`',
            'X-Content-Type-Options': 'Missing this header may lead to MIME type confusion attacks. Recommended: `X-Content-Type-Options: nosniff`',
            'X-XSS-Protection': 'Missing this header may reduce browser XSS protection. Recommended: `X-XSS-Protection: 1; mode=block`',
            'Strict-Transport-Security': 'Missing HSTS may allow HTTPS downgrade. Recommended: `Strict-Transport-Security: max-age=31536000; includeSubDomains`',
            'Content-Security-Policy': 'Missing CSP may lead to XSS risks. Recommended to set a proper policy, e.g., `default-src \'self\'`',
            'Referrer-Policy': 'Missing Referrer-Policy may leak referrer information. Recommended: `Referrer-Policy: strict-origin-when-cross-origin`',
            'Permissions-Policy': 'Missing Permissions-Policy may allow unwanted browser features. Recommended: `Permissions-Policy: geolocation=(), microphone=(), camera=()`',
            '/robots.txt': 'Exposes website directory structure. Recommend restricting sensitive paths or removing unnecessary information.',
            '/.env': 'Seriously exposes environment variables. Immediately delete or deny access.',
            '/.git/config': 'Exposes Git repository information. Delete or restrict access.',
            '/backup.zip': 'Backup file can be downloaded. Remove or set strong access control.',
            '/admin': 'Admin panel exposed. Recommend adding authentication or hiding the path.',
            '/phpinfo.php': 'Exposes PHP configuration. Delete this file.',
            xss: 'Reflected XSS can be exploited to execute malicious scripts. Recommend strict filtering and escaping of user input, and use Content Security Policy.',
            sql: 'SQL injection can lead to data leakage or tampering. Use parameterized queries, prepared statements, avoid SQL concatenation.',
            dirTraversal: 'Directory traversal vulnerability can read arbitrary files. Strictly restrict file paths and use whitelist validation.',
            httpMethods: (methods) => `Dangerous HTTP methods allowed: ${methods.join(', ')}. Recommend disabling unnecessary methods (e.g., PUT, DELETE, TRACE).`,
            infoLeakage: 'Response may contain sensitive information (emails, phone numbers, API keys). Review and remove such information.',
            cors: 'CORS misconfiguration may allow any origin to access resources. Restrict `Access-Control-Allow-Origin` to specific trusted domains.',
            cmsOutdated: 'CMS detected. Keep it updated to avoid known vulnerabilities.',
            cspUnsafeInline: 'CSP uses `unsafe-inline`, weakening XSS protection. Recommend using nonce or hash instead.',
            cspMissingDefaultSrc: 'CSP missing `default-src` directive. Recommend adding `default-src \'self\'`.'
        },
        detailed: {
            // 详细解说（完整内容见之前版本，此处为节省篇幅省略）
            securityHeaders: {
                title: 'Missing Security Headers',
                principle: 'Security headers are HTTP response headers that instruct the browser how to behave. Missing them leaves the site vulnerable to attacks like clickjacking, MIME type sniffing, and XSS.',
                scenario: 'An attacker could embed your site in an iframe (clickjacking) or trick the browser into executing malicious scripts via MIME confusion.',
                fix: 'Add the appropriate headers in your server configuration. For example, in Nginx:\n\nadd_header X-Frame-Options "SAMEORIGIN" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header X-XSS-Protection "1; mode=block" always;\nadd_header Content-Security-Policy "default-src \'self\'" always;'
            },
            // 其他 detailed 内容请参考之前提供的完整版本（此处省略）
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
        phaseComplete: '完成！',
        collapse: '折叠',
        expand: '展开',
        remediation: {
            // 中文修复建议（完整内容见之前版本）
            'X-Frame-Options': '缺少该头可能导致点击劫持攻击。建议添加: `X-Frame-Options: SAMEORIGIN`',
            // 其他...
        },
        detailed: {
            // 中文详细解说（略）
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

// DOM 元素
const targetInput = document.getElementById('target');
const scanBtn = document.getElementById('scan-btn');
const resultContainer = document.getElementById('result-container');
const errorContainer = document.getElementById('error-container');
const loadingDiv = document.getElementById('loading');
const exportContainer = document.getElementById('export-container');
const exportBtn = document.getElementById('export-btn');
const pdfBtn = document.getElementById('pdf-btn');
const htmlBtn = document.getElementById('html-btn');
const langEnBtn = document.getElementById('lang-en');
const langZhBtn = document.getElementById('lang-zh');
const themeToggle = document.getElementById('theme-toggle');
const scanTimeDiv = document.getElementById('scan-time');
const progressContainer = document.getElementById('progress-container');
const progressFill = document.getElementById('progress-fill');
const progressMessage = document.getElementById('progress-message');

// 初始隐藏所有临时UI
function hideTemporaryUI() {
    if (loadingDiv) loadingDiv.style.display = 'none';
    if (progressContainer) progressContainer.style.display = 'none';
    if (scanTimeDiv) scanTimeDiv.style.display = 'none';
    if (exportContainer) exportContainer.style.display = 'none';
    if (resultContainer) resultContainer.style.display = 'none';
    if (errorContainer) errorContainer.style.display = 'none';
}
hideTemporaryUI();

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

    // 基础信息卡片（不折叠）
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
    const securityCard = createCard(t('securityHeaders'), securityHtml, '', 'securityHeaders', false);

    // 敏感文件卡片
    const sensitive = data.sensitiveFiles || [];
    let sensitiveHtml = '';
    if (sensitive.length === 0) {
        sensitiveHtml = `<div class="info-value">${t('noSensitiveFiles')}</div>`;
    } else {
        sensitiveHtml = `<div class="info-value">${sensitive.map(f => `<span class="badge vuln-badge">${escapeHtml(f)}</span>`).join('')}</div>`;
        sensitiveHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong><br>${sensitive.map(f => `• ${escapeHtml(f)}: ${getRemediationText('sensitiveFiles', f)}`).join('<br>')}</div>`;
    }
    const sensitiveCard = createCard(t('sensitiveFiles'), sensitiveHtml, '', 'sensitiveFiles', false);

    // XSS 卡片
    let xssHtml = '';
    if (data.xss?.vulnerable) {
        xssHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.xss.param)}<br>URL: ${escapeHtml(data.xss.url)}</div>`;
        xssHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('xss')}</div>`;
    } else {
        xssHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noXss')}</div>`;
    }
    const xssCard = createCard(t('xss'), xssHtml, '', 'xss', false);

    // SQL 注入卡片
    let sqlHtml = '';
    if (data.sqlInjection?.vulnerable) {
        sqlHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.sqlInjection.param)}<br>URL: ${escapeHtml(data.sqlInjection.url)}${data.sqlInjection.note ? `<br>${t('note')}: ${escapeHtml(data.sqlInjection.note)}` : ''}</div>`;
        sqlHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('sql')}</div>`;
    } else {
        sqlHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noSql')}</div>`;
    }
    const sqlCard = createCard(t('sql'), sqlHtml, '', 'sql', false);

    // 目录遍历卡片
    let dirHtml = '';
    if (data.directoryTraversal?.vulnerable) {
        dirHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.directoryTraversal.param)}<br>Payload: ${escapeHtml(data.directoryTraversal.payload)}</div>`;
        dirHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('dirTraversal')}</div>`;
    } else {
        dirHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('dirTraversalNone')}</div>`;
    }
    const dirCard = createCard(t('directoryTraversal'), dirHtml, '', 'directoryTraversal', false);

    // HTTP 方法卡片
    const allowed = data.httpMethods?.allowed || [];
    let httpHtml = '';
    if (allowed.length > 0) {
        httpHtml = `<div class="info-value"><span class="badge vuln-badge">${t('dangerousMethods')}</span> ${allowed.join(', ')}</div>`;
        httpHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('httpMethods', allowed)}</div>`;
    } else {
        httpHtml = `<div class="info-value"><span class="badge safe-badge">${t('noDangerousMethods')}</span></div>`;
    }
    const httpCard = createCard(t('httpMethods'), httpHtml, '', 'httpMethods', false);

    // 信息泄露卡片（默认折叠）
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
    const infoCard = createCard(t('infoLeakage'), infoHtml, '', 'infoLeakage', true);

    // CORS 卡片（默认折叠）
    let corsHtml = '';
    if (data.cors?.vulnerable) {
        corsHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${data.cors.details}</div>`;
        corsHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cors')}</div>`;
    } else {
        corsHtml = `<div class="info-value"><span class="badge safe-badge">${t('corsSafe')}</span> ${data.cors?.details || ''}</div>`;
    }
    const corsCard = createCard(t('cors'), corsHtml, '', 'cors', true);

    // CMS 卡片（默认折叠）
    let cmsHtml = '';
    if (data.cms?.detected) {
        cmsHtml = `<div class="info-value">Detected CMS: <strong>${escapeHtml(data.cms.name)}</strong> ${data.cms.version ? `(v${data.cms.version})` : ''}</div>`;
        cmsHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cms')}</div>`;
    } else {
        cmsHtml = `<div class="info-value">${t('cmsUnknown')}</div>`;
    }
    const cmsCard = createCard(t('cms'), cmsHtml, '', 'cms', true);

    // CSP 卡片（默认折叠）
    let cspCard = null;
    if (data.security?.csp) {
        const csp = data.security.csp;
        let cspHtml = `<div class="info-value"><pre>${escapeHtml(JSON.stringify(csp.directives, null, 2))}</pre></div>`;
        if (csp.issues.unsafeInline) {
            cspHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cspUnsafeInline')}</div>`;
        }
        if (csp.issues.missingDefaultSrc) {
            cspHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cspMissingDefaultSrc')}</div>`;
        }
        cspCard = createCard(t('csp'), cspHtml, '', 'csp', true);
    }

    // SSL 卡片（默认折叠）
    let sslCard = null;
    if (data.ssl) {
        let sslHtml = '';
        if (data.ssl.error) {
            sslHtml = `<div class="info-value">Error: ${escapeHtml(data.ssl.error)}</div>`;
        } else {
            sslHtml = `
                <div class="info-row"><span class="info-label">Protocol:</span><span class="info-value">${escapeHtml(data.ssl.protocol)}</span></div>
                <div class="info-row"><span class="info-label">Cipher:</span><span class="info-value">${escapeHtml(data.ssl.cipher)}</span></div>
                <div class="info-row"><span class="info-label">Certificate:</span><span class="info-value"><pre>${escapeHtml(JSON.stringify(data.ssl.certificate, null, 2))}</pre></span></div>
                <div class="info-row"><span class="info-label">Weak Protocol:</span><span class="info-value">${data.ssl.weakProtocol ? 'Yes' : 'No'}</span></div>
            `;
            if (data.ssl.vulnerabilities?.weakProtocol) {
                sslHtml += `<div class="remediation-box"><strong>⚠️ Weak protocol detected. Upgrade to TLSv1.2 or higher.</strong></div>`;
            }
            if (data.ssl.vulnerabilities?.expiredCert) {
                sslHtml += `<div class="remediation-box"><strong>⚠️ Certificate expired. Renew immediately.</strong></div>`;
            }
        }
        sslCard = createCard(t('ssl'), sslHtml, '', 'ssl', true);
    }

    // 免责声明卡片
    const disclaimerCard = createCard('', `<div style="font-size:14px;">${t('disclaimer')}</div>`, 'disclaimer-card', null, false);
    disclaimerCard.querySelector('.card-header').innerHTML = `⚠️ ${t('disclaimer')}`;

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
    resultContainer.appendChild(disclaimerCard);

    resultContainer.style.display = 'block';
    exportContainer.style.display = 'block';
    window.lastScanData = data;
}

// 导出 JSON
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

// 导出 PDF
async function exportPDF() {
    if (!window.lastScanData) return;
    const element = resultContainer.cloneNode(true);
    element.querySelectorAll('.copy-btn, .info-btn, .collapse-icon').forEach(btn => btn.remove());
    element.style.padding = '20px';
    element.style.backgroundColor = 'white';
    element.style.color = 'black';
    element.style.width = '800px';
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

// 导出 HTML
async function exportHTML() {
    if (!window.lastScanData) return;
    const element = resultContainer.cloneNode(true);
    element.querySelectorAll('.copy-btn, .info-btn, .collapse-icon').forEach(btn => btn.remove());
    element.style.padding = '20px';
    element.style.backgroundColor = 'white';
    element.style.color = 'black';
    const htmlContent = `<!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"><title>MyScan Report</title>
    <style>body{font-family:sans-serif;padding:20px} .result-card{border:1px solid #ccc;margin-bottom:20px;padding:10px} .card-header{font-weight:bold}</style>
    </head>
    <body>${element.outerHTML}</body>
    </html>`;
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_report_${new Date().toISOString()}.html`;
    a.click();
    URL.revokeObjectURL(url);
}

// 扫描函数（含输入校验）
async function scan() {
    let url = targetInput.value.trim();
    if (!url) {
        errorContainer.textContent = t('pleaseEnterUrl');
        errorContainer.style.display = 'block';
        return;
    }

    // 危险协议过滤
    if (/^javascript:/i.test(url) || /^data:/i.test(url) || /^vbscript:/i.test(url)) {
        errorContainer.textContent = t('errorPrefix') + 'Invalid URL protocol';
        errorContainer.style.display = 'block';
        return;
    }

    // 基本 URL 格式校验
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
        return;
    }

    // 自动补全协议
    if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
        targetInput.value = url;
    }

    const depthElem = document.querySelector('input[name="depth"]:checked');
    const depth = depthElem ? depthElem.value : 'deep';

    scanBtn.disabled = true;
    scanBtn.textContent = t('scanning');
    loadingDiv.style.display = 'block';
    progressContainer.style.display = 'block';
    resultContainer.style.display = 'none';
    errorContainer.style.display = 'none';
    exportContainer.style.display = 'none';
    scanTimeDiv.style.display = 'none';

    // 阶段列表
    const allPhases = [
        { text: t('phaseBasic') },
        { text: t('phaseSecurity') },
        { text: t('phaseSensitive') },
        { text: t('phaseXss') },
        { text: t('phaseSql') },
        { text: t('phaseDir') },
        { text: t('phaseHttp') },
        { text: t('phaseInfo') },
        { text: t('phaseCors') },
        { text: t('phaseCms') },
        { text: t('phaseSsl') }
    ];
    const phases = depth === 'deep' ? allPhases : allPhases.slice(0, 2);
    let phaseIndex = 0;
    progressFill.style.width = '0%';
    progressMessage.textContent = phases[0].text;

    if (phaseInterval) clearInterval(phaseInterval);
    phaseInterval = setInterval(() => {
        if (phaseIndex < phases.length - 1) {
            phaseIndex++;
            progressMessage.textContent = phases[phaseIndex].text;
        }
    }, 1000);

    scanStartTime = Date.now();

    try {
        const data = await safeFetchJson(API_SCAN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, depth })
        });
        if (phaseInterval) clearInterval(phaseInterval);
        progressFill.style.width = '100%';
        progressMessage.textContent = t('phaseComplete');
        setTimeout(() => {
            progressContainer.style.display = 'none';
        }, 500);
        loadingDiv.style.display = 'none';
        renderResult(data);
    } catch (err) {
        if (phaseInterval) clearInterval(phaseInterval);
        loadingDiv.style.display = 'none';
        progressContainer.style.display = 'none';
        errorContainer.textContent = t('errorPrefix') + err.message;
        errorContainer.style.display = 'block';
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = currentLang === 'en' ? 'Start Scan' : '开始扫描';
    }
}

// 语言切换
function setLanguage(lang) {
    currentLang = lang;
    langEnBtn.classList.toggle('active', lang === 'en');
    langZhBtn.classList.toggle('active', lang === 'zh');
    if (window.lastScanData) renderResult(window.lastScanData);
    targetInput.placeholder = lang === 'en' ? 'https://example.com' : 'https://example.com';
    scanBtn.textContent = lang === 'en' ? 'Start Scan' : '开始扫描';
    exportBtn.textContent = t('export');
    pdfBtn.textContent = t('pdfExport');
    htmlBtn.textContent = t('htmlExport');
    const loadingSpan = loadingDiv.querySelector('span');
    if (loadingSpan) loadingSpan.textContent = t('scanning');
}

// 深色模式切换
function toggleTheme() {
    currentTheme = currentTheme === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', currentTheme);
    themeToggle.textContent = currentTheme === 'light' ? '🌙' : '☀️';
}

// 事件绑定
if (scanBtn) scanBtn.addEventListener('click', scan);
if (targetInput) targetInput.addEventListener('keypress', (e) => e.key === 'Enter' && scan());
if (exportBtn) exportBtn.addEventListener('click', exportReport);
if (pdfBtn) pdfBtn.addEventListener('click', exportPDF);
if (htmlBtn) htmlBtn.addEventListener('click', exportHTML);
if (langEnBtn) langEnBtn.addEventListener('click', () => setLanguage('en'));
if (langZhBtn) langZhBtn.addEventListener('click', () => setLanguage('zh'));
if (themeToggle) themeToggle.addEventListener('click', toggleTheme);

setLanguage('en');
