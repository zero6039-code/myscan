// ==================== 配置 ====================
const API_BASE = 'https://myscan-henna.vercel.app'; // 替换为你的 Vercel 域名
const API_SCAN = `${API_BASE}/api/scan`;

// ==================== 国际化文本库（含所有修复建议） ====================
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
        directoryTraversal: 'Directory Traversal',
        httpMethods: 'HTTP Methods',
        infoLeakage: 'Information Leakage',
        csp: 'CSP Analysis',
        cors: 'CORS Configuration',
        cms: 'CMS Fingerprint',
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
        // 修复建议文本库
        remediation: {
            // 安全头
            'X-Frame-Options': 'Missing this header may lead to clickjacking attacks. Recommended: `X-Frame-Options: SAMEORIGIN`',
            'X-Content-Type-Options': 'Missing this header may lead to MIME type confusion attacks. Recommended: `X-Content-Type-Options: nosniff`',
            'X-XSS-Protection': 'Missing this header may reduce browser XSS protection. Recommended: `X-XSS-Protection: 1; mode=block`',
            'Strict-Transport-Security': 'Missing HSTS may allow HTTPS downgrade. Recommended: `Strict-Transport-Security: max-age=31536000; includeSubDomains`',
            'Content-Security-Policy': 'Missing CSP may lead to XSS risks. Recommended to set a proper policy, e.g., `default-src \'self\'`',
            // 敏感文件
            '/robots.txt': 'Exposes website directory structure. Recommend restricting sensitive paths or removing unnecessary information.',
            '/.env': 'Seriously exposes environment variables. Immediately delete or deny access.',
            '/.git/config': 'Exposes Git repository information. Delete or restrict access.',
            '/backup.zip': 'Backup file can be downloaded. Remove or set strong access control.',
            '/admin': 'Admin panel exposed. Recommend adding authentication or hiding the path.',
            '/phpinfo.php': 'Exposes PHP configuration. Delete this file.',
            // 通用漏洞
            xss: 'Reflected XSS can be exploited to execute malicious scripts. Recommend strict filtering and escaping of user input, and use Content Security Policy.',
            sql: 'SQL injection can lead to data leakage or tampering. Use parameterized queries, prepared statements, avoid SQL concatenation.',
            dirTraversal: 'Directory traversal vulnerability can read arbitrary files. Strictly restrict file paths and use whitelist validation.',
            httpMethods: (methods) => `Dangerous HTTP methods allowed: ${methods.join(', ')}. Recommend disabling unnecessary methods (e.g., PUT, DELETE, TRACE).`,
            infoLeakage: 'Response may contain sensitive information (emails, phone numbers, API keys). Review and remove such information.',
            cors: 'CORS misconfiguration may allow any origin to access resources. Restrict `Access-Control-Allow-Origin` to specific trusted domains.',
            cmsOutdated: 'CMS detected. Keep it updated to avoid known vulnerabilities.',
            cspUnsafeInline: 'CSP uses `unsafe-inline`, weakening XSS protection. Recommend using nonce or hash instead.',
            cspMissingDefaultSrc: 'CSP missing `default-src` directive. Recommend adding `default-src \'self\'`.'
        }
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
        directoryTraversal: '目录遍历',
        httpMethods: 'HTTP 方法',
        infoLeakage: '信息泄露',
        csp: 'CSP 策略分析',
        cors: 'CORS 配置',
        cms: 'CMS 指纹',
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
        remediation: {
            'X-Frame-Options': '缺少该头可能导致点击劫持攻击。建议添加: `X-Frame-Options: SAMEORIGIN`',
            'X-Content-Type-Options': '缺少该头可能导致 MIME 类型混淆攻击。建议添加: `X-Content-Type-Options: nosniff`',
            'X-XSS-Protection': '缺少该头可能降低浏览器 XSS 防护。建议添加: `X-XSS-Protection: 1; mode=block`',
            'Strict-Transport-Security': '缺少 HSTS 可能使 HTTPS 降级。建议添加: `Strict-Transport-Security: max-age=31536000; includeSubDomains`',
            'Content-Security-Policy': '缺少 CSP 可能导致 XSS 风险。建议设置合适的策略，如: `default-src \'self\'`',
            '/robots.txt': '暴露了网站目录结构。建议限制敏感路径或移除不必要信息。',
            '/.env': '严重泄露环境变量。立即删除或禁止访问。',
            '/.git/config': '泄露 Git 仓库信息。删除或限制访问。',
            '/backup.zip': '备份文件可被下载。移除或设置强访问控制。',
            '/admin': '管理后台暴露。建议添加身份验证或隐藏路径。',
            '/phpinfo.php': '泄露 PHP 配置信息。删除该文件。',
            xss: '反射型 XSS 可被利用执行恶意脚本。建议对用户输入进行严格过滤和转义，使用内容安全策略。',
            sql: 'SQL 注入可导致数据泄露或篡改。使用参数化查询、预编译语句，避免拼接 SQL。',
            dirTraversal: '目录遍历漏洞可读取任意文件。严格限制文件路径，使用白名单验证。',
            httpMethods: (methods) => `允许危险 HTTP 方法: ${methods.join(', ')}。建议禁用不必要的方法（如 PUT, DELETE, TRACE）。`,
            infoLeakage: '响应中可能包含敏感信息（邮箱、手机号、API 密钥）。审查并移除这些信息。',
            cors: 'CORS 配置错误，允许任意来源访问资源。应将 `Access-Control-Allow-Origin` 限制为特定受信任域名。',
            cmsOutdated: '检测到 CMS。请保持其更新以避免已知漏洞。',
            cspUnsafeInline: 'CSP 中使用了 unsafe-inline，降低了 XSS 防护强度。建议使用 nonce 或 hash 替代。',
            cspMissingDefaultSrc: 'CSP 缺少 default-src 指令，可能导致策略不完整。建议添加 default-src \'self\'。'
        }
    }
};

let currentLang = 'en';
let scanStartTime = null;
let currentTheme = 'light';

// DOM 元素
const targetInput = document.getElementById('target');
const scanBtn = document.getElementById('scan-btn');
const resultContainer = document.getElementById('result-container');
const errorContainer = document.getElementById('error-container');
const loadingDiv = document.getElementById('loading');
const exportContainer = document.getElementById('export-container');
const exportBtn = document.getElementById('export-btn');
const pdfBtn = document.getElementById('pdf-btn');
const langEnBtn = document.getElementById('lang-en');
const langZhBtn = document.getElementById('lang-zh');
const themeToggle = document.getElementById('theme-toggle');
const scanTimeDiv = document.getElementById('scan-time');

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
        <div class="card-header">
            📋 ${escapeHtml(title)}
            <button class="copy-btn" data-copy="${escapeHtml(contentHtml).replace(/"/g, '&quot;')}">${t('copy')}</button>
        </div>
        <div class="card-body">${contentHtml}</div>
    `;
    const copyBtn = card.querySelector('.copy-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', (e) => {
            const textToCopy = copyBtn.dataset.copy.replace(/<br>/g, '\n').replace(/<[^>]*>/g, '');
            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalText = copyBtn.textContent;
                copyBtn.textContent = t('copied');
                setTimeout(() => copyBtn.textContent = originalText, 1500);
            });
        });
    }
    return card;
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

// 获取修复建议文本（支持函数和字符串）
function getRemediationText(category, detail = null) {
    const rem = i18n[currentLang].remediation;
    if (!rem) return '';
    if (category === 'missingHeaders') {
        return rem[detail] || '';
    }
    if (category === 'sensitiveFiles') {
        return rem[detail] || '';
    }
    if (category === 'xss') {
        return rem.xss || '';
    }
    if (category === 'sql') {
        return rem.sql || '';
    }
    if (category === 'dirTraversal') {
        return rem.dirTraversal || '';
    }
    if (category === 'httpMethods') {
        return typeof rem.httpMethods === 'function' ? rem.httpMethods(detail) : rem.httpMethods || '';
    }
    if (category === 'infoLeakage') {
        return rem.infoLeakage || '';
    }
    if (category === 'cors') {
        return rem.cors || '';
    }
    if (category === 'cspUnsafeInline') {
        return rem.cspUnsafeInline || '';
    }
    if (category === 'cspMissingDefaultSrc') {
        return rem.cspMissingDefaultSrc || '';
    }
    if (category === 'cms') {
        return rem.cmsOutdated || '';
    }
    return '';
}

// 渲染扫描结果
function renderResult(data) {
    if (!resultContainer) return;
    resultContainer.innerHTML = '';
    errorContainer.style.display = 'none';

    // 显示耗时
    if (scanStartTime) {
        const elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(2);
        scanTimeDiv.textContent = t('scanTime').replace('{time}', elapsed);
        scanTimeDiv.style.display = 'block';
    }

    // 基础信息卡片
    const basicCard = createCard(t('basicInfo'), `
        <div class="info-row"><span class="info-label">${t('urlLabel')}:</span><span class="info-value">${escapeHtml(data.url)}</span></div>
        <div class="info-row"><span class="info-label">${t('statusLabel')}:</span><span class="info-value">${data.basic?.status || '?'}</span></div>
        <div class="info-row"><span class="info-label">${t('titleLabel')}:</span><span class="info-value">${escapeHtml(data.basic?.title || '')}</span></div>
        <div class="info-row"><span class="info-label">${t('headersLabel')}:</span><span class="info-value"><pre>${escapeHtml(JSON.stringify(data.basic?.headers || {}, null, 2))}</pre></span></div>
    `);

    // 安全头部卡片
    const missing = data.security?.missingHeaders || [];
    let securityHtml = '';
    if (missing.length === 0) {
        securityHtml = `<div class="info-value">${t('noMissingHeaders')}</div>`;
    } else {
        securityHtml = `<div class="info-value">${missing.map(h => `<span class="badge">${escapeHtml(h)}</span>`).join('')}</div>`;
        securityHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong><br>${missing.map(h => `• ${escapeHtml(h)}: ${getRemediationText('missingHeaders', h)}`).join('<br>')}</div>`;
    }
    const securityCard = createCard(t('securityHeaders'), securityHtml);

    // 敏感文件卡片
    const sensitive = data.sensitiveFiles || [];
    let sensitiveHtml = '';
    if (sensitive.length === 0) {
        sensitiveHtml = `<div class="info-value">${t('noSensitiveFiles')}</div>`;
    } else {
        sensitiveHtml = `<div class="info-value">${sensitive.map(f => `<span class="badge vuln-badge">${escapeHtml(f)}</span>`).join('')}</div>`;
        sensitiveHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong><br>${sensitive.map(f => `• ${escapeHtml(f)}: ${getRemediationText('sensitiveFiles', f)}`).join('<br>')}</div>`;
    }
    const sensitiveCard = createCard(t('sensitiveFiles'), sensitiveHtml);

    // XSS 卡片
    let xssHtml = '';
    if (data.xss?.vulnerable) {
        xssHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.xss.param)}<br>URL: ${escapeHtml(data.xss.url)}</div>`;
        xssHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('xss')}</div>`;
    } else {
        xssHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noXss')}</div>`;
    }
    const xssCard = createCard(t('xss'), xssHtml);

    // SQL 注入卡片
    let sqlHtml = '';
    if (data.sqlInjection?.vulnerable) {
        sqlHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.sqlInjection.param)}<br>URL: ${escapeHtml(data.sqlInjection.url)}${data.sqlInjection.note ? `<br>${t('note')}: ${escapeHtml(data.sqlInjection.note)}` : ''}</div>`;
        sqlHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('sql')}</div>`;
    } else {
        sqlHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noSql')}</div>`;
    }
    const sqlCard = createCard(t('sql'), sqlHtml);

    // 目录遍历卡片
    let dirHtml = '';
    if (data.directoryTraversal?.vulnerable) {
        dirHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.directoryTraversal.param)}<br>Payload: ${escapeHtml(data.directoryTraversal.payload)}</div>`;
        dirHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('dirTraversal')}</div>`;
    } else {
        dirHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('dirTraversalNone')}</div>`;
    }
    const dirCard = createCard(t('directoryTraversal'), dirHtml);

    // HTTP 方法卡片
    const allowed = data.httpMethods?.allowed || [];
    let httpHtml = '';
    if (allowed.length > 0) {
        httpHtml = `<div class="info-value"><span class="badge vuln-badge">${t('dangerousMethods')}</span> ${allowed.join(', ')}</div>`;
        httpHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('httpMethods', allowed)}</div>`;
    } else {
        httpHtml = `<div class="info-value"><span class="badge safe-badge">${t('noDangerousMethods')}</span></div>`;
    }
    const httpCard = createCard(t('httpMethods'), httpHtml);

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
    const infoCard = createCard(t('infoLeakage'), infoHtml);

    // CORS 卡片
    let corsHtml = '';
    if (data.cors?.vulnerable) {
        corsHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${data.cors.details}</div>`;
        corsHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cors')}</div>`;
    } else {
        corsHtml = `<div class="info-value"><span class="badge safe-badge">${t('corsSafe')}</span> ${data.cors?.details || ''}</div>`;
    }
    const corsCard = createCard(t('cors'), corsHtml);

    // CMS 卡片
    let cmsHtml = '';
    if (data.cms?.detected) {
        cmsHtml = `<div class="info-value">Detected CMS: <strong>${escapeHtml(data.cms.name)}</strong> ${data.cms.version ? `(v${data.cms.version})` : ''}</div>`;
        cmsHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cms')}</div>`;
    } else {
        cmsHtml = `<div class="info-value">${t('cmsUnknown')}</div>`;
    }
    const cmsCard = createCard(t('cms'), cmsHtml);

    // CSP 卡片
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
        cspCard = createCard(t('csp'), cspHtml);
    }

    // 免责声明卡片
    const disclaimerCard = createCard('', `<div style="font-size:14px;">${t('disclaimer')}</div>`, 'disclaimer-card');
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
    element.querySelectorAll('.copy-btn').forEach(btn => btn.remove());
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

// 扫描函数
async function scan() {
    let url = targetInput.value.trim();
    if (!url) {
        errorContainer.textContent = t('pleaseEnterUrl');
        errorContainer.style.display = 'block';
        return;
    }
    // 智能添加协议
    if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
        targetInput.value = url;
    }

    scanBtn.disabled = true;
    scanBtn.textContent = t('scanning');
    loadingDiv.style.display = 'block';
    resultContainer.style.display = 'none';
    errorContainer.style.display = 'none';
    exportContainer.style.display = 'none';
    scanTimeDiv.style.display = 'none';

    scanStartTime = Date.now();

    try {
        const data = await safeFetchJson(API_SCAN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        renderResult(data);
    } catch (err) {
        errorContainer.textContent = t('errorPrefix') + err.message;
        errorContainer.style.display = 'block';
    } finally {
        loadingDiv.style.display = 'none';
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
    loadingDiv.querySelector('span').textContent = t('scanning');
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
if (langEnBtn) langEnBtn.addEventListener('click', () => setLanguage('en'));
if (langZhBtn) langZhBtn.addEventListener('click', () => setLanguage('zh'));
if (themeToggle) themeToggle.addEventListener('click', toggleTheme);

setLanguage('en');