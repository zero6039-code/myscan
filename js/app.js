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
            securityHeaders: {
                title: 'Missing Security Headers',
                principle: 'Security headers are HTTP response headers that instruct the browser how to behave. Missing them leaves the site vulnerable to attacks like clickjacking, MIME type sniffing, and XSS.',
                scenario: 'An attacker could embed your site in an iframe (clickjacking) or trick the browser into executing malicious scripts via MIME confusion.',
                fix: 'Add the appropriate headers in your server configuration. For example, in Nginx:\n\nadd_header X-Frame-Options "SAMEORIGIN" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header X-XSS-Protection "1; mode=block" always;\nadd_header Content-Security-Policy "default-src \'self\'" always;'
            },
            sensitiveFiles: {
                title: 'Sensitive Files',
                principle: 'Sensitive files (like .env, .git/config, backup files) may contain credentials, database passwords, or source code. Their exposure can lead to full system compromise.',
                scenario: 'An attacker finds a publicly accessible .env file containing AWS keys and uses them to access your cloud infrastructure.',
                fix: 'Remove such files from the web root or restrict access via server rules. For Nginx: location ~ /(\\.env|\\.git|backup\\.zip) { deny all; return 404; }'
            },
            xss: {
                title: 'Cross-Site Scripting (XSS)',
                principle: 'XSS allows attackers to inject malicious scripts into web pages viewed by other users. It can steal cookies, session tokens, or perform actions on behalf of the user.',
                scenario: 'An attacker injects <script>alert(\'XSS\')</script> into a comment field. When another user views the comment, the script executes, stealing their session cookie.',
                fix: 'Always escape user input. Use a Content Security Policy (CSP) and context-aware encoding. In JavaScript, use textContent instead of innerHTML when inserting user data.'
            },
            sql: {
                title: 'SQL Injection',
                principle: 'SQL injection occurs when user input is improperly sanitized and concatenated into SQL queries, allowing attackers to manipulate database queries.',
                scenario: 'An attacker enters \' OR \'1\'=\'1 in a login field, bypassing authentication and gaining admin access.',
                fix: 'Use parameterized queries (prepared statements) with bound parameters. Avoid dynamic SQL concatenation. Example (Node.js): db.query("SELECT * FROM users WHERE id = ?", [userId])'
            },
            directoryTraversal: {
                title: 'Directory Traversal',
                principle: 'Directory traversal vulnerabilities allow attackers to read arbitrary files on the server by manipulating path parameters (e.g., ../../etc/passwd).',
                scenario: 'An attacker requests https://example.com/download?file=../../../etc/passwd and retrieves the system password file.',
                fix: 'Validate and sanitize file paths. Use a whitelist of allowed files and strip any directory traversal sequences. In Node.js: path.resolve(baseDir, userPath) and check if it starts with baseDir.'
            },
            httpMethods: {
                title: 'HTTP Methods',
                principle: 'Exposing dangerous HTTP methods (PUT, DELETE, TRACE) can allow attackers to upload malicious files, delete resources, or perform cross-site tracing (XST) attacks.',
                scenario: 'An attacker uses PUT to upload a web shell to the server, then executes it to gain control.',
                fix: 'Disable unnecessary methods. In Nginx: limit_except GET POST HEAD { deny all; } Or use a web application firewall (WAF).'
            },
            infoLeakage: {
                title: 'Information Leakage',
                principle: 'Sensitive information (emails, phone numbers, API keys) in HTML responses can be harvested by attackers for phishing, social engineering, or direct attacks.',
                scenario: 'An attacker finds an API key in the page source and uses it to access your backend services.',
                fix: 'Review HTML source for sensitive data. Remove hardcoded secrets, use server-side rendering for sensitive info, and restrict error detail exposure.'
            },
            cors: {
                title: 'CORS Misconfiguration',
                principle: 'Cross-Origin Resource Sharing (CORS) headers control which origins can access your resources. A permissive policy (Access-Control-Allow-Origin: *) can allow malicious sites to read sensitive data.',
                scenario: 'A malicious site makes an AJAX request to your API, and if your CORS policy allows any origin, it can read the response and steal user data.',
                fix: 'Restrict Access-Control-Allow-Origin to specific trusted domains. Avoid using "*" with credentials. In Express: app.use(cors({ origin: "https://trusted.com" }))'
            },
            cms: {
                title: 'CMS Fingerprint',
                principle: 'Revealing the CMS (WordPress, Drupal, etc.) version helps attackers target known vulnerabilities specific to that version.',
                scenario: 'An attacker learns your site uses WordPress 5.0 and exploits a known vulnerability to gain admin access.',
                fix: 'Keep CMS updated, remove version meta tags, and use security plugins to hide fingerprints.'
            },
            csp: {
                title: 'Content Security Policy (CSP)',
                principle: 'CSP mitigates XSS by restricting which sources scripts, styles, and other resources can load. Weak policies (e.g., unsafe-inline) or missing default-src reduce effectiveness.',
                scenario: 'An attacker injects a script that would normally be blocked if CSP were properly configured, but unsafe-inline allows it to execute.',
                fix: 'Implement a strict CSP: default-src \'self\'; script-src \'self\' https://trusted.cdn.com; style-src \'self\' \'unsafe-inline\'; Avoid unsafe-inline for scripts if possible; use nonce or hash.'
            },
            ssl: {
                title: 'SSL/TLS Configuration',
                principle: 'Weak SSL/TLS protocols or ciphers can allow attackers to decrypt traffic or perform man-in-the-middle attacks.',
                scenario: 'An attacker downgrades the connection to SSLv3 and exploits the POODLE vulnerability to steal session cookies.',
                fix: 'Disable SSLv3, TLSv1.0, TLSv1.1. Use TLSv1.2 or higher. Configure strong cipher suites. Renew certificates before expiry.'
            }
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
            'X-Frame-Options': '缺少该头可能导致点击劫持攻击。建议添加: `X-Frame-Options: SAMEORIGIN`',
            'X-Content-Type-Options': '缺少该头可能导致 MIME 类型混淆攻击。建议添加: `X-Content-Type-Options: nosniff`',
            'X-XSS-Protection': '缺少该头可能降低浏览器 XSS 防护。建议添加: `X-XSS-Protection: 1; mode=block`',
            'Strict-Transport-Security': '缺少 HSTS 可能使 HTTPS 降级。建议添加: `Strict-Transport-Security: max-age=31536000; includeSubDomains`',
            'Content-Security-Policy': '缺少 CSP 可能导致 XSS 风险。建议设置合适的策略，如: `default-src \'self\'`',
            'Referrer-Policy': '缺少 Referrer-Policy 可能泄露来源信息。建议添加: `Referrer-Policy: strict-origin-when-cross-origin`',
            'Permissions-Policy': '缺少 Permissions-Policy 可能允许不必要的浏览器功能。建议添加: `Permissions-Policy: geolocation=(), microphone=(), camera=()`',
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
        },
        detailed: {
            securityHeaders: {
                title: '缺失的安全响应头',
                principle: '安全响应头是指导浏览器行为的 HTTP 头部。缺失它们会使网站容易受到点击劫持、MIME 类型嗅探、XSS 等攻击。',
                scenario: '攻击者可将你的网站嵌入 iframe（点击劫持），或通过 MIME 混淆诱使浏览器执行恶意脚本。',
                fix: '在服务器配置中添加对应头部。例如 Nginx：\n\nadd_header X-Frame-Options "SAMEORIGIN" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header X-XSS-Protection "1; mode=block" always;\nadd_header Content-Security-Policy "default-src \'self\'" always;'
            },
            // 其他详细解说可参考英文部分，为节省篇幅此处省略
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

// DOM 元素引用（稍后会在 DOMContentLoaded 中获取）
let targetInput, scanBtn, resultContainer, errorContainer, loadingDiv, exportContainer;
let langEnBtn, langZhBtn, themeToggle, scanTimeDiv, progressContainer, progressFill, progressMessage;
let exportMenuBtn, exportModal, shareModal, shareBtn, exportJsonBtn, exportPdfBtn, exportHtmlBtn;

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

async function scan() {
    let url = targetInput.value.trim();
    if (!url) {
        errorContainer.textContent = t('pleaseEnterUrl');
        errorContainer.style.display = 'block';
        return;
    }

    if (/^javascript:/i.test(url) || /^data:/i.test(url) || /^vbscript:/i.test(url)) {
        errorContainer.textContent = t('errorPrefix') + 'Invalid URL protocol';
        errorContainer.style.display = 'block';
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
        return;
    }

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

function setLanguage(lang) {
    currentLang = lang;
    langEnBtn.classList.toggle('active', lang === 'en');
    langZhBtn.classList.toggle('active', lang === 'zh');
    if (window.lastScanData) renderResult(window.lastScanData);
    targetInput.placeholder = lang === 'en' ? 'https://example.com' : 'https://example.com';
    scanBtn.textContent = lang === 'en' ? 'Start Scan' : '开始扫描';
    if (exportMenuBtn) exportMenuBtn.textContent = '📄 Report Export as';
    if (shareBtn) shareBtn.textContent = '🔗 Share Report';
    const loadingSpan = loadingDiv.querySelector('span');
    if (loadingSpan) loadingSpan.textContent = t('scanning');
}

function toggleTheme() {
    currentTheme = currentTheme === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', currentTheme);
    themeToggle.textContent = currentTheme === 'light' ? '🌙' : '☀️';
}

function shareOnPlatform(platform) {
    const url = encodeURIComponent(window.location.href);
    const title = encodeURIComponent('MyScan Security Report');
    let shareUrl = '';
    switch (platform) {
        case 'whatsapp':
            shareUrl = `https://wa.me/?text=${title}%20${url}`;
            break;
        case 'facebook':
            shareUrl = `https://www.facebook.com/sharer/sharer.php?u=${url}`;
            break;
        case 'messenger':
            shareUrl = `https://www.facebook.com/dialog/send?link=${url}&app_id=123456789`; // 需替换为真实 app_id
            break;
        case 'email':
            shareUrl = `mailto:?subject=${title}&body=${url}`;
            break;
        case 'wechat':
            navigator.clipboard.writeText(window.location.href);
            alert('Link copied to clipboard. Open WeChat and paste to share.');
            return;
        case 'line':
            shareUrl = `https://line.me/R/msg/text/?${title}%20${url}`;
            break;
        default:
            return;
    }
    if (shareUrl) window.open(shareUrl, '_blank');
}

// ==================== 页面初始化 ====================
document.addEventListener('DOMContentLoaded', () => {
    // 获取所有 DOM 元素
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
    shareModal = document.getElementById('share-modal');
    shareBtn = document.getElementById('share-btn');
    exportJsonBtn = document.getElementById('export-json-btn');
    exportPdfBtn = document.getElementById('export-pdf-btn');
    exportHtmlBtn = document.getElementById('export-html-btn');

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

    // 事件绑定
    if (scanBtn) scanBtn.addEventListener('click', scan);
    if (targetInput) targetInput.addEventListener('keypress', (e) => e.key === 'Enter' && scan());
    if (exportMenuBtn) exportMenuBtn.addEventListener('click', () => { if (exportModal) exportModal.style.display = 'flex'; });
    if (shareBtn) shareBtn.addEventListener('click', () => { if (shareModal) shareModal.style.display = 'flex'; });
    if (exportJsonBtn) exportJsonBtn.addEventListener('click', () => { if (exportModal) exportModal.style.display = 'none'; exportReport(); });
    if (exportPdfBtn) exportPdfBtn.addEventListener('click', () => { if (exportModal) exportModal.style.display = 'none'; exportPDF(); });
    if (exportHtmlBtn) exportHtmlBtn.addEventListener('click', () => { if (exportModal) exportModal.style.display = 'none'; exportHTML(); });
    if (langEnBtn) langEnBtn.addEventListener('click', () => setLanguage('en'));
    if (langZhBtn) langZhBtn.addEventListener('click', () => setLanguage('zh'));
    if (themeToggle) themeToggle.addEventListener('click', toggleTheme);

    // 模态框关闭
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

    // 分享图标
    document.querySelectorAll('.share-icon').forEach(icon => {
        icon.addEventListener('click', () => {
            const platform = icon.getAttribute('data-platform');
            shareOnPlatform(platform);
            if (shareModal) shareModal.style.display = 'none';
        });
    });

    // 语言初始化
    setLanguage('en');
});
