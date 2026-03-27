// ==================== 配置 ====================
const API_BASE = 'https://myscan-henna.vercel.app'; // 替换为您的 Vercel 域名
const API_SCAN = `${API_BASE}/api/scan`;

// ==================== 国际化文本库（含修复建议和详细解说） ====================
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
        // 详细解说（新增）
        infoButton: 'Info',
        close: 'Close',
        detailedTitle: 'Detailed Information',
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
            }
        }
    },
    zh: {
        // 中文字段与英文类似，此处为节省篇幅，请确保与英文结构对应，提供中文详细解说。
        // 实际部署时需包含所有字段的中文翻译。下面给出简要示例，请根据需求补充完整。
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
        infoButton: '详解',
        close: '关闭',
        detailedTitle: '详细说明',
        detailed: {
            securityHeaders: {
                title: '缺失的安全响应头',
                principle: '安全响应头是指导浏览器行为的 HTTP 头部。缺失它们会使网站容易受到点击劫持、MIME 类型嗅探、XSS 等攻击。',
                scenario: '攻击者可将你的网站嵌入 iframe（点击劫持），或通过 MIME 混淆诱使浏览器执行恶意脚本。',
                fix: '在服务器配置中添加对应头部。例如 Nginx：\n\nadd_header X-Frame-Options "SAMEORIGIN" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header X-XSS-Protection "1; mode=block" always;\nadd_header Content-Security-Policy "default-src \'self\'" always;'
            },
            sensitiveFiles: {
                title: '敏感文件',
                principle: '敏感文件（如 .env、.git/config、备份文件）可能包含凭证、数据库密码或源码。暴露它们可导致系统完全失陷。',
                scenario: '攻击者找到公开的 .env 文件，获取 AWS 密钥，进而控制云基础设施。',
                fix: '从 Web 根目录移除此类文件，或通过服务器规则限制访问。例如 Nginx：location ~ /(\\.env|\\.git|backup\\.zip) { deny all; return 404; }'
            },
            xss: {
                title: '跨站脚本 (XSS)',
                principle: 'XSS 允许攻击者向其他用户查看的网页注入恶意脚本。可窃取 Cookie、会话令牌或代表用户执行操作。',
                scenario: '攻击者在评论框中注入 <script>alert(\'XSS\')</script>，其他用户查看评论时脚本执行，窃取其会话 Cookie。',
                fix: '始终转义用户输入。使用内容安全策略（CSP）和上下文感知编码。在 JavaScript 中，插入用户数据时使用 textContent 而非 innerHTML。'
            },
            sql: {
                title: 'SQL 注入',
                principle: 'SQL 注入发生在用户输入未正确清理并拼接到 SQL 查询时，攻击者可操纵数据库查询。',
                scenario: '攻击者在登录框输入 \' OR \'1\'=\'1，绕过认证获得管理员权限。',
                fix: '使用参数化查询（预编译语句）绑定参数。避免动态拼接 SQL。例如 (Node.js)：db.query("SELECT * FROM users WHERE id = ?", [userId])'
            },
            directoryTraversal: {
                title: '目录遍历',
                principle: '目录遍历漏洞允许攻击者通过操控路径参数（如 ../../etc/passwd）读取服务器上的任意文件。',
                scenario: '攻击者请求 https://example.com/download?file=../../../etc/passwd，获取系统密码文件。',
                fix: '验证和清理文件路径。使用允许文件白名单，并去除任何目录遍历序列。在 Node.js 中：path.resolve(baseDir, userPath) 并检查是否以 baseDir 开头。'
            },
            httpMethods: {
                title: 'HTTP 方法',
                principle: '暴露危险 HTTP 方法（PUT、DELETE、TRACE）可允许攻击者上传恶意文件、删除资源或进行跨站追踪（XST）攻击。',
                scenario: '攻击者使用 PUT 上传 Webshell 到服务器，然后执行它获得控制权。',
                fix: '禁用不必要的方法。Nginx 中：limit_except GET POST HEAD { deny all; } 或使用 Web 应用防火墙（WAF）。'
            },
            infoLeakage: {
                title: '信息泄露',
                principle: 'HTML 响应中的敏感信息（邮箱、电话、API 密钥）可被攻击者收集用于钓鱼、社会工程学或直接攻击。',
                scenario: '攻击者在页面源码中发现 API 密钥，用于访问你的后端服务。',
                fix: '检查 HTML 源码中是否包含敏感数据。移除硬编码密钥，对敏感信息使用服务端渲染，并限制错误详情暴露。'
            },
            cors: {
                title: 'CORS 配置错误',
                principle: '跨域资源共享（CORS）头控制哪些源可以访问你的资源。宽松策略（Access-Control-Allow-Origin: *）可允许恶意站点读取敏感数据。',
                scenario: '恶意站点向你的 API 发起 AJAX 请求，若 CORS 策略允许任意源，则能读取响应并窃取用户数据。',
                fix: '将 Access-Control-Allow-Origin 限制为特定受信任域名。避免与凭证一起使用 "*"。在 Express 中：app.use(cors({ origin: "https://trusted.com" }))'
            },
            cms: {
                title: 'CMS 指纹',
                principle: '暴露 CMS（WordPress、Drupal 等）版本可帮助攻击者针对特定版本已知漏洞进行攻击。',
                scenario: '攻击者得知你使用 WordPress 5.0，利用已知漏洞获取管理员权限。',
                fix: '保持 CMS 更新，移除版本元标签，使用安全插件隐藏指纹。'
            },
            csp: {
                title: '内容安全策略 (CSP)',
                principle: 'CSP 通过限制脚本、样式等资源加载源来缓解 XSS。弱策略（如 unsafe-inline）或缺失 default-src 会降低有效性。',
                scenario: '攻击者注入脚本，若 CSP 配置不当（允许 unsafe-inline），脚本可执行。',
                fix: '实施严格 CSP：default-src \'self\'; script-src \'self\' https://trusted.cdn.com; style-src \'self\' \'unsafe-inline\'; 尽可能避免脚本使用 unsafe-inline，改用 nonce 或 hash。'
            }
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

// 创建模态框并显示详细解说
function showDetailedInfo(vulnerabilityType, title) {
    // 获取当前语言的详细数据
    const details = i18n[currentLang].detailed?.[vulnerabilityType];
    if (!details) {
        console.warn('No detailed info for', vulnerabilityType);
        return;
    }

    // 构建模态框内容
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>${escapeHtml(t('detailedTitle'))}: ${escapeHtml(title)}</h3>
                <span class="modal-close">&times;</span>
            </div>
            <div class="modal-body">
                <h4>🔍 Attack Principle</h4>
                <p>${escapeHtml(details.principle)}</p>
                <h4>⚠️ Attack Scenario</h4>
                <p>${escapeHtml(details.scenario)}</p>
                <h4>🛠️ Remediation</h4>
                <pre>${escapeHtml(details.fix)}</pre>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
    modal.style.display = 'flex';

    // 关闭模态框
    const closeSpan = modal.querySelector('.modal-close');
    closeSpan.onclick = () => modal.remove();
    window.onclick = (event) => {
        if (event.target === modal) modal.remove();
    };
}

// 修改 createCard 函数，增加解说按钮
function createCard(title, contentHtml, extraClass = '', vulnerabilityType = null) {
    const card = document.createElement('div');
    card.className = `result-card ${extraClass}`;
    const copyBtnHtml = `<button class="copy-btn" data-copy="${escapeHtml(contentHtml).replace(/"/g, '&quot;')}">${t('copy')}</button>`;
    const infoBtnHtml = vulnerabilityType ? `<button class="info-btn" data-type="${vulnerabilityType}" data-title="${escapeHtml(title)}">${t('infoButton')}</button>` : '';
    card.innerHTML = `
        <div class="card-header">
            📋 ${escapeHtml(title)}
            <div class="card-actions">
                ${infoBtnHtml}
                ${copyBtnHtml}
            </div>
        </div>
        <div class="card-body">${contentHtml}</div>
    `;

    // 复制按钮逻辑
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

    // 解说按钮逻辑
    const infoBtn = card.querySelector('.info-btn');
    if (infoBtn) {
        infoBtn.addEventListener('click', () => {
            const type = infoBtn.dataset.type;
            const cardTitle = infoBtn.dataset.title;
            showDetailedInfo(type, cardTitle);
        });
    }

    return card;
}

// 安全头部卡片 -> vulnerabilityType: 'securityHeaders'
// 敏感文件卡片 -> 'sensitiveFiles'（但需要细分？我们可以统一使用 'sensitiveFiles'）
// XSS -> 'xss', SQL -> 'sql', 目录遍历 -> 'directoryTraversal', HTTP方法 -> 'httpMethods', 信息泄露 -> 'infoLeakage', CORS -> 'cors', CMS -> 'cms', CSP -> 'csp'

async function safeFetchJson(url, options) { /* 同前 */ }

// 渲染扫描结果（需要适配新的 createCard 调用）
function renderResult(data) {
    if (!resultContainer) return;
    resultContainer.innerHTML = '';
    errorContainer.style.display = 'none';

    if (scanStartTime) {
        const elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(2);
        scanTimeDiv.textContent = t('scanTime').replace('{time}', elapsed);
        scanTimeDiv.style.display = 'block';
    }

    // 基础信息卡片（无详细解说）
    const basicCard = createCard(t('basicInfo'), `
        <div class="info-row"><span class="info-label">${t('urlLabel')}:</span><span class="info-value">${escapeHtml(data.url)}</span></div>
        <div class="info-row"><span class="info-label">${t('statusLabel')}:</span><span class="info-value">${data.basic?.status || '?'}</span></div>
        <div class="info-row"><span class="info-label">${t('titleLabel')}:</span><span class="info-value">${escapeHtml(data.basic?.title || '')}</span></div>
        <div class="info-row"><span class="info-label">${t('headersLabel')}:</span><span class="info-value"><pre>${escapeHtml(JSON.stringify(data.basic?.headers || {}, null, 2))}</pre></span></div>
    `, '', null);

    // 安全头部卡片
    const missing = data.security?.missingHeaders || [];
    let securityHtml = '';
    if (missing.length === 0) {
        securityHtml = `<div class="info-value">${t('noMissingHeaders')}</div>`;
    } else {
        securityHtml = `<div class="info-value">${missing.map(h => `<span class="badge">${escapeHtml(h)}</span>`).join('')}</div>`;
        securityHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong><br>${missing.map(h => `• ${escapeHtml(h)}: ${getRemediationText('missingHeaders', h)}`).join('<br>')}</div>`;
    }
    const securityCard = createCard(t('securityHeaders'), securityHtml, '', 'securityHeaders');

    // 敏感文件卡片
    const sensitive = data.sensitiveFiles || [];
    let sensitiveHtml = '';
    if (sensitive.length === 0) {
        sensitiveHtml = `<div class="info-value">${t('noSensitiveFiles')}</div>`;
    } else {
        sensitiveHtml = `<div class="info-value">${sensitive.map(f => `<span class="badge vuln-badge">${escapeHtml(f)}</span>`).join('')}</div>`;
        sensitiveHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong><br>${sensitive.map(f => `• ${escapeHtml(f)}: ${getRemediationText('sensitiveFiles', f)}`).join('<br>')}</div>`;
    }
    const sensitiveCard = createCard(t('sensitiveFiles'), sensitiveHtml, '', 'sensitiveFiles');

    // XSS 卡片
    let xssHtml = '';
    if (data.xss?.vulnerable) {
        xssHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.xss.param)}<br>URL: ${escapeHtml(data.xss.url)}</div>`;
        xssHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('xss')}</div>`;
    } else {
        xssHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noXss')}</div>`;
    }
    const xssCard = createCard(t('xss'), xssHtml, '', 'xss');

    // SQL 注入卡片
    let sqlHtml = '';
    if (data.sqlInjection?.vulnerable) {
        sqlHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.sqlInjection.param)}<br>URL: ${escapeHtml(data.sqlInjection.url)}${data.sqlInjection.note ? `<br>${t('note')}: ${escapeHtml(data.sqlInjection.note)}` : ''}</div>`;
        sqlHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('sql')}</div>`;
    } else {
        sqlHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noSql')}</div>`;
    }
    const sqlCard = createCard(t('sql'), sqlHtml, '', 'sql');

    // 目录遍历卡片
    let dirHtml = '';
    if (data.directoryTraversal?.vulnerable) {
        dirHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.directoryTraversal.param)}<br>Payload: ${escapeHtml(data.directoryTraversal.payload)}</div>`;
        dirHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('dirTraversal')}</div>`;
    } else {
        dirHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('dirTraversalNone')}</div>`;
    }
    const dirCard = createCard(t('directoryTraversal'), dirHtml, '', 'directoryTraversal');

    // HTTP 方法卡片
    const allowed = data.httpMethods?.allowed || [];
    let httpHtml = '';
    if (allowed.length > 0) {
        httpHtml = `<div class="info-value"><span class="badge vuln-badge">${t('dangerousMethods')}</span> ${allowed.join(', ')}</div>`;
        httpHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('httpMethods', allowed)}</div>`;
    } else {
        httpHtml = `<div class="info-value"><span class="badge safe-badge">${t('noDangerousMethods')}</span></div>`;
    }
    const httpCard = createCard(t('httpMethods'), httpHtml, '', 'httpMethods');

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
    const infoCard = createCard(t('infoLeakage'), infoHtml, '', 'infoLeakage');

    // CORS 卡片
    let corsHtml = '';
    if (data.cors?.vulnerable) {
        corsHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${data.cors.details}</div>`;
        corsHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cors')}</div>`;
    } else {
        corsHtml = `<div class="info-value"><span class="badge safe-badge">${t('corsSafe')}</span> ${data.cors?.details || ''}</div>`;
    }
    const corsCard = createCard(t('cors'), corsHtml, '', 'cors');

    // CMS 卡片
    let cmsHtml = '';
    if (data.cms?.detected) {
        cmsHtml = `<div class="info-value">Detected CMS: <strong>${escapeHtml(data.cms.name)}</strong> ${data.cms.version ? `(v${data.cms.version})` : ''}</div>`;
        cmsHtml += `<div class="remediation-box"><strong>🔧 ${t('remediationTitle')}：</strong> ${getRemediationText('cms')}</div>`;
    } else {
        cmsHtml = `<div class="info-value">${t('cmsUnknown')}</div>`;
    }
    const cmsCard = createCard(t('cms'), cmsHtml, '', 'cms');

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
        cspCard = createCard(t('csp'), cspHtml, '', 'csp');
    }

    // 免责声明卡片（无解说）
    const disclaimerCard = createCard('', `<div style="font-size:14px;">${t('disclaimer')}</div>`, 'disclaimer-card', null);
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

// 导出 JSON, PDF, scan, setLanguage, toggleTheme 等函数与之前相同，此处省略重复部分...
// 请确保这些函数完整包含在最终文件中（参考之前的完整版本）。

// 注意：getRemediationText 函数需要保留（用于修复建议），此处不重复。

// 事件绑定等（与之前相同）