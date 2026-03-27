// ==================== 配置 ====================
const API_BASE = 'https://myscan-henna.vercel.app'; // 替换为您的 Vercel 域名
const API_SCAN = `${API_BASE}/api/scan`;

// ==================== 国际化文本库 ====================
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
        infoButton: 'Info',
        close: 'Close',
        detailedTitle: 'Detailed Information',
        corsSafe: 'CORS policy is restrictive (good).',
        cmsUnknown: 'Unable to detect CMS.',
        // 修复建议映射
        remediation: {
            'X-Frame-Options': 'Missing this header may lead to clickjacking attacks. Recommended: `X-Frame-Options: SAMEORIGIN`',
            'X-Content-Type-Options': 'Missing this header may lead to MIME type confusion attacks. Recommended: `X-Content-Type-Options: nosniff`',
            'X-XSS-Protection': 'Missing this header may reduce browser XSS protection. Recommended: `X-XSS-Protection: 1; mode=block`',
            'Strict-Transport-Security': 'Missing HSTS may allow HTTPS downgrade. Recommended: `Strict-Transport-Security: max-age=31536000; includeSubDomains`',
            'Content-Security-Policy': 'Missing CSP may lead to XSS risks. Recommended to set a proper policy, e.g., `default-src \'self\'`',
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
        // 详细解说内容
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
        corsSafe: 'CORS 策略严格（良好）。',
        cmsUnknown: '无法识别 CMS。',
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
        },
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

function renderResult(data) {
    if (!resultContainer) return;
    resultContainer.innerHTML = '';
    errorContainer.style.display = 'none';
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
    // 免责声明卡片
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
    element.querySelectorAll('.copy-btn, .info-btn').forEach(btn => btn.remove());
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

async function scan() {
    let url = targetInput.value.trim();
    if (!url) {
        errorContainer.textContent = t('pleaseEnterUrl');
        errorContainer.style.display = 'block';
        return;
    }
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

function setLanguage(lang) {
    currentLang = lang;
    langEnBtn.classList.toggle('active', lang === 'en');
    langZhBtn.classList.toggle('active', lang === 'zh');
    if (window.lastScanData) renderResult(window.lastScanData);
    targetInput.placeholder = lang === 'en' ? 'https://example.com' : 'https://example.com';
    scanBtn.textContent = lang === 'en' ? 'Start Scan' : '开始扫描';
    exportBtn.textContent = t('export');
    pdfBtn.textContent = t('pdfExport');
    const loadingSpan = loadingDiv.querySelector('span');
    if (loadingSpan) loadingSpan.textContent = t('scanning');
}

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