const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');

// 读取外部规则文件
let rules = null;
try {
    const rulesPath = path.join(__dirname, '..', 'rules.json');
    const rulesContent = fs.readFileSync(rulesPath, 'utf8');
    rules = JSON.parse(rulesContent);
} catch (err) {
    console.error('读取 rules.json 失败，使用默认规则:', err.message);
    rules = {
        sensitivePaths: ['/robots.txt', '/.env', '/.git/config', '/backup.zip', '/admin', '/phpinfo.php'],
        xssParams: ['q', 's', 'id', 'search', 'query'],
        sqlParams: ['id', 'page', 'user'],
        securityHeaders: ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Strict-Transport-Security', 'Content-Security-Policy']
    };
}

// 增强的 axios 实例（模拟浏览器、忽略证书）
const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 8000,
    headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://www.google.com/'
    }
});

// 手动限流（最多同时3个请求）
async function runWithConcurrency(tasks, concurrency = 3) {
    const results = [];
    const executing = [];
    for (const task of tasks) {
        const p = Promise.resolve().then(() => task());
        results.push(p);
        if (concurrency <= tasks.length) {
            const e = p.then(() => executing.splice(executing.indexOf(e), 1));
            executing.push(e);
            if (executing.length >= concurrency) {
                await Promise.race(executing);
            }
        }
    }
    return Promise.all(results);
}

// 带重试的基础请求
async function fetchUrlWithRetry(url, retries = 2) {
    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const response = await axiosInstance.get(url);
            return response;
        } catch (error) {
            if (attempt === retries) {
                return { error: error.message, status: error.response?.status || 500 };
            }
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
}

// 1. 基础信息
async function getBasicInfo(url) {
    const response = await fetchUrlWithRetry(url);
    if (response.error) {
        return { error: response.error, status: response.status };
    }
    return {
        status: response.status,
        headers: response.headers,
        contentLength: response.data.length,
        title: (response.data.match(/<title>(.*?)<\/title>/i) || [])[1] || ''
    };
}

// 2. 安全头部检测
function checkSecurityHeaders(headers) {
    return rules.securityHeaders.filter(h => !headers[h.toLowerCase()]);
}

// 3. 敏感文件探测（使用手动限流）
async function checkSensitiveFiles(baseUrl) {
    const found = [];
    const tasks = rules.sensitivePaths.map(path => async () => {
        const url = new URL(path, baseUrl).href;
        try {
            const res = await axiosInstance.get(url, { timeout: 2000 });
            if (res.status === 200) found.push(path);
        } catch (e) { /* 忽略 */ }
    });
    await runWithConcurrency(tasks, 3);
    return found;
}

// 4. XSS 反射检测
async function checkXssReflected(baseUrl) {
    const payload = '<script>alert("XSS")</script>';
    for (const param of rules.xssParams) {
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(param, payload);
        try {
            const res = await axiosInstance.get(testUrl.href);
            if (res.data.includes(payload) && !res.data.includes('&lt;script&gt;')) {
                return { vulnerable: true, param, url: testUrl.href };
            }
        } catch (e) { /* 忽略 */ }
    }
    return { vulnerable: false };
}

// 5. SQL 注入检测
async function checkSqlInjection(baseUrl) {
    const payload = "' OR '1'='1";
    for (const param of rules.sqlParams) {
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(param, payload);
        try {
            const res = await axiosInstance.get(testUrl.href);
            const errorKeywords = ['sql', 'mysql', 'syntax', 'unclosed'];
            const hasError = errorKeywords.some(k => res.data.toLowerCase().includes(k));
            if (hasError) {
                return { vulnerable: true, param, url: testUrl.href };
            }
        } catch (e) {
            if (e.response && e.response.status >= 500) {
                return { vulnerable: true, param, url: testUrl.href, note: 'Server error likely caused by injection' };
            }
        }
    }
    return { vulnerable: false };
}

// 6. 目录遍历检测
async function checkDirectoryTraversal(baseUrl) {
    const payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini'];
    const testParams = ['file', 'path', 'page'];
    for (const param of testParams) {
        for (const payload of payloads) {
            const testUrl = new URL(baseUrl);
            testUrl.searchParams.set(param, payload);
            try {
                const res = await axiosInstance.get(testUrl.href, { timeout: 3000 });
                if (res.data.includes('root:') || res.data.includes('[extensions]')) {
                    return { vulnerable: true, param, payload, url: testUrl.href };
                }
            } catch (e) { /* 忽略 */ }
        }
    }
    return { vulnerable: false };
}

// 7. 危险 HTTP 方法检测
async function checkHttpMethods(baseUrl) {
    const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS'];
    const allowed = [];
    for (const method of dangerousMethods) {
        try {
            const res = await axiosInstance.request({
                method: method,
                url: baseUrl,
                timeout: 3000
            });
            if (res.status !== 405 && res.status !== 404) {
                allowed.push(method);
            }
        } catch (e) { /* 忽略 */ }
    }
    return allowed;
}

// 8. 敏感信息泄露检测
async function checkInfoLeakage(baseUrl) {
    try {
        const response = await axiosInstance.get(baseUrl);
        const text = response.data;
        const patterns = {
            emails: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
            phones: /(\+?[0-9]{1,3}[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}/g,
            apiKeys: /[A-Za-z0-9]{32,}/g
        };
        const found = {};
        for (const [type, regex] of Object.entries(patterns)) {
            const matches = text.match(regex);
            if (matches && matches.length) found[type] = [...new Set(matches.slice(0, 3))];
        }
        return found;
    } catch (e) {
        return {};
    }
}

// 9. CORS 配置检测
async function checkCors(baseUrl) {
    try {
        const response = await axiosInstance.options(baseUrl, { timeout: 3000 });
        const allowOrigin = response.headers['access-control-allow-origin'];
        if (allowOrigin === '*') {
            return { vulnerable: true, details: 'Access-Control-Allow-Origin: * allows any origin.' };
        }
        return { vulnerable: false, details: 'CORS policy is restrictive.' };
    } catch (e) {
        return { vulnerable: false, details: 'No CORS headers detected.' };
    }
}

// 10. CMS 指纹识别（简单示例）
async function detectCms(baseUrl) {
    const cmsSignatures = [
        { name: 'WordPress', paths: ['/wp-content/', '/wp-includes/'] },
        { name: 'Drupal', paths: ['/sites/default/', '/core/'] },
        { name: 'Joomla', paths: ['/media/system/', '/templates/'] }
    ];
    try {
        const response = await axiosInstance.get(baseUrl);
        const html = response.data;
        for (const cms of cmsSignatures) {
            for (const path of cms.paths) {
                if (html.includes(path)) {
                    return { detected: true, name: cms.name, version: null };
                }
            }
        }
        return { detected: false };
    } catch (e) {
        return { detected: false };
    }
}

// 11. CSP 策略分析
function analyzeCsp(cspHeader) {
    if (!cspHeader) return null;
    const directives = {};
    cspHeader.split(';').forEach(part => {
        const [key, ...values] = part.trim().split(' ');
        directives[key] = values;
    });
    const hasUnsafe = directives['script-src']?.includes("'unsafe-inline'") || directives['script-src']?.includes("'unsafe-eval'");
    const missingDefault = !directives['default-src'];
    return {
        directives,
        issues: { unsafeInline: hasUnsafe, missingDefaultSrc: missingDefault }
    };
}

// 主函数
module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

    try {
        // 并发执行所有独立检测
        const [basic, sensitiveFiles, xssResult, sqlResult, dirTraversal, httpMethods, infoLeakage, cors, cms] = await Promise.all([
            getBasicInfo(targetUrl),
            checkSensitiveFiles(targetUrl),
            checkXssReflected(targetUrl),
            checkSqlInjection(targetUrl),
            checkDirectoryTraversal(targetUrl),
            checkHttpMethods(targetUrl),
            checkInfoLeakage(targetUrl),
            checkCors(targetUrl),
            detectCms(targetUrl)
        ]);

        const securityMissing = checkSecurityHeaders(basic.headers || {});
        const cspAnalysis = analyzeCsp(basic.headers?.['content-security-policy']);

        const result = {
            url: targetUrl,
            basic,
            security: { missingHeaders: securityMissing, csp: cspAnalysis },
            sensitiveFiles,
            xss: xssResult,
            sqlInjection: sqlResult,
            directoryTraversal: dirTraversal,
            httpMethods: { allowed: httpMethods },
            infoLeakage,
            cors,
            cms
        };

        res.status(200).json(result);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
};