const axios = require('axios');
const https = require('https');
const tls = require('tls');
const pLimit = require('p-limit');
const rules = require('../rules.json');

// ========== 缓存配置 ==========
const cache = new Map(); // 内存缓存 { key: { result, timestamp } }
const CACHE_TTL = 5 * 60 * 1000; // 5分钟

// 请求限流（最多同时3个）
const limit = pLimit(3);

// 增强的 axios 实例
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

// ========== 辅助函数 ==========
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

// 3. 敏感文件探测（限流）
async function checkSensitiveFiles(baseUrl) {
    const found = [];
    const tasks = rules.sensitivePaths.map(path =>
        limit(async () => {
            const url = new URL(path, baseUrl).href;
            try {
                const res = await axiosInstance.get(url, { timeout: 2000 });
                if (res.status === 200) found.push(path);
            } catch (e) { /* 忽略 */ }
        })
    );
    await Promise.all(tasks);
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

// 8. 敏感信息泄露检测（增强）
async function checkInfoLeakage(baseUrl) {
    try {
        const response = await axiosInstance.get(baseUrl);
        const text = response.data;
        const patterns = {
            emails: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
            phones: /(\+?[0-9]{1,3}[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}/g,
            apiKeys: /[A-Za-z0-9]{32,}/g,
            idCards: /\b[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g,
            bankCards: /\b[0-9]{16,19}\b/g,
            awsKeys: /AKIA[0-9A-Z]{16}\b/g,
            privateKeys: /-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----/g
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

// 10. CMS 指纹识别
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

// 12. SSL/TLS 配置检测（增强容错）
async function checkSSLConfig(url) {
    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname;
        const port = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);
        if (parsed.protocol !== 'https:') {
            return { error: 'Not an HTTPS site' };
        }

        return new Promise((resolve) => {
            const socket = tls.connect(port, hostname, {
                rejectUnauthorized: false,
                servername: hostname
            }, () => {
                let cert = null;
                let protocol = null;
                let cipher = null;
                try {
                    cert = socket.getPeerCertificate();
                    protocol = socket.getProtocol();
                    cipher = socket.getCipher();
                } catch (err) {
                    socket.end();
                    return resolve({ error: `Failed to retrieve certificate: ${err.message}` });
                }
                socket.end();

                // 如果证书为空（例如连接被重置），返回错误
                if (!cert || Object.keys(cert).length === 0) {
                    return resolve({ error: 'No certificate received' });
                }

                // 检查弱协议
                const weakProtocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'];
                const isWeakProtocol = protocol ? weakProtocols.some(p => protocol === p) : false;

                // 检查证书有效性
                const now = new Date();
                let validFrom, validTo, isExpired = false, notYetValid = false;
                if (cert.valid_from && cert.valid_to) {
                    validFrom = new Date(cert.valid_from);
                    validTo = new Date(cert.valid_to);
                    isExpired = now > validTo;
                    notYetValid = now < validFrom;
                } else {
                    validFrom = 'Unknown';
                    validTo = 'Unknown';
                }

                const result = {
                    protocol: protocol || 'Unknown',
                    cipher: cipher ? cipher.name : 'Unknown',
                    certificate: {
                        subject: cert.subject || {},
                        issuer: cert.issuer || {},
                        validFrom: validFrom,
                        validTo: validTo,
                        isExpired,
                        notYetValid
                    },
                    weakProtocol: isWeakProtocol,
                    vulnerabilities: {
                        weakProtocol: isWeakProtocol,
                        expiredCert: isExpired,
                        notYetValid
                    }
                };
                resolve(result);
            });
            socket.on('error', (err) => {
                resolve({ error: err.message });
            });
            socket.setTimeout(5000, () => {
                socket.destroy();
                resolve({ error: 'Timeout' });
            });
        });
    } catch (err) {
        return { error: err.message };
    }
}

// ========== 主函数 ==========
module.exports = async (req, res) => {
    // CORS
    const allowedOrigin = process.env.FRONTEND_URL || 'https://myscan-henna.vercel.app';
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { url, depth = 'deep' } = req.body; // 接收前端传来的深度参数
    if (!url) return res.status(400).json({ error: 'Missing url' });

    // 输入校验：过滤危险协议
    if (/^javascript:/i.test(url) || /^data:/i.test(url) || /^vbscript:/i.test(url)) {
        return res.status(400).json({ error: 'Invalid URL protocol' });
    }

    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;
    targetUrl = targetUrl.replace(/\/$/, '');

    // 缓存键（包含深度）
    const cacheKey = `${targetUrl}_${depth}`;
    const cached = cache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
        return res.status(200).json(cached.result);
    }

    try {
        // 总是执行基础信息和安全头检测（这些很快）
        const basic = await getBasicInfo(targetUrl);
        const securityMissing = checkSecurityHeaders(basic.headers || {});
        const cspAnalysis = analyzeCsp(basic.headers?.['content-security-policy']);
        const sslConfig = await checkSSLConfig(targetUrl);

        let sensitiveFiles = [];
        let xssResult = { vulnerable: false };
        let sqlResult = { vulnerable: false };
        let dirTraversal = { vulnerable: false };
        let httpMethods = [];
        let infoLeakage = {};
        let cors = { vulnerable: false, details: 'No CORS headers detected.' };
        let cms = { detected: false };

        // 深度扫描模式才执行其他耗时检测
        if (depth === 'deep') {
            [sensitiveFiles, xssResult, sqlResult, dirTraversal, httpMethods, infoLeakage, cors, cms] = await Promise.all([
                checkSensitiveFiles(targetUrl),
                checkXssReflected(targetUrl),
                checkSqlInjection(targetUrl),
                checkDirectoryTraversal(targetUrl),
                checkHttpMethods(targetUrl),
                checkInfoLeakage(targetUrl),
                checkCors(targetUrl),
                detectCms(targetUrl)
            ]);
        }

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
            cms,
            ssl: sslConfig
        };

        // 存入缓存
        cache.set(cacheKey, { result, timestamp: Date.now() });

        res.status(200).json(result);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
};
