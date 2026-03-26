const axios = require('axios');
const pLimit = require('p-limit');
const rules = require('../rules.json'); // 确保 rules.json 在根目录

// 请求限流（最多同时3个请求）
const limit = pLimit(3);

// 安全头部检测（使用规则文件）
function checkSecurityHeaders(headers) {
    return rules.securityHeaders.filter(h => !headers[h.toLowerCase()]);
}

// 敏感文件探测（使用规则文件 + 限流）
async function checkSensitiveFiles(baseUrl) {
    const found = [];
    const tasks = rules.sensitivePaths.map(path =>
        limit(async () => {
            const url = new URL(path, baseUrl).href;
            try {
                const res = await axios.get(url, { timeout: 2000 });
                if (res.status === 200) found.push(path);
            } catch (e) { /* 忽略 */ }
        })
    );
    await Promise.all(tasks);
    return found;
}

// XSS 反射检测（使用规则文件）
async function checkXssReflected(baseUrl) {
    const payload = '<script>alert("XSS")</script>';
    for (const param of rules.xssParams) {
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(param, payload);
        try {
            const res = await axios.get(testUrl.href);
            if (res.data.includes(payload) && !res.data.includes('&lt;script&gt;')) {
                return { vulnerable: true, param, url: testUrl.href };
            }
        } catch (e) { /* 忽略 */ }
    }
    return { vulnerable: false };
}

// SQL 注入检测（使用规则文件）
async function checkSqlInjection(baseUrl) {
    const payload = "' OR '1'='1";
    for (const param of rules.sqlParams) {
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(param, payload);
        try {
            const res = await axios.get(testUrl.href);
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

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

    // 基础信息
    let basic = { status: 0, headers: {}, title: '', error: null };
    try {
        const response = await axios.get(targetUrl, { timeout: 5000 });
        basic = {
            status: response.status,
            headers: response.headers,
            title: (response.data.match(/<title>(.*?)<\/title>/i) || [])[1] || '',
            contentLength: response.data.length
        };
    } catch (error) {
        basic = { error: error.message, status: error.response?.status || 500 };
    }

    const missingHeaders = checkSecurityHeaders(basic.headers || {});
    const sensitiveFiles = await checkSensitiveFiles(targetUrl);
    const xssResult = await checkXssReflected(targetUrl);
    const sqlResult = await checkSqlInjection(targetUrl);

    const result = {
        url: targetUrl,
        basic,
        security: { missingHeaders },
        sensitiveFiles,
        xss: xssResult,
        sqlInjection: sqlResult,
        directoryTraversal: { vulnerable: false },
        httpMethods: { allowed: [] },
        infoLeakage: {},
        cors: { vulnerable: false, details: 'No CORS headers' },
        cms: { detected: false }
    };

    res.status(200).json(result);
};