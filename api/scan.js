const axios = require('axios');
const https = require('https');

// 增强的 axios 实例（模拟浏览器、忽略证书、超时10秒）
const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 10000,
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

// 带重试的请求函数（默认重试2次）
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

// 获取基础信息
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

// 检查安全头部缺失
function checkSecurityHeaders(headers) {
    const required = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy'
    ];
    const missing = required.filter(h => !headers[h.toLowerCase()]);
    return missing;
}

// 敏感文件探测
async function checkSensitiveFiles(baseUrl) {
    const sensitivePaths = [
        '/.env', '/.git/config', '/backup.zip', '/admin', '/phpinfo.php',
        '/wp-config.php.bak', '/config.php', '/robots.txt'
    ];
    const found = [];
    for (const path of sensitivePaths) {
        const url = new URL(path, baseUrl).href;
        try {
            const res = await axiosInstance.get(url, { timeout: 2000 });
            if (res.status === 200) found.push(path);
        } catch (e) { /* 忽略错误 */ }
    }
    return found;
}

// XSS 反射检测
async function checkXssReflected(baseUrl) {
    const payload = '<script>alert("XSS")</script>';
    const testParams = ['q', 's', 'id', 'search', 'query'];
    for (const param of testParams) {
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

// SQL 注入检测
async function checkSqlInjection(baseUrl) {
    const payload = "' OR '1'='1";
    const testParams = ['id', 'page', 'user'];
    for (const param of testParams) {
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(param, payload);
        try {
            const res = await axiosInstance.get(testUrl.href);
            const errorKeywords = ['sql', 'mysql', 'syntax', 'unclosed'];
            const hasError = errorKeywords.some(k => res.data.toLowerCase().includes(k));
            if (hasError) return { vulnerable: true, param, url: testUrl.href };
        } catch (e) {
            if (e.response && e.response.status >= 500) {
                return { vulnerable: true, param, url: testUrl.href, note: 'Server error likely caused by injection' };
            }
        }
    }
    return { vulnerable: false };
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
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'http://' + targetUrl;

    try {
        const basic = await getBasicInfo(targetUrl);
        const securityMissing = checkSecurityHeaders(basic.headers || {});
        const sensitiveFiles = await checkSensitiveFiles(targetUrl);
        const xssResult = await checkXssReflected(targetUrl);
        const sqlResult = await checkSqlInjection(targetUrl);

        const result = {
            url: targetUrl,
            basic,
            security: { missingHeaders: securityMissing },
            sensitiveFiles,
            xss: xssResult,
            sqlInjection: sqlResult
        };
        res.status(200).json(result);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
};