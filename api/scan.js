const axios = require('axios');
const https = require('https');

// 创建一个自定义的 axios 实例，忽略 SSL 证书验证（仅用于测试环境）
const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 5000
});

// 辅助函数：发送 GET 请求（使用自定义实例）
async function fetchUrl(url) {
    try {
        const response = await axiosInstance.get(url);
        return response;
    } catch (error) {
        return { error: error.message, status: error.response?.status || 500 };
    }
}

// 1. 基础信息：状态码、响应头、页面大小等
async function getBasicInfo(url) {
    const response = await fetchUrl(url);
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

// 2. 检测安全头部缺失
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

// 3. 检测敏感文件泄露（常见路径列表）
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
            if (res.status === 200) {
                found.push(path);
            }
        } catch (e) {
            // 忽略超时或 404
        }
    }
    return found;
}

// 4. 简单 XSS 检测（反射型）
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
        } catch (e) {
            // 忽略错误
        }
    }
    return { vulnerable: false };
}

// 5. 简单 SQL 注入检测（基于响应差异）
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

// 主函数
module.exports = async (req, res) => {
    // 设置 CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'Missing url' });
    }

    // 确保 URL 有协议
    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) {
        targetUrl = 'http://' + targetUrl;
    }

    try {
        const basic = await getBasicInfo(targetUrl);
        const securityMissing = checkSecurityHeaders(basic.headers || {});
        const sensitiveFiles = await checkSensitiveFiles(targetUrl);
        const xssResult = await checkXssReflected(targetUrl);
        const sqlResult = await checkSqlInjection(targetUrl);

        const result = {
            url: targetUrl,
            basic,
            security: {
                missingHeaders: securityMissing
            },
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