const axios = require('axios');

// 安全头部检测
function checkSecurityHeaders(headers) {
    const required = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy'
    ];
    return required.filter(h => !headers[h.toLowerCase()]);
}

// 敏感文件探测（硬编码路径，串行请求）
async function checkSensitiveFiles(baseUrl) {
    const sensitivePaths = [
        '/robots.txt', '/.env', '/.git/config', '/backup.zip', '/admin', '/phpinfo.php'
    ];
    const found = [];
    for (const path of sensitivePaths) {
        const url = new URL(path, baseUrl).href;
        try {
            const res = await axios.get(url, { timeout: 2000 });
            if (res.status === 200) found.push(path);
        } catch (e) {
            // 忽略超时或404
        }
    }
    return found;
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

    // 获取基础信息
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

    const result = {
        url: targetUrl,
        basic,
        security: { missingHeaders },
        sensitiveFiles,
        xss: { vulnerable: false },
        sqlInjection: { vulnerable: false },
        directoryTraversal: { vulnerable: false },
        httpMethods: { allowed: [] },
        infoLeakage: {},
        cors: { vulnerable: false, details: 'No CORS headers' },
        cms: { detected: false }
    };

    res.status(200).json(result);
};