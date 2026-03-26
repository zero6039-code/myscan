const axios = require('axios');
const https = require('https');

// ==================== 增强的 axios 实例 ====================
// 模拟真实浏览器，忽略 SSL 证书验证（仅测试环境）
const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 8000, // 单个请求超时 8 秒
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

// ==================== 辅助函数 ====================
// 带重试的请求函数（用于基础信息）
async function fetchUrlWithRetry(url, retries = 2) {
    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const response = await axiosInstance.get(url);
            return response;
        } catch (error) {
            if (attempt === retries) {
                return { error: error.message, status: error.response?.status || 500 };
            }
            await new Promise(resolve => setTimeout(resolve, 1000)); // 等待 1 秒后重试
        }
    }
}

// ==================== 检测模块 ====================
// 1. 基础信息（状态码、响应头、页面标题）
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
    const required = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy'
    ];
    return required.filter(h => !headers[h.toLowerCase()]);
}

// 3. 敏感文件探测（常见路径）
async function checkSensitiveFiles(baseUrl) {
    const sensitivePaths = [
        '/robots.txt', '/.env', '/.git/config', '/backup.zip', '/admin', '/phpinfo.php'
    ];
    const found = [];
    for (const path of sensitivePaths) {
        const url = new URL(path, baseUrl).href;
        try {
            const res = await axiosInstance.get(url, { timeout: 2000 });
            if (res.status === 200) found.push(path);
        } catch (e) {
            // 忽略超时或 404
        }
    }
    return found;
}

// 4. 反射型 XSS 检测（通过 URL 参数注入 payload）
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
            // 忽略网络错误
        }
    }
    return { vulnerable: false };
}

// 5. SQL 注入检测（通过注入 payload 观察响应变化）
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
            // 如果服务器返回 5xx 错误，也可能是注入导致
            if (e.response && e.response.status >= 500) {
                return { vulnerable: true, param, url: testUrl.href, note: 'Server error likely caused by injection' };
            }
        }
    }
    return { vulnerable: false };
}

// ==================== 主函数 ====================
module.exports = async (req, res) => {
    // CORS 设置
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

    // 自动补全协议
    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) {
        targetUrl = 'http://' + targetUrl;
    }

    try {
        // 并发执行独立检测，节省总耗时
        const [basic, sensitiveFiles, xssResult, sqlResult] = await Promise.all([
            getBasicInfo(targetUrl),
            checkSensitiveFiles(targetUrl),
            checkXssReflected(targetUrl),
            checkSqlInjection(targetUrl)
        ]);

        const securityMissing = checkSecurityHeaders(basic.headers || {});

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
        console.error('扫描失败:', error);
        res.status(500).json({ error: error.message });
    }
};