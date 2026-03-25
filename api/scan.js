const axios = require('axios');
const https = require('https');

// ==================== 增强的 axios 实例 ====================
// 模拟真实浏览器请求头，提高通过率
const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 10000,  // 单次请求超时10秒（原5秒）
    headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://www.google.com/'  // 部分网站依赖 Referer
    }
});

// ==================== 带重试的请求函数 ====================
// 用于获取页面基本信息（失败时自动重试2次）
async function fetchUrlWithRetry(url, retries = 2) {
    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const response = await axiosInstance.get(url);
            return response;
        } catch (error) {
            if (attempt === retries) {
                // 最后一次失败，返回错误信息
                return { error: error.message, status: error.response?.status || 500 };
            }
            // 等待1秒后重试
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
}

// 基础信息获取（使用重试）
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

// ==================== 其他检测（沿用增强的 axiosInstance，但无重试） ====================
// 检测安全头部缺失
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

// 检测敏感文件泄露（使用增强 axiosInstance，但单独设置超时）
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

// 简单 XSS 检测（反射型）
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

// 简单 SQL 注入检测（基于响应差异）
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

    // 确保 URL 有协议
    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) {
        targetUrl = 'http://' + targetUrl;
    }

    try {
        // 并行执行检测
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