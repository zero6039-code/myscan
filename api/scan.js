const axios = require('axios');
const https = require('https');

// 增强的 axios 实例（模拟浏览器、忽略证书）
const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 8000, // 单次请求超时 8 秒
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

// 辅助函数：带重试的请求（用于基础信息）
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
    const required = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy'
    ];
    return required.filter(h => !headers[h.toLowerCase()]);
}

// 3. 敏感文件探测（精简路径，控制时间）
async function checkSensitiveFiles(baseUrl) {
    const sensitivePaths = [
        '/robots.txt', '/.env', '/.git/config', '/backup.zip', '/admin'
    ];
    const found = [];
    for (const path of sensitivePaths) {
        const url = new URL(path, baseUrl).href;
        try {
            const res = await axiosInstance.get(url, { timeout: 2000 });
            if (res.status === 200) found.push(path);
        } catch (e) { /* 忽略 */ }
    }
    return found;
}

// 4. 简单 XSS 检测（反射型）
async function checkXssReflected(baseUrl) {
    const payload = '<script>alert("XSS")</script>';
    const testParams = ['q', 's', 'id', 'search'];
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

// 5. 简单 SQL 注入检测
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

// 6. 威胁情报（VirusTotal）可选，需要环境变量
async function getVirusTotalInfo(domain) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) return { error: 'API key not configured' };
    try {
        const url = `https://www.virustotal.com/api/v3/domains/${domain}`;
        const response = await axios.get(url, {
            headers: { 'x-apikey': apiKey },
            timeout: 5000
        });
        const stats = response.data.data.attributes.last_analysis_stats;
        return {
            malicious: stats.malicious,
            suspicious: stats.suspicious,
            harmless: stats.harmless,
            undetected: stats.undetected
        };
    } catch (error) {
        return { error: error.message };
    }
}

// 主函数
module.exports = async (req, res) => {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'http://' + targetUrl;

    try {
        // 并发执行独立检测（节省时间）
        const [basic, sensitiveFiles, xssResult, sqlResult] = await Promise.all([
            getBasicInfo(targetUrl),
            checkSensitiveFiles(targetUrl),
            checkXssReflected(targetUrl),
            checkSqlInjection(targetUrl)
        ]);

        const securityMissing = checkSecurityHeaders(basic.headers || {});

        // 可选：威胁情报（单独执行，不影响主流程）
        let threatIntel = null;
        if (process.env.VIRUSTOTAL_API_KEY) {
            try {
                const domain = new URL(targetUrl).hostname;
                threatIntel = await getVirusTotalInfo(domain);
            } catch (e) {
                threatIntel = { error: e.message };
            }
        }

        const result = {
            url: targetUrl,
            basic,
            security: { missingHeaders: securityMissing },
            sensitiveFiles,
            xss: xssResult,
            sqlInjection: sqlResult,
            threatIntel: threatIntel || { error: 'Not configured' }
        };
        res.status(200).json(result);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
};