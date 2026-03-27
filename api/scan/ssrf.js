// api/scan/ssrf.js
const axios = require('axios');
const https = require('https');

const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 5000,
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

// 简单 SSRF 检测：尝试在常见参数中注入内部地址，观察响应是否包含特定内容
async function checkSSRF(baseUrl) {
    // 常见可能引发 SSRF 的参数名
    const testParams = ['url', 'src', 'dest', 'redirect', 'return', 'path', 'load', 'fetch'];
    // 内部地址测试 payload
    const internalUrls = [
        'http://169.254.169.254/latest/meta-data/',
        'http://localhost:80/',
        'http://127.0.0.1:80/',
        'file:///etc/passwd'
    ];
    for (const param of testParams) {
        for (const internal of internalUrls) {
            const testUrl = new URL(baseUrl);
            testUrl.searchParams.set(param, internal);
            try {
                const response = await axiosInstance.get(testUrl.href);
                // 检查响应中是否包含敏感内容（简单启发）
                const sensitiveKeywords = ['root:', 'instance-id', 'admin', 'passwd'];
                if (sensitiveKeywords.some(k => response.data.toLowerCase().includes(k))) {
                    return { vulnerable: true, param, url: testUrl.href, note: 'Possible SSRF vulnerability detected' };
                }
            } catch (e) {
                // 忽略请求错误
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

    try {
        const result = await checkSSRF(targetUrl);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
