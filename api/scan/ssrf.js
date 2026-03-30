const axios = require('axios');
const https = require('https');

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
    },
    maxRedirects: 10,
    validateStatus: (status) => status < 500
});

function isInternalIP(hostname) {
    const parts = hostname.split('.');
    if (parts.length === 4) {
        const first = parseInt(parts[0], 10);
        const second = parseInt(parts[1], 10);
        if (first === 10) return true;
        if (first === 172 && second >= 16 && second <= 31) return true;
        if (first === 192 && second === 168) return true;
        if (first === 127) return true;
    }
    return hostname === 'localhost' || hostname === '0.0.0.0' || hostname === '[::1]';
}

async function checkSSRF(baseUrl) {
    const testParams = ['url', 'src', 'dest', 'redirect', 'return', 'path', 'load', 'fetch', 'location', 'callback', 'domain'];
    const internalUrls = [
        'http://169.254.169.254/latest/meta-data/',
        'http://localhost:80/',
        'http://127.0.0.1:80/',
        'http://0.0.0.0:80/',
        'http://[::1]:80/',
        'http://10.0.0.1/',
        'http://172.16.0.1/',
        'http://192.168.0.1/',
        'file:///etc/passwd'
    ];
    for (const param of testParams) {
        for (const internal of internalUrls) {
            const testUrl = new URL(baseUrl);
            testUrl.searchParams.set(param, internal);
            try {
                const response = await axiosInstance.get(testUrl.href);
                // 检查最终请求的 URL 是否指向内网
                const finalUrl = response.request?.res?.responseUrl || testUrl.href;
                let finalHostname;
                try {
                    finalHostname = new URL(finalUrl).hostname;
                } catch (e) { continue; }
                if (isInternalIP(finalHostname)) {
                    return { vulnerable: true, param, url: testUrl.href, note: 'Internal IP reached via SSRF' };
                }
                // 检查响应内容中是否包含敏感内容
                const sensitiveKeywords = ['root:', 'instance-id', 'admin', 'passwd', 'secret'];
                if (sensitiveKeywords.some(k => response.data.toLowerCase().includes(k))) {
                    return { vulnerable: true, param, url: testUrl.href, note: 'Possible SSRF vulnerability detected' };
                }
            } catch (e) {}
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
