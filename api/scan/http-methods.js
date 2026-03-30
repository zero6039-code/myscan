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
    }
});

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

    const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'PATCH', 'COPY', 'MOVE', 'PROPFIND', 'MKCOL', 'LOCK', 'UNLOCK'];
    const allowed = [];
    for (const method of dangerousMethods) {
        try {
            const resMethod = await axiosInstance.request({
                method: method,
                url: targetUrl,
                timeout: 3000,
                validateStatus: (status) => status < 500 // 允许所有 4xx 也视为允许（但实际需判断）
            });
            // 如果状态码不是 405 且不是 404，则视为允许
            if (resMethod.status !== 405 && resMethod.status !== 404) {
                allowed.push(method);
            }
        } catch (e) {
            // 忽略错误
        }
    }
    res.json(allowed);
};
