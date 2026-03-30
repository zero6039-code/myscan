// api/scan/ssrf.js
const axios = require('axios');
const https = require('https');

// 1. 移除原来的 require 和 limit 定义
// const pLimit = require('p-limit');
// const limit = pLimit(3);

const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 3000,
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

const testParams = ['url', 'src', 'dest', 'redirect'];
const internalUrls = [
    'http://169.254.169.254/latest/meta-data/',
    'http://localhost:80/',
    'http://127.0.0.1:80/'
];

// 2. 将 checkSSRF 改为异步函数，内部动态导入 p-limit
async function checkSSRF(baseUrl) {
    // 动态导入 ES 模块，获取默认导出
    const pLimitModule = await import('p-limit');
    const pLimit = pLimitModule.default;
    const limit = pLimit(3); // 并发限制

    const tasks = [];
    for (const param of testParams) {
        for (const internal of internalUrls) {
            const testUrl = new URL(baseUrl);
            testUrl.searchParams.set(param, internal);
            tasks.push(async () => {
                try {
                    const res = await axiosInstance.get(testUrl.href);
                    const sensitiveKeywords = ['root:', 'instance-id', 'admin', 'passwd'];
                    if (sensitiveKeywords.some(k => res.data.toLowerCase().includes(k))) {
                        return { vulnerable: true, param, url: testUrl.href, note: 'Possible SSRF vulnerability detected' };
                    }
                } catch (e) {
                    // 忽略超时或错误
                }
                return null;
            });
        }
    }

    const results = await Promise.all(tasks.map(task => limit(task)));
    for (const result of results) {
        if (result && result.vulnerable) return result;
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
        console.error(err);
        res.status(500).json({ error: err.message });
    }
};
