// api/scan/ssrf.js
const axios = require('axios');
const https = require('https');
const pLimit = require('p-limit');

const limit = pLimit(3); // 并发控制，最多同时3个请求

const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 3000, // 缩短到3秒
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

// 精简的测试列表（可根据需要调整）
const testParams = ['url', 'src', 'dest', 'redirect']; // 减少参数数量
const internalUrls = [
    'http://169.254.169.254/latest/meta-data/',
    'http://localhost:80/',
    'http://127.0.0.1:80/'
]; // 减少内部地址

async function checkSSRF(baseUrl) {
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

    // 并发执行，一旦有结果立即返回
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
