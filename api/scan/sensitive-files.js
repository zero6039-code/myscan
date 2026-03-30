const axios = require('axios');
const https = require('https');
const rules = require('../../rules.json');

// 安全加载敏感路径列表
const sensitivePaths = rules && rules.sensitivePaths && Array.isArray(rules.sensitivePaths)
    ? rules.sensitivePaths
    : [
        '/robots.txt', '/.env', '/.git/config', '/backup.zip', '/admin', '/phpinfo.php',
        '/wp-config.php.bak', '/config.php', '/backup.sql'
    ];

// 自定义并发控制（最多同时 3 个请求）
async function runWithConcurrency(tasks, concurrency = 3) {
    const results = [];
    const executing = [];
    for (const task of tasks) {
        const p = Promise.resolve().then(() => task());
        results.push(p);
        if (concurrency <= tasks.length) {
            const e = p.then(() => executing.splice(executing.indexOf(e), 1));
            executing.push(e);
            if (executing.length >= concurrency) {
                await Promise.race(executing);
            }
        }
    }
    return Promise.all(results);
}

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

    try {
        const found = [];
        const tasks = sensitivePaths.map(path => async () => {
            const testUrl = new URL(path, targetUrl).href;
            try {
                const res = await axiosInstance.get(testUrl, { timeout: 2000 });
                if (res.status === 200) found.push(path);
            } catch (e) {
                // 忽略错误
            }
        });
        await runWithConcurrency(tasks, 3);
        res.json(found);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
};
