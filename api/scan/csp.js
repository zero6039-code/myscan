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

function analyzeCsp(cspHeader) {
    if (!cspHeader) return null;
    const directives = {};
    cspHeader.split(';').forEach(part => {
        const [key, ...values] = part.trim().split(' ');
        directives[key] = values;
    });
    const hasUnsafe = directives['script-src']?.includes("'unsafe-inline'") || directives['script-src']?.includes("'unsafe-eval'");
    const missingDefault = !directives['default-src'];
    return {
        directives,
        issues: { unsafeInline: hasUnsafe, missingDefaultSrc: missingDefault }
    };
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
        const response = await fetchUrlWithRetry(targetUrl);
        if (response.error) {
            return res.json({ error: response.error, status: response.status });
        }
        const cspAnalysis = analyzeCsp(response.headers?.['content-security-policy']);
        res.json(cspAnalysis);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
