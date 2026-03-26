module.exports = async (req, res) => {
    // CORS 头
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'Missing url' });
    }

    // 确保 URL 有协议
    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) {
        targetUrl = 'http://' + targetUrl;
    }

    // 模拟扫描结果（包含前端所有字段）
    const result = {
        url: targetUrl,
        basic: {
            status: 200,
            headers: { 'content-type': 'text/html', 'server': 'MockServer' },
            title: 'Mock Page Title',
            contentLength: 1234
        },
        security: {
            missingHeaders: ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Strict-Transport-Security', 'Content-Security-Policy']
        },
        sensitiveFiles: ['/robots.txt'],
        xss: { vulnerable: false },
        sqlInjection: { vulnerable: false },
        threatIntel: { error: 'Threat intelligence not configured (add VIRUSTOTAL_API_KEY)' }
    };

    res.status(200).json(result);
};