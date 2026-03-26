const axios = require('axios');

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

    // 获取真实基础信息
    let basic = { status: 0, headers: {}, title: '', error: null };
    try {
        const response = await axios.get(targetUrl, { timeout: 5000 });
        basic = {
            status: response.status,
            headers: response.headers,
            title: (response.data.match(/<title>(.*?)<\/title>/i) || [])[1] || '',
            contentLength: response.data.length
        };
    } catch (error) {
        basic = { error: error.message, status: error.response?.status || 500 };
    }

    // 其他字段仍用模拟数据
    const result = {
        url: targetUrl,
        basic,
        security: { missingHeaders: [] },
        sensitiveFiles: [],
        xss: { vulnerable: false },
        sqlInjection: { vulnerable: false },
        directoryTraversal: { vulnerable: false },
        httpMethods: { allowed: [] },
        infoLeakage: {},
        cors: { vulnerable: false, details: 'No CORS headers' },
        cms: { detected: false }
    };

    res.status(200).json(result);
};