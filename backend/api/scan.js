const axios = require('axios');

module.exports = async (req, res) => {
    // 设置 CORS 头
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

    try {
        // 简单的请求示例（后续可替换为扫描逻辑）
        const response = await axios.get(url, { timeout: 5000 });
        res.status(200).json({
            url,
            status: response.status,
            headers: response.headers
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};