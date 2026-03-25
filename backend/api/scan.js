const axios = require('axios');

module.exports = async (req, res) => {
    // 设置 CORS 头（允许所有来源，生产环境建议改为你的前端域名）
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
        // 简单的请求示例（后续可扩展为真正的漏洞扫描）
        const response = await axios.get(url, { timeout: 5000 });
        res.status(200).json({
            url,
            status: response.status,
            headers: response.headers,
            // 这里可以添加更多扫描结果，例如敏感信息、XSS检测等
        });
    } catch (error) {
        // 处理错误，如网络超时、无效域名等
        res.status(500).json({ error: error.message });
    }
};