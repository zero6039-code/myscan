// 示例：接收 URL，进行简单的安全检测（需要安装 axios 等依赖）
const axios = require('axios');

module.exports = async (req, res) => {
    // 设置 CORS，允许前端域名（后续可改为你的自定义域名）
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
        // 这里添加你的扫描逻辑，例如：
        const response = await axios.get(url, { timeout: 5000 });
        // 模拟检测结果
        const result = {
            url,
            status: response.status,
            headers: response.headers,
            // ... 更多漏洞检测结果
        };
        res.status(200).json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
