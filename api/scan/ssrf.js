// api/scan/ssrf.js
const axios = require('axios');
const https = require('https');

const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 5000
});

module.exports = async (req, res) => {
    // ... CORS 设置 ...
    const { url } = req.body;
    let targetUrl = url; // 确保 URL 处理正确

    const internalUrls = [
        'http://169.254.169.254/latest/meta-data/',
        'http://localhost:8080/',
        'http://127.0.0.1:80/'
    ];
    for (const internal of internalUrls) {
        const testUrl = new URL(internal, targetUrl).href; // 简单拼接，更严谨的做法是替换域名
        // 实际检测中应让服务器发起请求，这里需要根据目标 URL 构造参数，较为复杂。
        // 此处仅示意
    }
    res.json({ vulnerable: false });
};
