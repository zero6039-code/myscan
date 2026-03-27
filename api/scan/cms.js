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

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

    const cmsSignatures = [
        { name: 'WordPress', paths: ['/wp-content/', '/wp-includes/'] },
        { name: 'Drupal', paths: ['/sites/default/', '/core/'] },
        { name: 'Joomla', paths: ['/media/system/', '/templates/'] }
    ];
    try {
        const response = await axiosInstance.get(targetUrl);
        const html = response.data;
        for (const cms of cmsSignatures) {
            for (const path of cms.paths) {
                if (html.includes(path)) {
                    return res.json({ detected: true, name: cms.name, version: null });
                }
            }
        }
        res.json({ detected: false });
    } catch (e) {
        res.json({ detected: false });
    }
};
