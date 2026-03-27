const axios = require('axios');
const https = require('https');
const tls = require('tls');

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

async function checkSSLConfig(url) {
    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname;
        const port = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);
        if (parsed.protocol !== 'https:') {
            return { error: 'Not an HTTPS site' };
        }

        return new Promise((resolve) => {
            const socket = tls.connect(port, hostname, {
                rejectUnauthorized: false,
                servername: hostname
            }, () => {
                let cert = null;
                let protocol = null;
                let cipher = null;
                try {
                    cert = socket.getPeerCertificate();
                    protocol = socket.getProtocol();
                    cipher = socket.getCipher();
                } catch (err) {
                    socket.end();
                    return resolve({ error: `Failed to retrieve certificate: ${err.message}` });
                }
                socket.end();

                if (!cert || Object.keys(cert).length === 0) {
                    return resolve({ error: 'No certificate received' });
                }

                const weakProtocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'];
                const isWeakProtocol = protocol ? weakProtocols.some(p => protocol === p) : false;

                const now = new Date();
                let validFrom, validTo, isExpired = false, notYetValid = false;
                if (cert.valid_from && cert.valid_to) {
                    validFrom = new Date(cert.valid_from);
                    validTo = new Date(cert.valid_to);
                    isExpired = now > validTo;
                    notYetValid = now < validFrom;
                } else {
                    validFrom = 'Unknown';
                    validTo = 'Unknown';
                }

                resolve({
                    protocol: protocol || 'Unknown',
                    cipher: cipher ? cipher.name : 'Unknown',
                    certificate: {
                        subject: cert.subject || {},
                        issuer: cert.issuer || {},
                        validFrom,
                        validTo,
                        isExpired,
                        notYetValid
                    },
                    weakProtocol: isWeakProtocol,
                    vulnerabilities: {
                        weakProtocol: isWeakProtocol,
                        expiredCert: isExpired,
                        notYetValid
                    }
                });
            });
            socket.on('error', (err) => {
                resolve({ error: err.message });
            });
            socket.setTimeout(5000, () => {
                socket.destroy();
                resolve({ error: 'Timeout' });
            });
        });
    } catch (err) {
        return { error: err.message };
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

    try {
        const sslConfig = await checkSSLConfig(targetUrl);
        res.json(sslConfig);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
