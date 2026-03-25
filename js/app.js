// 请将下面地址替换为你实际的 Vercel 后端地址
const API_URL = 'https://myscan-henna.vercel.app/api/scan';

async function scan() {
    const targetInput = document.getElementById('target');
    const resultDiv = document.getElementById('result');
    const url = targetInput.value.trim();

    if (!url) {
        resultDiv.textContent = '请填写目标URL';
        return;
    }

    resultDiv.textContent = '扫描中...';

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        resultDiv.textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        resultDiv.textContent = '错误：' + error.message;
    }
}