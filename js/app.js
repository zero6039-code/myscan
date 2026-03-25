// 后端 API 地址 – 后续绑定 Vercel 后会得到正式地址
const API_URL = 'https://myscan.vercel.app/api/scan';  // 暂用，以后可换

async function scan() {
    const target = document.getElementById('target').value;
    const resultDiv = document.getElementById('result');
    resultDiv.textContent = '扫描中...';
    
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: target })
        });
        const data = await response.json();
        resultDiv.textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        resultDiv.textContent = '错误：' + error.message;
    }
}
