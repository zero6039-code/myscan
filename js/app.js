// 极简测试版 app.js
document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const targetInput = document.getElementById('target');
    
    if (!scanBtn) {
        console.error('按钮未找到');
        return;
    }
    
    scanBtn.addEventListener('click', () => {
        const url = targetInput ? targetInput.value : '';
        alert(`扫描地址: ${url}`);
        // 实际调用 API
        fetch('https://myscan-henna.vercel.app/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        })
        .then(r => r.json())
        .then(data => console.log(data))
        .catch(err => console.error(err));
    });
});