const i18n = {
    en: { 
        placeholder: '🚀 Under reconstruction, new features coming soon...',
        product: 'Products', audit: 'Security Audit', scan: 'Vulnerability Scan',
        solution: 'Solutions', defi: 'DeFi Security', track: 'On-chain Tracking',
        company: 'Company', clients: 'Clients Served'
    },
    zh: { 
        placeholder: '🚀 重构中，新功能即将上线...',
        product: '产品', audit: '安全审计', scan: '漏洞扫描',
        solution: '解决方案', defi: 'DeFi 安全', track: '链上追踪',
        company: '公司介绍', clients: '服务客户'
    },
    ms: { 
        placeholder: '🚀 Dalam pembinaan semula, ciri baharu akan datang...',
        product: 'Produk', audit: 'Audit Keselamatan', scan: 'Imbasan Kerentanan',
        solution: 'Penyelesaian', defi: 'Keselamatan DeFi', track: 'Penjejakan Rantaian',
        company: 'Syarikat', clients: 'Pelanggan Dilayani'
    }
};

let currentLang = 'zh';

function setLanguage(lang) {
    currentLang = lang;
    document.querySelectorAll('.lang-option').forEach(opt => {
        opt.classList.toggle('active', opt.dataset.lang === lang);
    });
    
    const p = document.querySelector('.placeholder-message p');
    if (p) p.textContent = i18n[lang].placeholder;

    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (i18n[lang][key]) {
            el.textContent = i18n[lang][key];
        }
    });
}

/**
 * 核心：初始化并触发数字滚动动画
 * @param {number} targetNumber - 需要滚动到的目标数字，例如 69 或 125
 */
function animateCounter(targetNumber) {
    const counterContainer = document.getElementById("stats-counter");
    if (!counterContainer) return;

    // 清空容器
    counterContainer.innerHTML = "";

    // 将数字转为字符串数组
    const digitStringArray = targetNumber.toString().split("");

    // 1. 动态生成纵向数字列槽
    const slots = digitStringArray.map(() => {
        const slot = document.createElement("div");
        slot.className = "counter-digit-slot";
        
        // 填入 0 到 9
        for (let i = 0; i <= 9; i++) {
            const numSpan = document.createElement("span");
            numSpan.innerText = i;
            slot.appendChild(numSpan);
        }
        
        counterContainer.appendChild(slot);
        return slot;
    });

    // 2. 强制浏览器重绘 (Reflow)
    counterContainer.offsetHeight;

    // 3. 执行向上滚动：100% 代表整个槽高（10个数字），每个数字完美占据 10%
    digitStringArray.forEach((digitChar, index) => {
        const targetDigit = parseInt(digitChar, 10);
        
        setTimeout(() => {
            // 直接使用百分比位移，彻底剥离 JS 获取高度受到的 DOM 渲染干扰
            slots[index].style.transform = `translateY(-${targetDigit * 10}%)`;
        }, index * 50);
    });
}
// 4. 页面加载完毕后自动运行（移到了外层，修复了原配置无法触发的 Bug）
document.addEventListener('DOMContentLoaded', () => {
    // 初始化多语言切换点击事件
    const options = document.querySelectorAll('.lang-option');
    options.forEach(opt => {
        opt.addEventListener('click', (e) => {
            e.stopPropagation();
            setLanguage(opt.dataset.lang);
        });
    });
    
    // 默认加载中文语言
    setLanguage('zh');

    // 自动初始化并触发滚动数字
    const counterContainer = document.getElementById("stats-counter");
    if (counterContainer) {
        const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
        setTimeout(() => {
            animateCounter(target);
        }, 300);
    }
});
