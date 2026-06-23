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

    // 清空容器，准备根据位数重新生成结构
    counterContainer.innerHTML = "";

    // 将数字转为字符串数组
    const digitStringArray = targetNumber.toString().split("");

    // 1. 动态为每一位数字生成一个 0-9 的纵向数字列槽
    const slots = digitStringArray.map(() => {
        const slot = document.createElement("div");
        slot.className = "counter-digit-slot";
        
        // 填入 0 到 9 供纵向滚动切换
        for (let i = 0; i <= 9; i++) {
            const numSpan = document.createElement("span");
            numSpan.innerText = i;
            slot.appendChild(numSpan);
        }
        
        counterContainer.appendChild(slot);
        return slot;
    });

    // 2. 强制浏览器重绘 (Reflow)，确保 0 已经渲染完毕
    counterContainer.offsetHeight;

    // 3. 开始执行向上滚动
// 3. 开始执行向上滚动（改为使用固定高度位移，彻底解决 image_0b007c.png 中的断层问题）
    digitStringArray.forEach((digitChar, index) => {
        const targetDigit = parseInt(digitChar, 10);
        
        // 关键修改：直接计算精准的像素或em位移（这里采用每行 56px 的绝对高度）
        // 如果在移动端，它会自动读取当前元素的设计高度，这里直接用行高乘以数字最安全
        setTimeout(() => {
            // 获取当前槽位单行的高度（动态适应 PC 端的 56px 和移动端的 38px）
            const lineHeight = slots[index].offsetHeight / 10; 
            slots[index].style.transform = `translateY(-${targetDigit * lineHeight}px)`;
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
