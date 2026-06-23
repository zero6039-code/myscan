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

/**
 * 语言切换函数
 * @param {string} lang - 目标语言代码 ('zh', 'en', 'ms')
 */
function setLanguage(lang) {
    currentLang = lang;
    
    // 1. 更新语言选择器的高亮状态
    document.querySelectorAll('.lang-option').forEach(opt => {
        opt.classList.toggle('active', opt.dataset.lang === lang);
    });
    
    // 2. 更新主看板占位提示语
    const p = document.querySelector('.placeholder-message p');
    if (p) p.textContent = i18n[lang].placeholder;

    // 3. 全局动态翻译带有 data-i18n 属性的标签
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (i18n[lang][key]) {
            el.textContent = i18n[lang][key];
        }
    });
}

/**
 * 核心：初始化并触发数字滚动动画
 * @param {number} targetNumber - 需要滚动到的目标数字（例如 69）
 */
function animateCounter(targetNumber) {
    const counterContainer = document.getElementById("stats-counter");
    if (!counterContainer) return;

    // 强制防刷保护：如果该节点的父级不小心带有 data-i18n 产生文本覆盖，清除并重新赋予结构
    counterContainer.innerHTML = "";

    // 将目标数字转换为单字符数组 (例如 69 -> ["6", "9"])
    const digitStringArray = targetNumber.toString().split("");

    // 1. 动态生成纵向数字列槽 (0-9 的大转盘)
    const slots = digitStringArray.map(() => {
        const slot = document.createElement("div");
        slot.className = "counter-digit-slot";
        
        // 依次填入 0 到 9 数字标签
        for (let i = 0; i <= 9; i++) {
            const numSpan = document.createElement("span");
            numSpan.innerText = i;
            slot.appendChild(numSpan);
        }
        
        counterContainer.appendChild(slot);
        return slot;
    });

    // 2. 强制浏览器重绘 (Reflow) 锁死 CSS 刚性高度
    counterContainer.offsetHeight;

    // 3. 精准执行向上滚动位移（10% 代表一个数字的高度，完美规避像素碎裂断层）
    digitStringArray.forEach((digitChar, index) => {
        const targetDigit = parseInt(digitChar, 10);
        
        setTimeout(() => {
            slots[index].style.transform = `translateY(-${targetDigit * 10}%)`;
        }, index * 60); // 逐位错开 60ms 触发，增强视觉滚动层次感
    });
}

/**
 * 页面加载完毕的总线初始化生命周期
 */
document.addEventListener('DOMContentLoaded', () => {
    // 1. 绑定多语言切换栏的点击事件
    const options = document.querySelectorAll('.lang-option');
    options.forEach(opt => {
        opt.addEventListener('click', (e) => {
            e.stopPropagation();
            
            // 切换语言
            setLanguage(opt.dataset.lang);
            
            // 💡 规避覆盖死穴：切换语言后，重新刷新一下滚动数字的状态，保持动画与数字不丢失
            const counterContainer = document.getElementById("stats-counter");
            if (counterContainer) {
                const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
                animateCounter(target);
            }
        });
    });
    
    // 2. 默认优先加载中文环境文本
    setLanguage('zh');

    // 3. 略微延时，等所有多语言静态文本落盘、DOM 稳定后，再安全触发数字转盘动画
    const counterContainer = document.getElementById("stats-counter");
    if (counterContainer) {
        const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
        setTimeout(() => {
            animateCounter(target);
        }, 350); 
    }
});
