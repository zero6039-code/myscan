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

document.addEventListener('DOMContentLoaded', () => {
    const options = document.querySelectorAll('.lang-option');
    options.forEach(opt => {
        opt.addEventListener('click', (e) => {
            e.stopPropagation();
            setLanguage(opt.dataset.lang);
        });
    });
    setLanguage('zh');
});

/**
 * 核心：初始化并触发数字滚动动画
 * @param {number} targetNumber - 需要滚动到的目标数字，例如 69 或 125
 */
function animateCounter(targetNumber) {
    const counterContainer = document.getElementById("stats-counter");
    if (!counterContainer) return;

    // 清空容器，准备根据位数重新生成结构
    counterContainer.innerHTML = "";

    // 将数字转为字符串数组，例如：69 -> ["6", "9"] 
    // 排列自然符合：左边十位、右边个位。如果到了3位数如 125 -> ["1", "2", "5"] 自动兼容
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

    // 2. 强制浏览器重绘 (Reflow)，确保 0 已经渲染完毕，然后再开始向上滚动
    counterContainer.offsetHeight;

    // 3. 开始执行向上滚动：根据当前位上的目标数字计算偏移百分比
    digitStringArray.forEach((digitChar, index) => {
        const targetDigit = parseInt(digitChar, 10);
        // 因为每个数字高度一致，目标数字是几，就往上偏移 (目标数字 * 10%)
        // 例如目标是 9，向上平移 90% 就会刚好显示 9
        const translateYPercentage = targetDigit * 10; 
        
        // 附加一点微小的随机延迟（50ms以内），让百位、十位、个位落点有微小的层次感
        setTimeout(() => {
            slots[index].style.transform = `translateY(-${translateYPercentage}%)`;
        }, index * 50);
    });


// 4. 页面加载完毕后自动运行（默认从 data-target 获取绑定的 69）
    document.addEventListener("DOMContentLoaded", () => {
        const counterContainer = document.getElementById("stats-counter");
        if (counterContainer) {
            const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
            // 延迟 300ms 启动，防止首屏加载卡顿影响动画流畅度
            setTimeout(() => {
                animateCounter(target);
            }, 300);
        }
    });
}
