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
 * 多语言切换
 */
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
 * 核心：动态像素对齐滚动算法（完美适配所有屏幕与自适应）
 */
function animateCounter(targetNumber) {
    const counterContainer = document.getElementById("stats-counter");
    if (!counterContainer) return;

    // 清空容器，防止多语言重叠污染
    counterContainer.innerHTML = "";

    // 将数字转为单字符数组
    const digitStringArray = targetNumber.toString().split("");

    // 1. 动态生成纵向数字列槽
    const slots = digitStringArray.map(() => {
        const slot = document.createElement("div");
        slot.className = "counter-digit-slot";
        
        // 填入 0 到 9 的独立 span 节点
        for (let i = 0; i <= 9; i++) {
            const numSpan = document.createElement("span");
            numSpan.innerText = i;
            slot.appendChild(numSpan);
        }
        
        counterContainer.appendChild(slot);
        return slot;
    });

    // 2. 【核心修复】强制重绘后，动态抓取当前屏幕下第一个数字 Span 的精准物理像素高度
    counterContainer.offsetHeight; // 触发 reflow
    
    const firstSpan = slots[0]?.querySelector('span');
    if (!firstSpan) return;
    
    // 💡 实时获取当前屏幕下的单字高度（PC端会拿到56，移动端会自动拿到38）
    const singleDigitHeight = firstSpan.offsetHeight; 

    // 3. 严格按照动态像素执行平移，彻底切断与 CSS 百分比继承的干扰
    digitStringArray.forEach((digitChar, index) => {
        const targetDigit = parseInt(digitChar, 10);
        const finalPixelOffset = targetDigit * singleDigitHeight; // 精准计算像素偏移量
        
        setTimeout(() => {
            slots[index].style.transform = `translateY(-${finalPixelOffset}px)`;
        }, index * 60);
    });
}

/**
 * 初始化总线
 */
document.addEventListener('DOMContentLoaded', () => {
    // 初始化多语言切换点击事件
    const options = document.querySelectorAll('.lang-option');
    options.forEach(opt => {
        opt.addEventListener('click', (e) => {
            e.stopPropagation();
            setLanguage(opt.dataset.lang);
            
            // 每次语言切换，重新计算并对齐数字位置
            const counterContainer = document.getElementById("stats-counter");
            if (counterContainer) {
                const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
                animateCounter(target);
            }
        });
    });
    
    // 默认加载中文语言
    setLanguage('zh');

    // 页面加载时自动触发滚动
    const counterContainer = document.getElementById("stats-counter");
    if (counterContainer) {
        const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
        setTimeout(() => {
            animateCounter(target);
        }, 350); // 留出 350ms 等 CSS 媒体查询和 DOM 完全稳定
    }
    
    // 💡 监听屏幕大小改变（比如手机横屏、浏览器缩放），自动重新计算对齐，防止拉伸断层
    window.addEventListener('resize', () => {
        const counterContainer = document.getElementById("stats-counter");
        if (counterContainer) {
            const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
            animateCounter(target);
        }
    });
});
