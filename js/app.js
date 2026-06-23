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

function setLanguage(lang) {
    currentLang = lang;
    document.querySelectorAll('.lang-option').forEach(opt => {
        opt.classList.toggle('active', opt.dataset.lang === lang);
    });
    
    // 更新占位文案
    const p = document.querySelector('.placeholder-message p');
    if (p) p.textContent = i18n[lang].placeholder;

    // 自动更新所有带有 data-i18n 属性的导航元素
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (i18n[lang][key]) {
            // 保留图标元素
            const icon = el.querySelector('i');
            el.textContent = i18n[lang][key];
            if (icon) el.appendChild(icon);
        }
    });
}
// ... 后续保持你原有的 DOMContentLoaded 事件监听逻辑 ...
