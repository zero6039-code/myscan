const i18n = {
    en: { 
        // 核心 Hero 区域
        hero_title: 'Focusing on Web3 Web Penetration & Code Auditing',
        hero_desc: 'DewSecure is a Web3 security platform built by a team with deep practical experience, integrating deep penetration testing, advanced code auditing, and comprehensive security solutions. Entrust your audit to us, ensuring your project or webpage always evolves in a continuously healthy and secure environment.',
        
        // 导航栏
        product: 'Products', audit: 'Security Audit', scan: 'Vulnerability Scan',
        solution: 'Solutions', defi: 'DeFi Security', track: 'On-chain Tracking',
        company: 'Company', disclaimer: 'Disclaimer', clients: 'Clients Served',

        // 下拉面板
        about_title: 'About Company',
        about_desc: 'DewSecure has been active across major vulnerability bounty platforms for years...',
        disclaimer_title: 'Disclaimer',
        disclaimer_sub: 'DewSecure legal compliance and service nature liability limitation statements.',
        disc_1_title: '1. Service Nature', disc_1_desc: 'Test content...',
        disc_2_title: '2. Technical Limitations', disc_2_desc: 'Limitation details...',
        disc_3_title: '3. Third-party Liability', disc_3_desc: 'Liability details...',
        disc_4_title: '4. Website Content', disc_4_desc: 'Website statement...',
        disc_5_title: '5. Intellectual Property', disc_5_desc: 'All rights reserved...',
        disc_6_title: '6. Limitation of Liability', disc_6_desc: 'Maximum legal allowance limit...'
    },
    zh: { 
        // 核心 Hero 区域
        hero_title: '专注 Web3 的网页渗透与代码审计',
        hero_desc: 'DewSecure 是由实战经验深厚的团队构建的 Web3 安全平台，集深度渗透测试、高阶代码审计与全方位安全解决方案于一体。交给我们审计，让您更了解自己的项目或网页始终处于在健康和安全的环境持续发展。',
        
        // 导航栏
        product: '产品', audit: '安全审计', scan: '漏洞扫描',
        solution: '解决方案', defi: 'DeFi 安全', track: '链上追踪',
        company: '公司介绍', disclaimer: '免责声明', clients: '服务客户',

        // 下拉面板
        about_title: '关于公司',
        about_desc: 'DewSecure 多年来活跃于各大漏洞赏金平台...',
        disclaimer_title: '免责声明',
        disclaimer_sub: 'DewSecure 安全服务法律合规与服务性质责任限制说明。',
        disc_1_title: '1. 服务性质声明', disc_1_desc: '测试内容...',
        disc_2_title: '2. 技术局限性', disc_2_desc: '局限说明...',
        disc_3_title: '3. 第三方责任', disc_3_desc: '责任说明...',
        disc_4_title: '4. 网站内容', disc_4_desc: '网站声明...',
        disc_5_title: '5. 知识产权', disc_5_desc: '产权所有...',
        disc_6_title: '6. 责任限制', disc_6_desc: '最大法律允许限制...'
    },
    ms: { 
        // 核心 Hero 区域
        hero_title: 'Fokus pada Penembusan Web & Audit Kod Web3',
        hero_desc: 'DewSecure ialah platform keselamatan Web3 yang dibina oleh pasukan yang mempunyai pengalaman praktikal yang mendalam, menyepadukan ujian penembusan mendalam, audit kod lanjutan dan penyelesaian keselamatan yang komprehensif. Serahkan audit kepada kami, memastikan projek atau laman web anda sentiasa berkembang dalam persekitaran yang sihat dan selamat secara berterusan.',
        
        // 导航栏
        product: 'Produk', audit: 'Audit Keselamatan', scan: 'Imbasan Kerentanan',
        solution: 'Penyelesaian', defi: 'Keselamatan DeFi', track: 'Penjejakan Rantaian',
        company: 'Syarikat', disclaimer: 'Penafian', clients: 'Pelanggan Dilayani',

        // 下拉面板
        about_title: 'Mengenai Syarikat',
        about_desc: 'DewSecure telah aktif di platform ganjaran kerentanan utama selama bertahun-tahun...',
        disclaimer_title: 'Penafian',
        disclaimer_sub: 'Kenyataan pematuhan undang-undang perkhidmatan keselamatan DewSecure dan had liabiliti perkhidmatan.',
        disc_1_title: '1. Sifat Perkhidmatan', disc_1_desc: 'Kandungan ujian...',
        disc_2_title: '2. Had Teknikal', disc_2_desc: 'Butiran had...',
        disc_3_title: '3. Liabiliti Pihak Ketiga', disc_3_desc: 'Butiran liabiliti...',
        disc_4_title: '4. Kandungan Laman Web', disc_4_desc: 'Kenyataan laman web...',
        disc_5_title: '5. Harta Intelek', disc_5_desc: 'Hak cipta terpelihara...',
        disc_6_title: '6. Had Liabiliti', disc_6_desc: 'Had elaun undang-undang maksimum...'
    }
};

let currentLang = 'zh';

function setLanguage(lang) {
    currentLang = lang;
    
    document.querySelectorAll('.lang-option').forEach(opt => {
        opt.classList.toggle('active', opt.dataset.lang === lang);
    });

    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (i18n[lang][key]) {
            el.textContent = i18n[lang][key];
        }
    });
}

function animateCounter(targetNumber) {
    const counterContainer = document.getElementById("stats-counter");
    if (!counterContainer) return;

    counterContainer.innerHTML = "";
    const digitStringArray = targetNumber.toString().split("");

    const slots = digitStringArray.map(() => {
        const slot = document.createElement("div");
        slot.className = "counter-digit-slot";
        for (let i = 0; i <= 9; i++) {
            const numSpan = document.createElement("span");
            numSpan.innerText = i;
            slot.appendChild(numSpan);
        }
        counterContainer.appendChild(slot);
        return slot;
    });

    counterContainer.offsetHeight; // Reflow
    
    const firstSpan = slots[0]?.querySelector('span');
    if (!firstSpan) return;
    const singleDigitHeight = firstSpan.offsetHeight; 

    digitStringArray.forEach((digitChar, index) => {
        const targetDigit = parseInt(digitChar, 10);
        const finalPixelOffset = targetDigit * singleDigitHeight;
        
        setTimeout(() => {
            slots[index].style.transform = `translateY(-${finalPixelOffset}px)`;
        }, index * 60);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const options = document.querySelectorAll('.lang-option');
    options.forEach(opt => {
        opt.addEventListener('click', (e) => {
            e.stopPropagation();
            setLanguage(opt.dataset.lang);
            
            const counterContainer = document.getElementById("stats-counter");
            if (counterContainer) {
                const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
                animateCounter(target);
            }
        });
    });
    
    setLanguage('zh');
