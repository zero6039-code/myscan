// ==================== 国际化文本库 ====================
const i18n = {
    en: {
        legalNoticeTitle: 'Legal Disclaimer',
        legalNoticeText: '⚠️ This tool is for authorized security testing only. Unauthorized scanning is prohibited. By using this tool, you agree that you have explicit permission to test the target. Any illegal use is strictly forbidden. Users are responsible for complying with all applicable laws and regulations.',
        aboutTitle: 'About NetEye',
        aboutText: [
            'NetEye is a professional web vulnerability scanner designed for users of all levels—security researchers, web developers, students, and IT professionals. It helps you identify common security flaws in your own websites or authorized targets.',
            '⚠️ Responsible Use: Always obtain explicit permission before scanning any website. This tool is intended for educational purposes, internal security testing, and improving your own systems. NetEye does not encourage illegal use and is not responsible for any irresponsible actions.',
            '🔍 Learning Resource: NetEye provides detailed remediation suggestions for each detected vulnerability, helping you understand the attack principle and how to fix it.',
            '🛡️ Compliance: NetEye does not permanently store any scan results. All data is processed in real-time and never shared with third parties.'
        ]
    },
    zh: {
        legalNoticeTitle: '法律免责声明',
        legalNoticeText: '⚠️ 本工具仅供授权的安全测试使用。未经授权扫描他人网站属违法行为。使用本工具即表示您已获得目标网站的明确授权。任何非法使用将被严格禁止。用户需自行遵守所有适用法律法规。',
        aboutTitle: '关于 NetEye',
        aboutText: [
            'NetEye 是一款专业的网页漏洞扫描器，提供给无论有无经验者、安全研究人员、网页开发者、学生 和 IT 专业人士设计。帮助您识别自己网站或授权目标中的常见安全漏洞。',
            '⚠️ 负责任使用：扫描任何网站前，请务必获得明确授权。本工具仅用于教育目的、内部安全测试和改善自身系统 ，本工具一概不提倡非法使用，也不为任何不负责任的行为负责。',
            '🔍 学习资源和教育用途：NetEye 为每个检测到的漏洞提供详细的修复建议，帮助您理解攻击原理及修复方法。',
            '🛡️ 合规性：NetEye 不永久存储任何扫描结果。所有数据实时处理，绝不与第三方共享。'
        ]
    },
    ms: {
        legalNoticeTitle: 'Penafian Undang-undang',
        legalNoticeText: '⚠️ Alat ini hanya untuk ujian keselamatan yang dibenarkan. Imbasan tanpa kebenaran adalah dilarang. Dengan menggunakan alat ini, anda bersetuju bahawa anda mempunyai kebenaran eksplisit untuk menguji sasaran. Sebarang penggunaan haram adalah dilarang sama sekali. Pengguna bertanggungjawab mematuhi semua undang-undang dan peraturan yang berkenaan.',
        aboutTitle: 'Mengenai NetEye',
        aboutText: [
            'NetEye adalah pengimbas kelemahan web profesional yang direka untuk pengguna dari pelbagai peringkat—penyelidik keselamatan, pembangun web, pelajar, dan profesional IT. Ia membantu anda mengenal pasti kelemahan keselamatan biasa di laman web anda sendiri atau sasaran yang dibenarkan.',
            '⚠️ Penggunaan Bertanggungjawab: Sentiasa dapatkan kebenaran eksplisit sebelum mengimbas mana-mana laman web. Alat ini bertujuan untuk tujuan pendidikan, ujian keselamatan dalaman, dan menambah baik sistem anda sendiri. NetEye tidak menggalakkan penggunaan haram dan tidak bertanggungjawab atas sebarang tindakan tidak bertanggungjawab.',
            '🔍 Sumber Pembelajaran: NetEye menyediakan cadangan pembaikan terperinci untuk setiap kelemahan yang dikesan, membantu anda memahami prinsip serangan dan cara membetulkannya.',
            '🛡️ Pematuhan: NetEye tidak menyimpan secara kekal sebarang keputusan imbasan. Semua data diproses secara masa nyata dan tidak pernah dikongsi dengan pihak ketiga.'
        ]
    }
};

let currentLang = 'en';

function t(key) {
    return i18n[currentLang][key] || key;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    });
}

function setLanguage(lang) {
    currentLang = lang;
    // 更新下拉菜单高亮
    const langOptions = document.querySelectorAll('.lang-option');
    langOptions.forEach(opt => {
        opt.classList.toggle('active', opt.dataset.lang === lang);
    });
    // 更新占位文本（如果有）
    const placeholder = document.querySelector('.placeholder-message p');
    if (placeholder) {
        placeholder.textContent = lang === 'en' ? '🚀 Under reconstruction, new features coming soon...' :
                                 lang === 'zh' ? '🚀 重构中，新功能即将上线...' :
                                 '🚀 Dalam pembinaan semula, ciri baharu akan datang...';
    }
}

// ==================== 页面初始化 ====================
document.addEventListener('DOMContentLoaded', () => {
    const langToggle = document.getElementById('lang-toggle');
    const langDropdown = document.getElementById('lang-dropdown');
    const langOptions = document.querySelectorAll('.lang-option');

    // 语言下拉菜单交互
    if (langToggle) {
        langToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            if (langDropdown) {
                const isOpen = langDropdown.style.display === 'block';
                langDropdown.style.display = isOpen ? 'none' : 'block';
            }
        });
    }
    if (langOptions) {
        langOptions.forEach(opt => {
            opt.addEventListener('click', () => {
                const lang = opt.dataset.lang;
                if (lang) setLanguage(lang);
                if (langDropdown) langDropdown.style.display = 'none';
            });
        });
    }
    // 点击页面其他区域关闭下拉菜单
    document.addEventListener('click', () => {
        if (langDropdown) langDropdown.style.display = 'none';
    });
    if (langDropdown) {
        langDropdown.addEventListener('click', (e) => e.stopPropagation());
    }

    // 默认语言
    setLanguage('en');
});
