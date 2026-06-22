const i18n = {
    en: { placeholder: '🚀 Under reconstruction, new features coming soon...' },
    zh: { placeholder: '🚀 重构中，新功能即将上线...' },
    ms: { placeholder: '🚀 Dalam pembinaan semula, ciri baharu akan datang...' }
};

let currentLang = 'en';

function setLanguage(lang) {
    currentLang = lang;
    document.querySelectorAll('.lang-option').forEach(opt => {
        opt.classList.toggle('active', opt.dataset.lang === lang);
    });
    const p = document.querySelector('.placeholder-message p');
    if (p) p.textContent = i18n[lang].placeholder;
}

document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('lang-toggle');
    const dropdown = document.getElementById('lang-dropdown');
    const options = document.querySelectorAll('.lang-option');

    toggle.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
    });
    options.forEach(opt => {
        opt.addEventListener('click', () => {
            setLanguage(opt.dataset.lang);
            dropdown.style.display = 'none';
        });
    });
    document.addEventListener('click', () => { dropdown.style.display = 'none'; });
    dropdown.addEventListener('click', e => e.stopPropagation());
    setLanguage('en');
});
