// i18n.js —— 配合防 FOUC 方案
window.currentLang = 'en';
window.fallbackTranslations = null;

async function initFallback() {
    try {
        const response = await fetch('/locales/en.json');
        if (response.ok) {
            window.fallbackTranslations = await response.json();
            console.log("[i18n] 基础包初始化成功");
        }
    } catch(e) {
        console.error("[i18n] 基础包初始化失败", e);
    }
}

async function loadLanguage(lang) {
    try {
        console.log(`[i18n] 正在请求语言包: /locales/${lang}.json`);
        
        const response = await fetch(`/locales/${lang}.json`);
        if (!response.ok) throw new Error(`无法加载语言文件: ${lang}`);
        const translations = await response.json();

        // 更新页面标题
        if (translations["page_title"]) {
            document.title = translations["page_title"];
        }

        // 更新所有带 data-i18n 的元素
        document.querySelectorAll("[data-i18n]").forEach(element => {
            const key = element.getAttribute("data-i18n");
            let targetText = translations[key] || (window.fallbackTranslations && window.fallbackTranslations[key]);
            if (targetText !== undefined && targetText !== null) {
                if (element.tagName.toLowerCase() === 'option') {
                    element.text = targetText;
                    element.value = element.getAttribute('value') || targetText;
                } else {
                    if (/<[a-z="']/i.test(targetText)) {
                        element.innerHTML = targetText;
                    } else {
                        element.textContent = targetText;
                    }
                }
            }
        });

        // 更新 placeholder 属性
        document.querySelectorAll("[data-i18n-placeholder]").forEach(element => {
            const key = element.getAttribute("data-i18n-placeholder");
            let targetAttrText = translations[key] || (window.fallbackTranslations && window.fallbackTranslations[key]);
            if (targetAttrText) {
                element.setAttribute("placeholder", targetAttrText);
            }
        });

        // 持久化语言偏好
        localStorage.setItem("preferred_lang", lang);
        window.currentLang = lang;
        updateDropdownUI(lang);

        if (typeof triggerStatsCounter === "function") {
            triggerStatsCounter();
        }

        // ✅ 关键：移除防闪烁类，显示所有翻译文本
        document.documentElement.classList.remove("i18n-loading");
        document.documentElement.setAttribute("data-i18n-ready", "true");
        console.log(`[i18n] 语言已成功切换至: ${lang}`);

    } catch (error) {
        console.error("国际化架构加载失败:", error);
        // 失败时也必须显示页面，移除类
        document.documentElement.classList.remove("i18n-loading");
        document.documentElement.setAttribute("data-i18n-ready", "true");
    }
}

function updateDropdownUI(activeLang) {
    document.querySelectorAll(".lang-option").forEach(option => {
        if (option.getAttribute("data-lang") === activeLang) {
            option.classList.add("active");
        } else {
            option.classList.remove("active");
        }
    });
}

// 立即执行初始化（不再依赖 DOMContentLoaded，配合 defer 或放在 body 底部）
(async () => {
    await initFallback();
    
    let defaultLang = localStorage.getItem("preferred_lang");
    if (!defaultLang) {
        defaultLang = 'en';
        localStorage.setItem("preferred_lang", 'en');
    }
    
    await loadLanguage(defaultLang);

    // 绑定语言切换事件
    document.querySelectorAll(".lang-option").forEach(option => {
        option.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            const selectedLang = option.getAttribute("data-lang");
            if (selectedLang !== window.currentLang) {
                loadLanguage(selectedLang);
            }
        });
    });
})();
