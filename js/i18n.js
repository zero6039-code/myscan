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
        document.documentElement.removeAttribute("data-i18n-ready");
        console.log(`[i18n] 正在请求语言包: /locales/${lang}.json`);
        
        const response = await fetch(`/locales/${lang}.json`);
        if (!response.ok) throw new Error(`无法加载语言文件: ${lang}`);
        const translations = await response.json();

        // 1. 动态更新页面标题
        if (translations["page_title"]) {
            document.title = translations["page_title"];
        }

        // 2. 遍历并动态更新所有带有 data-i18n 属性的标签内容
        const elements = document.querySelectorAll("[data-i18n]");
        elements.forEach(element => {
            const key = element.getAttribute("data-i18n");
            let targetText = translations[key] || (window.fallbackTranslations && window.fallbackTranslations[key]);

            if (targetText !== undefined && targetText !== null) {
                // 针对 option 标签的特殊兼容处理
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

        // 3. 【关键新增】全面遍历并动态更新带有属性翻译的标签 (如 placeholder)
        const attrElements = document.querySelectorAll("[data-i18n-placeholder]");
        attrElements.forEach(element => {
            const key = element.getAttribute("data-i18n-placeholder");
            let targetAttrText = translations[key] || (window.fallbackTranslations && window.fallbackTranslations[key]);
            if (targetAttrText) {
                element.setAttribute("placeholder", targetAttrText);
            }
        });

        // 4. 状态持久化
        localStorage.setItem("preferred_lang", lang);
        window.currentLang = lang;
        updateDropdownUI(lang);

        if (typeof triggerStatsCounter === "function") {
            triggerStatsCounter();
        }
        
        document.documentElement.setAttribute("data-i18n-ready", "true");
        console.log(`[i18n] 语言已成功切换至: ${lang}`);

    } catch (error) {
        console.error("国际化架构加载失败:", error);
        document.documentElement.setAttribute("data-i18n-ready", "true");
    }
}

function updateDropdownUI(activeLang) {
    const options = document.querySelectorAll(".lang-option");
    options.forEach(option => {
        if (option.getAttribute("data-lang") === activeLang) {
            option.classList.add("active");
        } else {
            option.classList.remove("active");
        }
    });
}

document.addEventListener("DOMContentLoaded", async () => {
    await initFallback();
    const defaultLang = localStorage.getItem("preferred_lang") || 'en'; 
    loadLanguage(defaultLang);

    const langOptions = document.querySelectorAll(".lang-option");
    langOptions.forEach(option => {
        option.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            const selectedLang = option.getAttribute("data-lang");
            if (selectedLang !== window.currentLang) {
                loadLanguage(selectedLang);
            }
        });
    });
});
