window.currentLang = 'en';
window.fallbackTranslations = null; 

// 预先静默加载英文基础包作为全局降级方案
async function initFallback() {
    try {
        const response = await fetch('/locales/en.json');
        if (response.ok) {
            window.fallbackTranslations = await response.json();
        }
    } catch(e) {
        console.error("[i18n] 基础包初始化失败", e);
    }
}
initFallback();

async function loadLanguage(lang) {
    try {
        // 开始请求时，先移除就绪标记，防止切语言时发生瞬闪
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
            let targetText = translations[key];

            // 降级兜底：当前包没有就去英文包捞
            if (!targetText && window.fallbackTranslations && window.fallbackTranslations[key]) {
                targetText = window.fallbackTranslations[key];
            }

            if (targetText) {
                element.innerHTML = targetText;
            }
        });

        // 3. 状态持久化
        localStorage.setItem("preferred_lang", lang);
        window.currentLang = lang;
        updateDropdownUI(lang);

        if (typeof triggerStatsCounter === "function") {
            triggerStatsCounter();
        }
        
        // 【关键防御步骤】全部渲染完成后，通知 CSS 解锁显示，杜绝任何中文外露
        document.documentElement.setAttribute("data-i18n-ready", "true");
        console.log(`[i18n] 语言已成功切换至: ${lang}`);

    } catch (error) {
        console.error("国际化架构加载失败:", error);
        // 发生异常时强制降级解锁，防止页面永久空白
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

document.addEventListener("DOMContentLoaded", () => {
    // 强制每次刷新或首次进入时默认显示 'en' (英文)
    const defaultLang = 'en'; 
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
