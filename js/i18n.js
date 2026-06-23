window.currentLang = 'en';
window.fallbackTranslations = null; 

// 预先静默加载英文基础包
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

// 渲染黑客骨架屏的函数
function injectSkeleton(element, type) {
    if (type === 'hero_title') {
        element.innerHTML = '<span class="skeleton-line skeleton-title"></span>';
    } else if (type === 'hero_desc') {
        element.innerHTML = '<span class="skeleton-line"></span><span class="skeleton-line" style="width: 75%; margin: 12px auto 0;"></span>';
    }
}

async function loadLanguage(lang) {
    try {
        console.log(`[i18n] 正在请求语言包: /locales/${lang}.json`);
        
        // 渲染文本前，先对主视觉区上锁并展示骨架屏
        const titleEl = document.querySelector("[data-i18n='hero_title']");
        const descEl = document.querySelector("[data-i18n='hero_desc']");
        if (titleEl) injectSkeleton(titleEl, 'hero_title');
        if (descEl) injectSkeleton(descEl, 'hero_desc');

        const response = await fetch(`/locales/${lang}.json`);
        if (!response.ok) throw new Error(`无法加载语言文件: ${lang}`);
        const translations = await response.json();

        // 动态更新页面标题
        if (translations["page_title"]) {
            document.title = translations["page_title"];
        }

        // 遍历并动态更新所有标签
        const elements = document.querySelectorAll("[data-i18n]");
        elements.forEach(element => {
            const key = element.getAttribute("data-i18n");
            let targetText = translations[key];

            // 降级兜底策略
            if (!targetText && window.fallbackTranslations && window.fallbackTranslations[key]) {
                targetText = window.fallbackTranslations[key];
            }

            if (targetText) {
                // 只有确实拿到文本时，才覆盖掉骨架屏并触发淡入
                element.innerHTML = targetText;
                element.classList.remove("is-skeleton"); 
            } else {
                // 如果实在什么都没有，保持骨架屏形态
                if (key === 'hero_title' || key === 'hero_desc') {
                     element.classList.add("is-skeleton");
                }
            }
        });

        localStorage.setItem("preferred_lang", lang);
        window.currentLang = lang;
        updateDropdownUI(lang);

        if (typeof triggerStatsCounter === "function") {
            triggerStatsCounter();
        }
        
        console.log(`[i18n] 语言已成功切换至: ${lang}`);

    } catch (error) {
        console.error("国际化架构加载失败:", error);
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
