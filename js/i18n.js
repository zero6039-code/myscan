window.currentLang = 'en';
window.fallbackTranslations = null; 

async function initFallback() {
    try {
        const response = await fetch('/locales/en.json');
        if (response.ok) {
            window.fallbackTranslations = await response.json();
            console.log("[i18n] 基础回滚包初始化成功");
        }
    } catch(e) {
        console.error("[i18n] 基础回滚包初始化失败", e);
    }
}

async function loadLanguage(lang) {
    try {
        // 标记开始加载，防止 FOUT 闪烁
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
                const tagName = element.tagName.toLowerCase();
                if (tagName === 'option') {
                    // 🛡️ 架构核心修复：只改变显示文本，绝对不污染/覆盖 option 的原始 value 属性
                    element.text = targetText;
                } else {
                    element.innerHTML = targetText;
                }
            }
        });

        // 3. 处理占位符属性的特殊替换 (如 textarea, input)
        const placeholders = document.querySelectorAll("[data-i18n-placeholder]");
        placeholders.forEach(element => {
            const key = element.getAttribute("data-i18n-placeholder");
            let targetText = translations[key] || (window.fallbackTranslations && window.fallbackTranslations[key]);
            if (targetText) {
                element.setAttribute("placeholder", targetText);
            }
        });

        // 4. 状态持久化与同步
        localStorage.setItem("preferred_lang", lang);
        window.currentLang = lang;
        updateDropdownUI(lang);

        // 如果数字计数器已加载，语言切换后重新触发对齐计算
        if (typeof triggerStatsCounter === "function") {
            triggerStatsCounter();
        }
        
        // 成功挂载，通知 CSS 渐显显示，消除视觉闪烁
        document.documentElement.setAttribute("data-i18n-ready", \"true\");
        console.log(`[i18n] 语言已成功切换至: ${lang}`);

    } catch (error) {
        console.error("国际化架构加载失败，采用回滚机制:", error);
        document.documentElement.setAttribute("data-i18n-ready", \"true\");
    }
}

function updateDropdownUI(activeLang) {
    const options = document.querySelectorAll(".lang-option");
    options.forEach(option => {
        if (option.getAttribute("data-id") === activeLang || option.getAttribute("data-lang") === activeLang) {
            option.classList.add("active");
        } else {
            option.classList.remove("active");
        }
    });
}

// 采用高性能的初始化时机
(async () => {
    await initFallback();
    const defaultLang = localStorage.getItem("preferred_lang") || 'en'; 
    await loadLanguage(defaultLang);

    // 绑定多语言切换按钮事件
    document.addEventListener("DOMContentLoaded", () => {
        const langOptions = document.querySelectorAll(".lang-option");
        langOptions.forEach(option => {
            option.addEventListener("click", (e) => {
                e.preventDefault();
                e.stopPropagation();
                const selectedLang = option.getAttribute("data-lang") || option.getAttribute("data-id");
                if (selectedLang && selectedLang !== window.currentLang) {
                    loadLanguage(selectedLang);
                }
            });
        });
    });
})();
