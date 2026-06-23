document.addEventListener("DOMContentLoaded", () => {
    const supportedLanguages = ["zh", "en", "ms"];
    
    // 优先本地缓存 -> 浏览器语言 -> 默认中文
    let currentLang = localStorage.getItem("preferred_lang") || 
                      navigator.language.split("-")[0] || "zh";
    
    if (!supportedLanguages.includes(currentLang)) {
        currentLang = "zh";
    }

    // 异步加载语言包并更新 DOM
    async function loadLanguage(lang) {
        try {
            // 请确保你的项目根目录下有 /locales/zh.json, /locales/en.json, /locales/ms.json
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
                if (translations[key]) {
                    // 使用 textContent 避免 XSS，如果有安全 HTML 标签才使用 innerHTML
                    element.innerHTML = translations[key];
                }
            });

            // 3. 状态持久化
            localStorage.setItem("preferred_lang", lang);
            currentLang = lang;

            // 4. 更新语言选择器高亮
            updateDropdownUI(lang);

            // ✨ 关键架构联动：多语言文本渲染完成后，重新触发数字滚动动画
            // 确保动画容器的高度是基于当前语言环境正确计算的
            if (typeof triggerStatsCounter === "function") {
                triggerStatsCounter();
            }

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

    // 绑定单一点击事件源，防止 app.js 与 i18n.js 重复绑定造成的动画混乱
    const langOptions = document.querySelectorAll(".lang-option");
    langOptions.forEach(option => {
        option.addEventListener("click", (e) => {
            e.stopPropagation();
            const selectedLang = option.getAttribute("data-lang");
            if (selectedLang !== currentLang) {
                loadLanguage(selectedLang);
            }
        });
    });

    // 初始化加载
    loadLanguage(currentLang);
});
