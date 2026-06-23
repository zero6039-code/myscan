document.addEventListener("DOMContentLoaded", () => {
    // 默认支持的语言列表
    const supportedLanguages = ["zh", "en", "ms"];
    // 获取默认语言：优先使用本地缓存 -> 其次浏览器语言 -> 最终保底使用中文 'zh'
    let currentLang = localStorage.getItem("preferred_lang") || 
                      navigator.language.split("-")[0] || "zh";
    
    if (!supportedLanguages.includes(currentLang)) {
        currentLang = "zh"; // 不在支持列表中则默认中文
    }

    // 异步获取语言 JSON 并更新 DOM
    async function loadLanguage(lang) {
        try {
            const response = await fetch(`/locales/${lang}.json`);
            if (!response.ok) throw new Error(`无法加载语言文件: ${lang}`);
            const translations = await response.json();

            // 1. 动态更新页面 Title
            if (translations["page_title"]) {
                document.title = translations["page_title"];
            }

            // 2. 遍历并动态更新所有带有 data-i18n 属性的标签内容
            const elements = document.querySelectorAll("[data-i18n]");
            elements.forEach(element => {
                const key = element.getAttribute("data-i18n");
                if (translations[key]) {
                    element.innerHTML = translations[key];
                }
            });

            // 3. 更新 LocalStorage 缓存
            localStorage.setItem("preferred_lang", lang);
            currentLang = lang;

            // 4. 更新语言下拉菜单的 active 状态高亮
            updateDropdownUI(lang);

        } catch (error) {
            console.error("国际化加载失败:", error);
        }
    }

    // 更新多语言选择列表的 UI 状态
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

    // 为切换语言列表里的每一项绑定点击事件
    const langOptions = document.querySelectorAll(".lang-option");
    langOptions.forEach(option => {
        option.addEventListener("click", () => {
            const selectedLang = option.getAttribute("data-lang");
            if (selectedLang !== currentLang) {
                loadLanguage(selectedLang);
            }
        });
    });

    // 初始化加载
    loadLanguage(currentLang);
});
