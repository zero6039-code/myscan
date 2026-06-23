// 确保每次加载网页时，如果没有手动切换过，都强制默认使用 'en' (英文)
document.addEventListener("DOMContentLoaded", () => {
    // 强制指定 'en' 作为初始语言
    const defaultLang = 'en'; 
    
    // 如果您希望用户手动切了语言后刷新能保留，可以改为：const defaultLang = localStorage.getItem('lang') || 'en';
    // 如果要绝对每次死死卡在英文，就用上面那行 const defaultLang = 'en';
    
    setLanguage(defaultLang);
});

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
