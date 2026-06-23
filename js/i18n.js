// 初始化当前语言变量（全局或作用域顶层声明）
let currentLang = 'en';

// 异步加载语言包并更新 DOM
async function loadLanguage(lang) {
    try {
        // 请确保您的项目根目录下有 /locales/zh.json, /locales/en.json, /locales/ms.json
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
                // 使用 innerHTML 允许 JSON 中的基础格式化标签，若追求极致安全可换回 textContent
                element.innerHTML = translations[key];
            }
        });

        // 3. 状态持久化与变量更新
        localStorage.setItem("preferred_lang", lang);
        currentLang = lang;

        // 4. 更新语言选择器高亮
        updateDropdownUI(lang);

        // ✨ 关键架构联动：多语言文本渲染完成后，重新触发数字滚动动画
        if (typeof triggerStatsCounter === "function") {
            triggerStatsCounter();
        }

    } catch (error) {
        console.error("国际化架构加载失败:", error);
    }
}

// 更新语言下拉菜单的高亮 UI 状态
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

// 确保 DOM 加载完毕后执行初始化与事件绑定
document.addEventListener("DOMContentLoaded", () => {
    // 1. 每次加载网页，如果没有手动切换过，都强制默认使用 'en' (英文)
    const defaultLang = 'en'; 
    
    // 执行初始语言加载（修正了原先 setLanguage 的命名错误）
    loadLanguage(defaultLang);

    // 2. 绑定单一点击事件源，防止 app.js 与 i18n.js 重复绑定造成的动画混乱
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
});
