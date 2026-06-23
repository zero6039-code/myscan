// 1. 声明一个安全的全局可访问语言追踪变量
window.currentLang = 'en';
// 全局缓存英文包，作为最后的降级方案，防止别的脚本乱切语言导致字段缺失
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

// 2. 异步加载语言包并更新 DOM 的核心函数
async function loadLanguage(lang) {
    try {
        console.log(`[i18n] 正在请求语言包: /locales/${lang}.json`);
        
        const response = await fetch(`/locales/${lang}.json`);
        if (!response.ok) throw new Error(`无法加载语言文件: ${lang}`);
        const translations = await response.json();

        // 动态更新页面标题
        const titleKey = "page_title";
        if (translations[titleKey]) {
            document.title = translations[titleKey];
        } else if (window.fallbackTranslations && window.fallbackTranslations[titleKey]) {
            document.title = window.fallbackTranslations[titleKey];
        }

        // 遍历并动态更新所有带有 data-i18n 属性的标签内容
        const elements = document.querySelectorAll("[data-i18n]");
        elements.forEach(element => {
            const key = element.getAttribute("data-i18n");
            
            if (translations[key]) {
                // A 方案：当前语言包有，直接用当前语言包
                element.innerHTML = translations[key];
            } else if (window.fallbackTranslations && window.fallbackTranslations[key]) {
                // B 方案（防御降级）：当前语言包没有（比如 zh/ms 没写），用英文兜底，绝不留白或保留硬编码
                element.innerHTML = window.fallbackTranslations[key];
                console.warn(`[i18n] 字段 [${key}] 在 [${lang}.json] 中缺失，已自动使用英文兜底。`);
            }
        });

        // 成功后，同步更新状态持久化缓存与全局变量
        localStorage.setItem("preferred_lang", lang);
        window.currentLang = lang;

        // 更新语言选择器高亮 UI
        updateDropdownUI(lang);

        // 关键架构联动：重新触发数字滚动动画
        if (typeof triggerStatsCounter === "function") {
            triggerStatsCounter();
        }
        
        console.log(`[i18n] 语言已成功切换至: ${lang}`);

    } catch (error) {
        console.error("国际化架构加载失败:", error);
    }
}

// 3. 更新语言下拉菜单的高亮 UI 状态
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

// 4. 确保 DOM 树完全建立后执行初始化
document.addEventListener("DOMContentLoaded", () => {
    // 默认初始语言设置为英文
    const defaultLang = 'en'; 
    loadLanguage(defaultLang);

    // 绑定点击事件
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
