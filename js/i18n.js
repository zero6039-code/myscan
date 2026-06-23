// 1. 声明一个安全的全局可访问语言追踪变量，默认设置为 'en'
window.currentLang = 'en';

// 2. 异步加载语言包并更新 DOM 的核心函数
async function loadLanguage(lang) {
    try {
        console.log(`[i18n] 正在请求语言包: /locales/${lang}.json`);
        
        const response = await fetch(`/locales/${lang}.json`);
        if (!response.ok) throw new Error(`无法加载语言文件: ${lang}`);
        const translations = await response.json();

        // 动态更新页面标题
        if (translations["page_title"]) {
            document.title = translations["page_title"];
        }

        // 遍历并动态更新所有带有 data-i18n 属性的标签内容
        const elements = document.querySelectorAll("[data-i18n]");
        elements.forEach(element => {
            const key = element.getAttribute("data-i18n");
            if (translations[key]) {
                element.innerHTML = translations[key];
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
        console.error("国际化架构加载失败，请检查 /locales/ 路径及 JSON 格式:", error);
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

// 4. 确保 DOM 树完全建立后，按照严格的拓扑顺序执行初始化
document.addEventListener("DOMContentLoaded", () => {
    // 强制每次刷新或首次进入时默认显示 'en' (英文)
    const defaultLang = 'en'; 
    
    // 步骤 A：先安全启动初始语言加载，确保 window.currentLang 得到正确写入
    loadLanguage(defaultLang);

    // 步骤 B：绑定点击事件，直接通过绑定的属性实时对比，防止作用域死锁
    const langOptions = document.querySelectorAll(".lang-option");
    langOptions.forEach(option => {
        option.addEventListener("click", (e) => {
            e.stopPropagation();
            const selectedLang = option.getAttribute("data-lang");
            
            // 健壮性检查：如果点击的语言和当前激活的语言不同，才触发异步异步抓取
            if (selectedLang !== window.currentLang) {
                loadLanguage(selectedLang);
            }
        });
    });
});
