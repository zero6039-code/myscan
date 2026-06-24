window.currentLang = 'en';
window.fallbackTranslations = null; 

// 1. 将初始化改为返回 Promise，以便后续同步控制
async function initFallback() {
    try {
        const response = await fetch('/locales/en.json');
        if (response.ok) {
            window.fallbackTranslations = await response.json();
            console.log("[i18n] 英文基础包（降级方案）预加载成功");
        }
    } catch(e) {
        console.error("[i18n] 基础包初始化失败", e);
    }
}

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

            if (targetText !== undefined && targetText !== null) {
                // 优化：检查是否包含 HTML 标签，没有则用 textContent 防范 XSS
                if (/<[a-z="']/i.test(targetText)) {
                    element.innerHTML = targetText;
                } else {
                    element.textContent = targetText;
                }
            }
        });

        // 【新增优化】支持属性翻译，例如 data-i18n-placeholder="input_placeholder_key"
        const attrElements = document.querySelectorAll("[data-i18n-placeholder], [data-i18n-title]");
        attrElements.forEach(element => {
            ['placeholder', 'title'].forEach(attr => {
                const key = element.getAttribute(`data-i18n-${attr}`);
                if (key) {
                    let targetAttrText = translations[key] || (window.fallbackTranslations && window.fallbackTranslations[key]);
                    if (targetAttrText) {
                        element.setAttribute(attr, targetAttrText);
                    }
                }
            });
        });

        // 3. 状态持久化
        localStorage.setItem("preferred_lang", lang);
        window.currentLang = lang;
        updateDropdownUI(lang);

        if (typeof triggerStatsCounter === "function") {
            triggerStatsCounter();
        }
        
        // 全部渲染完成后，通知 CSS 解锁显示，杜绝任何中文外露
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

// 监听生命周期
document.addEventListener("DOMContentLoaded", async () => {
    // 关键修复：先等待英文兜底基础包加载完毕，再执行后续逻辑
    await initFallback();

    // 优化：优先从本地缓存读取用户上次偏好的语言，如果没有再默认 'en'
    // 如果你业务要求【必须每次硬性死守英文】，则保持 const defaultLang = 'en'; 即可
    const defaultLang = localStorage.getItem("preferred_lang") || 'en'; 
    
    // 执行加载
    loadLanguage(defaultLang);

    // 绑定下拉菜单事件
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
