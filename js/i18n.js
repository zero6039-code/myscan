window.currentLang = 'en';
window.fallbackTranslations = null; 

async function initFallback() {
    try {
        // 如果是在本地 file:/// 协议下运行，fetch 必定失败，直接跳过避免抛出阻塞后续逻辑的未捕获异常
        if (window.location.protocol === 'file:') {
            console.warn("[i18n] 本地文件协议(file:///)下无法动态加载JSON，已启用降级兼容模式");
            return;
        }
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
        // 1. 只有在非本地文件协议下，才移除 ready 标记，走防闪烁流程
        if (window.location.protocol !== 'file:') {
            document.documentElement.removeAttribute("data-i18n-ready");
        }
        
        console.log(`[i18n] 正在请求语言包: /locales/${lang}.json`);
        
        // 2. 本地直接双击运行时强制抛出，进入 catch 块的降级可见度流程
        if (window.location.protocol === 'file:') {
            throw new Error("Local file protocol detected. Shifting to fallback rendering.");
        }

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
            let targetText = translations[key] || (window.fallbackTranslations && window.fallbackTranslations[key]);

            if (targetText !== undefined && targetText !== null) {
                const tagName = element.tagName.toLowerCase();
                if (tagName === 'option') {
                    element.text = targetText;
                } else {
                    element.innerHTML = targetText;
                }
            }
        });

        // 处理占位符属性的特殊替换
        const placeholders = document.querySelectorAll("[data-i18n-placeholder]");
        placeholders.forEach(element => {
            const key = element.getAttribute("data-i18n-placeholder");
            let targetText = translations[key] || (window.fallbackTranslations && window.fallbackTranslations[key]);
            if (targetText) {
                element.setAttribute("placeholder", targetText);
            }
        });

        localStorage.setItem("preferred_lang", lang);
        window.currentLang = lang;
        updateDropdownUI(lang);

    } catch (error) {
        console.warn("[i18n] 触发架构降级线:", error.message);
    } finally {
        // 🛡️ 架构核心修复：无论异步获取成功还是失败、哪怕是本地离线运行，在最后一步也必须解除透明死锁
        document.documentElement.setAttribute("data-i18n-ready", "true");
        
        // 如果数字计数器已加载，切换或降级后激活对齐计算
        if (typeof triggerStatsCounter === "function") {
            triggerStatsCounter();
        }
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

// 执行高可用自适应流
(async () => {
    await initFallback();
    const defaultLang = localStorage.getItem("preferred_lang") || 'en'; 
    await loadLanguage(defaultLang);

    // 绑定事件
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
