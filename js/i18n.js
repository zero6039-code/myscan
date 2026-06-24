/**
 * DewSecure - 国际化(i18n)核心控制脚本
 * 适配语言：中文(zh)、英文(en)、马来语(ms)
 */

window.currentLang = 'en';
window.fallbackTranslations = null; 

/**
 * 初始化英文基础包（作为全局兜底文本，防止某些Key在其他语言包中缺失）
 */
async function initFallback() {
    try {
        const response = await fetch('/locales/en.json');
        if (response.ok) {
            window.fallbackTranslations = await response.json();
            console.log("[i18n] 基础包(en)初始化成功");
        } else {
            console.error("[i18n] 基础包(en)文件读取失败，状态码:", response.status);
        }
    } catch(e) {
        console.error("[i18n] 基础包(en)网络请求初始化失败", e);
    }
}

/**
 * 核心方法：加载并渲染指定语言
 * @param {string} lang 语言代码 ('zh', 'en', 'ms')
 */
async function loadLanguage(lang) {
    try {
        // 关键安全锁：在开始加载新语言包前，移除就绪标记，触发 CSS 隐藏机制，防止中文或旧语言文本闪现
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
                // 针对 option 标签的特殊兼容处理
                if (element.tagName.toLowerCase() === 'option') {
                    element.text = targetText;
                    element.value = element.getAttribute('value') || targetText;
                } else {
                    // 如果文本内包含 HTML 标签则解析为 innerHTML，否则使用纯文本 textContent
                    if (/<[a-z="']/i.test(targetText)) {
                        element.innerHTML = targetText;
                    } else {
                        element.textContent = targetText;
                    }
                }
            }
        });

        // 3. 全面遍历并动态更新带有属性翻译的标签 (如占位符 placeholder)
        const attrElements = document.querySelectorAll("[data-i18n-placeholder]");
        attrElements.forEach(element => {
            const key = element.getAttribute("data-i18n-placeholder");
            let targetAttrText = translations[key] || (window.fallbackTranslations && window.fallbackTranslations[key]);
            if (targetAttrText) {
                // 双保险修改：同时作用于 DOM 属性与内存对象
                element.setAttribute("placeholder", targetAttrText);
                element.placeholder = targetAttrText;
            }
        });

        // 4. 🔥【强效死锁补丁】针对手机号/联系方式输入框实施精准防御
        // 应对可能存在的第三方脚本重置、或者页面双弹窗 DOM 导致的覆盖问题
        const contactInputs = document.querySelectorAll("#form-contact-val");
        contactInputs.forEach(contactInput => {
            const contactKey = contactInput.getAttribute("data-i18n-placeholder") || "form_plh_contact";
            let specificText = translations[contactKey] || (window.fallbackTranslations && window.fallbackTranslations[contactKey]);
            if (specificText) {
                contactInput.setAttribute("placeholder", specificText);
                contactInput.placeholder = specificText;
                console.log(`[i18n-Debug] 目标输入框占位符已强制修正为: ${specificText}`);
            }
        });

        // 5. 状态持久化与 UI 同步
        localStorage.setItem("preferred_lang", lang);
        window.currentLang = lang;
        updateDropdownUI(lang);

        // 如果项目中有统计分析脚本，在此触发回调
        if (typeof triggerStatsCounter === "function") {
            triggerStatsCounter();
        }
        
        // 核心释放锁：翻译完全注入 DOM 完成，通知 CSS 显示文本
        document.documentElement.setAttribute("data-i18n-ready", "true");
        console.log(`[i18n] 页面语言已成功切换至: ${lang}`);

    } catch (error) {
        console.error("国际化架构加载失败，启动安全逃生通道:", error);
        // 即使失败也要释放锁，防止页面因异常导致永久隐藏或白屏
        document.documentElement.setAttribute("data-i18n-ready", "true");
    }
}

/**
 * 更新语言切换下拉菜单的选中状态 UI
 * @param {string} activeLang 当前激活的语言
 */
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

// 统一生命周期控制
document.addEventListener("DOMContentLoaded", async () => {
    // 1. 优先并行加载英文兜底基础包
    await initFallback();
    
    // 2. 优化语言选择逻辑：优先读取本地缓存
    let defaultLang = localStorage.getItem("preferred_lang");
    
    // 如果本地缓存没有记录过语言，则默认设置为英文 'en'
    if (!defaultLang) {
        defaultLang = 'en';
        localStorage.setItem("preferred_lang", 'en');
    }
    
    // 3. 执行加载首选语言
    await loadLanguage(defaultLang);

    // 4. 动态绑定切换语言下拉菜单的点击事件
    const langOptions = document.querySelectorAll(".lang-option");
    langOptions.forEach(option => {
        option.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            const selectedLang = option.getAttribute("data-lang");
            if (selectedLang && selectedLang !== window.currentLang) {
                loadLanguage(selectedLang);
            }
        });
    });
});
