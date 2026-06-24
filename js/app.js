/**
 * ==========================================================================
 * 🚀 DewSecure 核心业务交互脚本 (数字滚动 + 询价弹窗多功能定制)
 * ==========================================================================
 */

// 1. 🔢 统一管理数字滚动的核心逻辑
function animateCounter(targetNumber) {
    const counterContainer = document.getElementById("stats-counter");
    if (!counterContainer) return;

    counterContainer.innerHTML = "";
    const digitStringArray = targetNumber.toString().split("");

    const slots = digitStringArray.map(() => {
        const slot = document.createElement("div");
        slot.className = "counter-digit-slot";
        for (let i = 0; i <= 9; i++) {
            const numSpan = document.createElement("span");
            numSpan.innerText = i;
            slot.appendChild(numSpan);
        }
        counterContainer.appendChild(slot);
        return slot;
    });

    counterContainer.offsetHeight; // 触发重绘
    
    const firstSpan = slots[0]?.querySelector('span');
    if (!firstSpan) return;
    const singleDigitHeight = firstSpan.offsetHeight; 

    digitStringArray.forEach((digitChar, index) => {
        const targetDigit = parseInt(digitChar, 10);
        const finalPixelOffset = targetDigit * singleDigitHeight;
        
        setTimeout(() => {
            slots[index].style.transform = `translateY(-${finalPixelOffset}px)`;
        }, index * 60);
    });
}

function triggerStatsCounter() {
    const counterContainer = document.getElementById("stats-counter");
    if (counterContainer) {
        const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
        animateCounter(target);
    }
}

// 2. 🌌 动态黑客帝国二进制矩阵滚动流（对应需求 1 & 2）
function initBinaryStream() {
    const streamContainer = document.getElementById("binary-stream");
    if (!streamContainer) return;

    // 定时随机刷新二进制数组，制造“号码不停地跑”的动态黑客效果
    setInterval(() => {
        const rows = 5;
        let htmlContent = "";
        for (let i = 0; i < rows; i++) {
            let rowText = "";
            for (let j = 0; j < 4; j++) {
                // 随机生成 8 位二进制字节
                const byte = Array.from({length: 8}, () => Math.round(Math.random())).join("");
                rowText += byte + " ";
            }
            htmlContent += `<div>${rowText.trim()}</div>`;
        }
        streamContainer.innerHTML = htmlContent;
    }, 120); // 每 120ms 剧烈闪烁跑动一次
}

// 3. 🛡️ 询价弹窗核心控制逻辑
function initQuoteModal() {
    const modalOverlay = document.getElementById("quote-modal");
    const closeBtn = document.getElementById("modal-close-btn");
    const quoteForm = document.getElementById("quote-form");
    const textareaInfo = document.getElementById("form-info");

    if (!modalOverlay) return;

    // 点击事件代理唤起弹窗
    document.addEventListener("click", (e) => {
        const triggerBtn = e.target.closest(".btn-cyber-red") || e.target.closest('[data-i18n="hero_btn_quote"]');
        if (triggerBtn && !triggerBtn.closest("#quote-form")) { 
            e.preventDefault();
            modalOverlay.classList.add("is-open");
        }
    });

    // 关闭弹窗并重置
    function closeModal() {
        modalOverlay.classList.remove("is-open");
        if (quoteForm) {
            const erroredGroups = quoteForm.querySelectorAll(".form-group.has-error");
            erroredGroups.forEach(group => group.classList.remove("has-error"));
            quoteForm.reset();
        }
    }

    if (closeBtn) closeBtn.addEventListener("click", closeModal);
    modalOverlay.addEventListener("click", (e) => {
        if (e.target === modalOverlay) closeModal();
    });

    // 🔒 限制其他信息 500 字上限并阻断（对应需求 5）
    if (textareaInfo) {
        textareaInfo.addEventListener("input", () => {
            if (textareaInfo.value.length > 500) {
                textareaInfo.value = textareaInfo.value.substring(0, 500); // 强行截断
            }
        });
    }

    // 表单提交拦截校验
    if (quoteForm) {
        quoteForm.addEventListener("submit", (e) => {
            let passed = true;
            const erroredGroups = quoteForm.querySelectorAll(".form-group.has-error");
            erroredGroups.forEach(group => group.classList.remove("has-error"));

            const companyInput = document.getElementById("form-company");
            if (!companyInput || !companyInput.value.trim()) {
                companyInput?.closest(".form-group").classList.add("has-error");
                passed = false;
            }

            const emailInput = document.getElementById("form-email");
            const emailReg = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailInput || !emailInput.value.trim() || !emailReg.test(emailInput.value.trim())) {
                emailInput?.closest(".form-group").classList.add("has-error");
                passed = false;
            }

            const contactInput = document.getElementById("form-contact-val");
            if (!contactInput || !contactInput.value.trim()) {
                contactInput?.closest(".form-group").classList.add("has-error");
                passed = false;
            }

            if (!passed) {
                e.preventDefault();
                return false;
            }

            e.preventDefault();
            alert("提交成功！DewSecure 团队将尽快与您取得联系。");
            closeModal();
        });
    }
}

// 4. 🏁 统一生命周期监听
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(triggerStatsCounter, 350); 
    initQuoteModal();
    initBinaryStream(); // 注入动态数字跑动
    
    // 🌟 在这里注入 ESC 键监听
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const modal = document.getElementById("quote-modal");
            if (modal && modal.classList.contains('active')) {
                modal.classList.remove('active');
                document.body.style.overflow = '';
            }
        }
    });

    window.addEventListener('resize', triggerStatsCounter);
});
