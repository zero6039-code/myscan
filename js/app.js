/**
 * ==========================================================================
 * 🚀 DewSecure 核心业务交互脚本 (数字滚动 + 询价弹窗拦截控制)
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

    counterContainer.offsetHeight; // 触发重绘 (Reflow)
    
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

// 2. 🔢 统一触发数字刷新的入口
function triggerStatsCounter() {
    const counterContainer = document.getElementById("stats-counter");
    if (counterContainer) {
        const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
        animateCounter(target);
    }
}

// 3. 🌌 统一封装询价弹窗控制与图2报错校验逻辑
function initQuoteModal() {
    const modalOverlay = document.getElementById("quote-modal");
    const openBtn = document.getElementById("open-quote-btn");
    const closeBtn = document.getElementById("modal-close-btn");
    const quoteForm = document.getElementById("quote-form");

    if (!modalOverlay) return;

    // 打开弹窗
    if (openBtn) {
        openBtn.addEventListener("click", (e) => {
            e.preventDefault();
            modalOverlay.classList.add("is-open");
        });
    }

    // 关闭弹窗并重置表单与报错态
    function closeModal() {
        modalOverlay.classList.remove("is-open");
        if (quoteForm) {
            const erroredGroups = quoteForm.querySelectorAll(".form-group.has-error");
            erroredGroups.forEach(group => group.classList.remove("has-error"));
            quoteForm.reset();
        }
    }

    if (closeBtn) closeBtn.addEventListener("click", closeModal);
    
    // 点击背景空白区域关闭
    modalOverlay.addEventListener("click", (e) => {
        if (e.target === modalOverlay) closeModal();
    });

    // ❌ 核心：右下角提交校验拦截 (完全对齐图2：红框 + 粉红底 + 文字变红)
    if (quoteForm) {
        quoteForm.addEventListener("submit", (e) => {
            let passed = true;

            // 提交前先清空上一轮的报错状态
            const erroredGroups = quoteForm.querySelectorAll(".form-group.has-error");
            erroredGroups.forEach(group => group.classList.remove("has-error"));

            // 校验 A: 项目/公司
            const companyInput = document.getElementById("form-company");
            if (!companyInput || !companyInput.value.trim()) {
                companyInput?.closest(".form-group").classList.add("has-error");
                passed = false;
            }

            // 校验 B: 电子邮件
            const emailInput = document.getElementById("form-email");
            const emailReg = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailInput || !emailInput.value.trim() || !emailReg.test(emailInput.value.trim())) {
                emailInput?.closest(".form-group").classList.add("has-error");
                passed = false;
            }

            // 校验 C: 联系方式 (Telegram/WhatsApp/WeChat 用户名)
            const contactInput = document.getElementById("form-contact-val");
            if (!contactInput || !contactInput.value.trim()) {
                contactInput?.closest(".form-group").classList.add("has-error");
                passed = false;
            }

            // 如果有任何必填项未通过，强行斩断提交链
            if (!passed) {
                e.preventDefault();
                console.warn("[DewSecure] 表单必填项未通过合规性审查，已拦截提交。");
                return false;
            }

            // 全部校验通过后的逻辑
            e.preventDefault();
            alert("提交成功！DewSecure 团队将尽快与您取得联系。");
            closeModal();
        });
    }
}

// 4. 🏁 统一 DOM 生命周期监听
document.addEventListener('DOMContentLoaded', () => {
    // 执行原有的数字滚动延迟初始化
    setTimeout(triggerStatsCounter, 350); 
    
    // 初始化询价弹窗事件管理
    initQuoteModal();
    
    // 响应式视口改变时重新计算高度并滚动
    window.addEventListener('resize', triggerStatsCounter);
});
