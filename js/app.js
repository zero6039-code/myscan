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

// 2. 🌌 动态黑客帝国二进制矩阵滚动流（精准匹配 HTML 结构，实现真·单个字符随机突变）
function initBinaryStream() {
    // 获取所有的行
    const rows = document.querySelectorAll('.binary-matrix-stream .matrix-row');
    if (rows.length === 0) return;

    // 收集所有行下面原生的 span 节点（排除可能混入的空格或换行文本节点）
    const allSpans = [];
    rows.forEach(row => {
        const spans = row.querySelectorAll('span');
        spans.forEach(span => {
            allSpans.push(span);
        });
    });

    if (allSpans.length === 0) return;

    // 🌟 极高频的分布式位突变引擎
    setInterval(() => {
        // 每次高频周期（45ms）随机挑选 2 到 3 个独立的 span 分组进行位突变
        const mutationCount = Math.floor(Math.random() * 2) + 2; // 2 ~ 3
        
        for (let k = 0; k < mutationCount; k++) {
            // 随机选择一个 span（例如：<span>11100011</span>）
            const targetSpan = allSpans[Math.floor(Math.random() * allSpans.length)];
            if (!targetSpan) continue;

            // 将该 span 的文本打碎成字符数组
            const charArray = Array.from(targetSpan.textContent);
            if (charArray.length === 0) continue;

            // 在这个 span 内部随机挑选一个字符下标
            const randomCharIdx = Math.floor(Math.random() * charArray.length);
            
            // 精准按位翻转
            if (charArray[randomCharIdx] === '0') {
                charArray[randomCharIdx] = '1';
            } else if (charArray[randomCharIdx] === '1') {
                charArray[randomCharIdx] = '0';
            }

            // 精准刷回当前 span，不破坏任何 HTML 结构，排版稳如磐石
            targetSpan.textContent = charArray.join('');
        }
    }, 45); 
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

    // 全局 ESC 键盘监听
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' || e.key === 'Esc') {
            if (modalOverlay.classList.contains('is-open')) {
                closeModal();
            }
        }
    });

    // 限制其他信息 500 字上限并阻断
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
    initBinaryStream(); // 激活全新单点位跳动效果
    window.addEventListener('resize', triggerStatsCounter);
});
