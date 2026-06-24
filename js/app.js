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

// 2. 🌌 动态黑客帝国二进制矩阵滚动流（含自动结构修复）
function initBinaryStream() {
    // 获取所有的行
    const rows = document.querySelectorAll('.binary-matrix-stream .matrix-row');
    if (rows.length === 0) return;

    // ========== 新增：自动修复结构（解决“乱码”问题） ==========
    rows.forEach(row => {
        // 只处理当 row 内只有一个 span 且内容超过 7 个字符的情况
        const spans = row.querySelectorAll('span');
        if (spans.length === 1) {
            const text = spans[0].textContent.replace(/\s/g, '');
            // 检查是否是一长串二进制数字（长度 > 7）
            if (text.length > 7 && /^[01]+$/.test(text)) {
                // 按 7 位一组分割
                const fragments = [];
                for (let i = 0; i < text.length; i += 7) {
                    const chunk = text.substr(i, 7);
                    if (chunk.length === 7) { // 只取完整的 7 位
                        fragments.push(chunk);
                    }
                }
                // 如果拆出的组数 ≥ 4，则重建 row（取前 4 组）
                if (fragments.length >= 4) {
                    row.innerHTML = ''; // 清空
                    fragments.slice(0, 4).forEach(bits => {
                        const span = document.createElement('span');
                        span.textContent = bits;
                        row.appendChild(span);
                    });
                }
            }
        }
    });

    // 重新收集所有 span（现在每行应该有 4 个了）
    const allSpans = [];
    rows.forEach(row => {
        const spans = row.querySelectorAll('span');
        spans.forEach(span => {
            allSpans.push(span);
        });
    });

    if (allSpans.length === 0) return;

    // 🌟 极高频的分布式位突变引擎（每 45ms 随机翻转 2~3 个字符）
    setInterval(() => {
        const mutationCount = Math.floor(Math.random() * 2) + 2; // 2 ~ 3
        
        for (let k = 0; k < mutationCount; k++) {
            const targetSpan = allSpans[Math.floor(Math.random() * allSpans.length)];
            if (!targetSpan) continue;

            const charArray = Array.from(targetSpan.textContent);
            if (charArray.length === 0) continue;

            const randomCharIdx = Math.floor(Math.random() * charArray.length);
            
            // 按位翻转
            charArray[randomCharIdx] = charArray[randomCharIdx] === '0' ? '1' : '0';
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
                textareaInfo.value = textareaInfo.value.substring(0, 500);
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
    initBinaryStream(); // 激活二进制矩阵动态流（含结构修复）
    window.addEventListener('resize', triggerStatsCounter);
});
