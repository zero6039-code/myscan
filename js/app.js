// 放到 app.js 的最顶部或 DOMContentLoaded 监听器中
document.addEventListener('DOMContentLoaded', () => {
    // 页面结构加载完成，开始淡入
    document.body.style.opacity = '1';

    // 执行你原本的业务逻辑
    triggerStatsCounter();
    initQuoteModal();
    initBinaryStream();
});

window.addEventListener('load', () => {
    document.body.classList.add('is-ready');
});


/**
 * ==========================================================================
 * 🚀 DewSecure 核心业务交互脚本 (数字滚动 + 询价弹窗 + 邮件发送)
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

// 2. 🌌 动态黑客帝国二进制矩阵滚动流（3列空格跳动）
function initBinaryStream() {
    const rows = document.querySelectorAll('.binary-matrix-stream .matrix-row');
    if (rows.length === 0) return;

    const binaryTemplates = [
        "11010101 00110111 01100111", "01011001 00101001 00000111",
        "10000011 11111100 01110001", "10100100 00111001 10001101",
        "00110111 00010110 01100111", "11011111 10000110 00010110",
        "00110111 01101101 00011000", "11101110 00110011 10100001",
        "10111011 11110111 01101011", "01111101 10010101 00111001"
    ];

    rows.forEach((row, index) => {
        const tpl = binaryTemplates[index] || binaryTemplates[0];
        row.matrixData = Array.from(tpl);
        row.textContent = tpl;
    });

    setInterval(() => {
        const mutationCount = Math.floor(Math.random() * 2) + 2;
        for (let k = 0; k < mutationCount; k++) {
            const targetRow = rows[Math.floor(Math.random() * rows.length)];
            if (!targetRow || !targetRow.matrixData) continue;
            const arr = targetRow.matrixData;
            const idx = Math.floor(Math.random() * arr.length);
            if (arr[idx] === '0') arr[idx] = '1';
            else if (arr[idx] === '1') arr[idx] = '0';
            targetRow.textContent = arr.join('');
        }
    }, 45);
}

// 3. 🛡️ 询价弹窗核心控制逻辑（含邮件发送）
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

    // 表单提交拦截校验 + 发送邮件 (使用你的 Formspree 端点)
    if (quoteForm) {
        quoteForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            // 清除错误样式
            const erroredGroups = quoteForm.querySelectorAll(".form-group.has-error");
            erroredGroups.forEach(group => group.classList.remove("has-error"));

            let passed = true;

            const companyInput = document.getElementById("form-company");
            if (!companyInput || !companyInput.value.trim()) {
                companyInput?.closest(".form-group")?.classList.add("has-error");
                passed = false;
            }

            const emailInput = document.getElementById("form-email");
            const emailReg = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailInput || !emailInput.value.trim() || !emailReg.test(emailInput.value.trim())) {
                emailInput?.closest(".form-group")?.classList.add("has-error");
                passed = false;
            }

            const contactInput = document.getElementById("form-contact-val");
            if (!contactInput || !contactInput.value.trim()) {
                contactInput?.closest(".form-group")?.classList.add("has-error");
                passed = false;
            }

            if (!passed) return;

            // 构建要发送的数据
            const payload = {
                company: companyInput.value.trim(),
                email: emailInput.value.trim(),
                contact: contactInput.value.trim(),
                fullname: document.getElementById("form-name")?.value || '',
                role: document.getElementById("form-role")?.value || '',
                service: document.getElementById("form-service")?.value || '',
                message: document.getElementById("form-info")?.value || '',
                _subject: "新的咨询报价请求"
            };

            // 你的 Formspree 端点
            const FORMSPREE_URL = 'https://formspree.io/f/xojojwrq';

            try {
                const response = await fetch(FORMSPREE_URL, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify(payload)
                });

                if (response.ok) {
                    alert("提交成功！DewSecure 团队将尽快与您取得联系。");
                    closeModal();
                } else {
                    const data = await response.json();
                    if (data.errors) {
                        alert("请检查邮箱地址是否正确。");
                    } else {
                        alert("发送失败，请稍后重试。");
                    }
                }
            } catch (error) {
                console.error('发送错误:', error);
                alert("网络错误，请稍后再试。");
            }
        });
    }
}

// 4. 🏁 统一生命周期监听
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(triggerStatsCounter, 350);
    initQuoteModal();
    initBinaryStream();
    window.addEventListener('resize', triggerStatsCounter);
});
