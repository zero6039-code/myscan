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

// 2. 🌌 动态黑客帝国二进制矩阵滚动流（保留 4 列 span 结构，实现位翻转跳动）
function initBinaryStream() {
    const rows = document.querySelectorAll('.binary-matrix-stream .matrix-row');
    if (rows.length === 0) return;

    // 初始 4 列数据（每行 4 个 8-bit 二进制串，对应 HTML 原始内容）
    const initialData = [
        "11100011", "01100001", "01101100", "10101011",
        "00001111", "01011100", "00011100", "01101010",
        "10111001", "10100000", "00010111", "11100001",
        "01110101", "01101011", "11110000", "00011011",
        "11101011", "10110011", "00010111", "10101000",
        "01011001", "00100111", "00010101", "01110011",
        "01110110", "00100100", "01100100", "11000110",
        "10001010", "10000100", "00100101", "01011101",
        "00011010", "10101101", "10010001", "11100011",
        "11010101", "10001010", "11001110", "00001111"
    ];

    // 初始化：确保每行恰好有 4 个 <span>，并填入初始数据
    rows.forEach((row, index) => {
        row.innerHTML = '';                         // 清空原内容（保留容器）
        const startIdx = index * 4;
        for (let col = 0; col < 4; col++) {
            const span = document.createElement('span');
            span.textContent = initialData[startIdx + col];
            row.appendChild(span);
        }
    });

    // 定时器：每隔 45ms 随机翻转 1~2 个 <span> 中的某一位
    setInterval(() => {
        const allSpans = document.querySelectorAll('.binary-matrix-stream .matrix-row span');
        if (allSpans.length === 0) return;

        const mutationCount = Math.floor(Math.random() * 2) + 1; // 1 或 2 次突变
        for (let i = 0; i < mutationCount; i++) {
            const randomSpan = allSpans[Math.floor(Math.random() * allSpans.length)];
            const bits = randomSpan.textContent.split('');
            const flipIdx = Math.floor(Math.random() * bits.length);
            // 翻转位
            bits[flipIdx] = bits[flipIdx] === '0' ? '1' : '0';
            randomSpan.textContent = bits.join('');
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

    // 表单提交拦截校验 + 邮件发送
    if (quoteForm) {
        quoteForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            let passed = true;
            const erroredGroups = quoteForm.querySelectorAll(".form-group.has-error");
            erroredGroups.forEach(group => group.classList.remove("has-error"));

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

            // 验证失败直接返回
            if (!passed) return;

            // ===== 验证通过，构建数据并发送邮件 =====
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

            const FORMSPREE_URL = 'https://formspree.io/f/xojojwrq';  // 请确认是你的端点

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
