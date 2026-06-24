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

// 2. 🌌 动态黑客帝国二进制矩阵滚动流（精准匹配 HTML 结构，实现真·单个数字随机突变）
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

    // 存储所有真正可以用来突变的数字 span 节点
    const digitSpans = [];

    // 初始化：用 span 标签包裹每一个字符，锁死排版
    rows.forEach((row, index) => {
        const templateStr = binaryTemplates[index] || binaryTemplates[0];
        row.innerHTML = ""; // 清空原有文本

        Array.from(templateStr).forEach(char => {
            const span = document.createElement('span');
            if (char === ' ') {
                // 使用不换行空格，确保三列间距绝对固定
                span.innerHTML = '&nbsp;'; 
            } else {
                span.textContent = char;
                span.className = 'matrix-digit'; // 方便以后加单独的渐变或高亮样式
                digitSpans.push(span); // 只有数字才加入突变池
            }
            row.appendChild(span);
        });
    });

    // 🌟 极高频的分布式按位精准突变引擎
    setInterval(() => {
        if (digitSpans.length === 0) return;
        
        // 每次高频周期随机挑选 2 到 3 个独立的数字节点进行翻转
        const mutationCount = Math.floor(Math.random() * 2) + 2; // 2 ~ 3
        
        for (let k = 0; k < mutationCount; k++) {
            const randomSpan = digitSpans[Math.floor(Math.random() * digitSpans.length)];
            
            // 精确单点翻转，不触发整行重绘，排版坚如磐石
            if (randomSpan.textContent === '0') {
                randomSpan.textContent = '1';
            } else if (randomSpan.textContent === '1') {
                randomSpan.textContent = '0';
            }
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
