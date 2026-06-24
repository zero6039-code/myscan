// 放到 app.js 的最顶部或 DOMContentLoaded 监听器中
document.addEventListener('DOMContentLoaded', () => {
    // 页面结构加载完成，开始淡入
    document.body.style.opacity = '1';
    
    // 执行你原本的业务逻辑
    triggerStatsCounter();
    initQuoteModal();
    initBinaryStream();
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

// 2. 🌌 动态黑客帝国二进制矩阵滚动流（精准匹配 HTML 结构，实现真·单个数字随机突变）
function initBinaryStream() {
    // 🌟 核心修复 1：完美对齐 HTML 结构，获取全部 10 行元素外壳
    const rows = document.querySelectorAll('.binary-matrix-stream .matrix-row');
    if (rows.length === 0) return;

    // 预设十行各不相同的初始二进制底噪数据（每组8位，共3组，带空格）
    const binaryTemplates = [
        "11010101 00110111 01100111", "01011001 00101001 00000111",
        "10000011 11111100 01110001", "10100100 00111001 10001101",
        "00110111 00010110 01100111", "11011111 10000110 00010110",
        "00110111 01101101 00011000", "11101110 00110011 10100001",
        "10111011 11110111 01101011", "01111101 10010101 00111001"
    ];

    // 初始化每一行的数据容器
    rows.forEach((row, index) => {
        const templateStr = binaryTemplates[index] || binaryTemplates[0];
        // 将字符串打碎为字符数组，挂载到 DOM 对象的自定义属性上（防止污染全局变量）
        row.matrixData = Array.from(templateStr);
        row.textContent = templateStr;
    });

    // 🌟 核心修复 2：极其高效的分布式位突变引擎
    // 彻底废弃原本粗暴的 innerHTML 重写，采用极高频的按位翻转
    setInterval(() => {
        // 每次高频周期（45ms）随机挑选 2 到 3 个独立的数字进行位翻转
        const mutationCount = Math.floor(Math.random() * 2) + 2; // 2 ~ 3
        
        for (let k = 0; k < mutationCount; k++) {
            const randomRowIdx = Math.floor(Math.random() * rows.length);
            const targetRow = rows[randomRowIdx];
            if (!targetRow || !targetRow.matrixData) continue;

            const dataArr = targetRow.matrixData;
            const randomCharIdx = Math.floor(Math.random() * dataArr.length);
            
            // 🔒 只有在遇到真正的二进制数字时才进行突变，完美避开并保留空格排版
            if (dataArr[randomCharIdx] === '0') {
                dataArr[randomCharIdx] = '1';
            } else if (dataArr[randomCharIdx] === '1') {
                dataArr[randomCharIdx] = '0';
            }

            // 精准刷新当前这一行，其它九行完全静止不动，完美形成细微的硬件单点跳动感
            targetRow.textContent = dataArr.join('');
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
