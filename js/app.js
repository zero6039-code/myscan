/**
 * ==========================================================================
 * 🚀 DewSecure 核心业务交互脚本
 * 功能：页面淡入 / 数字滚动计数器 / 二进制矩阵动态突变 / 询价弹窗
 * ==========================================================================
 */

/* -------------------------------------
   0. 页面初始化与生命周期管理
   ------------------------------------- */
document.addEventListener('DOMContentLoaded', () => {
    // 页面结构就绪后开始淡入
    document.body.style.opacity = '1';

    // 启动所有功能模块
    setTimeout(triggerStatsCounter, 350);   // 数字滚动动画
    initQuoteModal();                      // 弹窗事件绑定
    initBinaryStream();                    // 二进制矩阵动态效果

    // 监听窗口大小变化，重新触发计数器（保证滚动位置正确）
    window.addEventListener('resize', triggerStatsCounter);
});

// 所有资源（包括图片）加载完成后，添加就绪状态类（用于显示隐藏的元素）
window.addEventListener('load', () => {
    document.body.classList.add('is-ready');
});


/* -------------------------------------
   1. 🔢 数字滚动计数器
   ------------------------------------- */
function animateCounter(targetNumber) {
    const counterContainer = document.getElementById("stats-counter");
    if (!counterContainer) return;

    // 清空原有内容
    counterContainer.innerHTML = "";

    // 将目标数字拆分为单个数字位
    const digitStringArray = targetNumber.toString().split("");

    // 为每一位数字创建一个滚动槽位（包含 0-9 的 span）
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

    // 强制浏览器重绘，确保后续过渡动画生效
    counterContainer.offsetHeight;

    // 获取单个数字的高度（用于计算 translateY 偏移量）
    const firstSpan = slots[0]?.querySelector('span');
    if (!firstSpan) return;
    const singleDigitHeight = firstSpan.offsetHeight;

    // 依次滚动每一位到目标数字
    digitStringArray.forEach((digitChar, index) => {
        const targetDigit = parseInt(digitChar, 10);
        const finalPixelOffset = targetDigit * singleDigitHeight;

        setTimeout(() => {
            slots[index].style.transform = `translateY(-${finalPixelOffset}px)`;
        }, index * 60); // 轻微的延迟让滚动有错落感
    });
}

function triggerStatsCounter() {
    const counterContainer = document.getElementById("stats-counter");
    if (counterContainer) {
        const target = parseInt(counterContainer.getAttribute("data-target"), 10) || 69;
        animateCounter(target);
    }
}


/* -------------------------------------
   2. 🌌 动态二进制矩阵随机突变（4 列 × 10 行）
   ------------------------------------- */
function initBinaryStream() {
    // 获取 HTML 中原有的 10 行矩阵行容器
    const rows = document.querySelectorAll('.binary-matrix-stream .matrix-row');
    if (rows.length === 0) return;

    // 初始 40 个二进制块（每行 4 个），与 HTML 原始内容一致
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

    // 初始化每一行：确保 DOM 中每行恰好有 4 个 <span> 元素
    rows.forEach((row, index) => {
        row.innerHTML = '';                        // 清空内部（避免残留文本节点）
        const startIdx = index * 4;
        for (let col = 0; col < 4; col++) {
            const span = document.createElement('span');
            span.textContent = initialData[startIdx + col];
            row.appendChild(span);
        }
    });

    // 定时器：每隔 45ms 随机改变 1~2 个二进制块中的某一位
    setInterval(() => {
        const allSpans = document.querySelectorAll('.binary-matrix-stream .matrix-row span');
        if (allSpans.length === 0) return;

        const mutationCount = Math.floor(Math.random() * 2) + 1; // 1 或 2 次突变
        for (let i = 0; i < mutationCount; i++) {
            // 随机选取一个 <span>
            const randomSpan = allSpans[Math.floor(Math.random() * allSpans.length)];
            const bits = randomSpan.textContent.split('');
            // 随机翻转某一位
            const flipIdx = Math.floor(Math.random() * bits.length);
            bits[flipIdx] = bits[flipIdx] === '0' ? '1' : '0';
            randomSpan.textContent = bits.join('');
        }
    }, 45);
}


/* -------------------------------------
   3. 🛡️ 询价弹窗控制逻辑
   ------------------------------------- */
function initQuoteModal() {
    const modalOverlay = document.getElementById("quote-modal");
    const closeBtn = document.getElementById("modal-close-btn");
    const quoteForm = document.getElementById("quote-form");
    const textareaInfo = document.getElementById("form-info");

    if (!modalOverlay) return;

    // 打开弹窗：点击页面中所有“咨询报价”按钮
    document.addEventListener("click", (e) => {
        const triggerBtn = e.target.closest(".btn-cyber-red") ||
                           e.target.closest('[data-i18n="hero_btn_quote"]');
        if (triggerBtn && !triggerBtn.closest("#quote-form")) {
            e.preventDefault();
            modalOverlay.classList.add("is-open");
        }
    });

    // 关闭弹窗的通用函数
    function closeModal() {
        modalOverlay.classList.remove("is-open");
        if (quoteForm) {
            // 移除所有错误状态
            const erroredGroups = quoteForm.querySelectorAll(".form-group.has-error");
            erroredGroups.forEach(group => group.classList.remove("has-error"));
            quoteForm.reset();
        }
    }

    // 关闭按钮点击事件
    if (closeBtn) {
        closeBtn.addEventListener("click", closeModal);
    }

    // 点击遮罩层（背景）关闭弹窗
    modalOverlay.addEventListener("click", (e) => {
        if (e.target === modalOverlay) {
            closeModal();
        }
    });

    // 按下 ESC 键关闭弹窗
    document.addEventListener('keydown', (e) => {
        if ((e.key === 'Escape' || e.key === 'Esc') &&
            modalOverlay.classList.contains('is-open')) {
            closeModal();
        }
    });

    // 限制“其他信息”文本域最多输入 500 个字符
    if (textareaInfo) {
        textareaInfo.addEventListener("input", () => {
            if (textareaInfo.value.length > 500) {
                textareaInfo.value = textareaInfo.value.substring(0, 500);
            }
        });
    }

    // 表单提交验证
    if (quoteForm) {
        quoteForm.addEventListener("submit", (e) => {
            let passed = true;

            // 清除之前的错误样式
            const erroredGroups = quoteForm.querySelectorAll(".form-group.has-error");
            erroredGroups.forEach(group => group.classList.remove("has-error"));

            // 校验公司/项目名称
            const companyInput = document.getElementById("form-company");
            if (!companyInput || !companyInput.value.trim()) {
                companyInput?.closest(".form-group")?.classList.add("has-error");
                passed = false;
            }

            // 校验邮箱格式
            const emailInput = document.getElementById("form-email");
            const emailReg = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailInput || !emailInput.value.trim() || !emailReg.test(emailInput.value.trim())) {
                emailInput?.closest(".form-group")?.classList.add("has-error");
                passed = false;
            }

            // 校验联系方式（WhatsApp）
            const contactInput = document.getElementById("form-contact-val");
            if (!contactInput || !contactInput.value.trim()) {
                contactInput?.closest(".form-group")?.classList.add("has-error");
                passed = false;
            }

            if (!passed) {
                e.preventDefault();
                return false;
            }

            // 验证通过后的处理
            e.preventDefault();
            alert("提交成功！DewSecure 团队将尽快与您取得联系。");
            closeModal();
        });
    }
}
