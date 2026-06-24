// DewSecure 完整交互脚本
// 功能：页面淡入 | 数字滚动计数器 | 二进制矩阵动态突变 | 询价弹窗 + 邮件发送

/* ============================================
   0. 生命周期管理
   ============================================ */
document.addEventListener('DOMContentLoaded', () => {
    // 页面淡入
    document.body.style.opacity = '1';

    // 初始化所有功能
    setTimeout(triggerStatsCounter, 350);
    initQuoteModal();
    initBinaryStream();

    // 窗口大小变化时重设计数器
    window.addEventListener('resize', triggerStatsCounter);
});

window.addEventListener('load', () => {
    document.body.classList.add('is-ready');
});


/* ============================================
   1. 数字滚动计数器
   ============================================ */
function animateCounter(targetNumber) {
    const counterContainer = document.getElementById("stats-counter");
    if (!counterContainer) return;

    // 清空现有内容
    counterContainer.innerHTML = "";

    // 把目标数字拆成单个数字
    const digitStringArray = targetNumber.toString().split("");

    // 为每一位数字创建一个滚动槽 (0-9)
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

    // 强制重绘，确保动画生效
    counterContainer.offsetHeight;

    // 获取单个数字的高度
    const firstSpan = slots[0]?.querySelector('span');
    if (!firstSpan) return;
    const singleDigitHeight = firstSpan.offsetHeight;

    // 依次将每一位滚动到目标数字
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


/* ============================================
   2. 二进制矩阵动态跳动 (4 列 × 10 行)
   ============================================ */
function initBinaryStream() {
    // 获取矩阵中的所有行
    const rows = document.querySelectorAll('.binary-matrix-stream .matrix-row');
    if (rows.length === 0) return;

    // 初始 4 列数据（每行 4 个 8 位二进制串）
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

    // 为每一行创建 4 个 <span>，并填入初始数据
    rows.forEach((row, index) => {
        row.innerHTML = '';              // 清空内部（但保留行容器）
        const startIdx = index * 4;
        for (let col = 0; col < 4; col++) {
            const span = document.createElement('span');
            span.textContent = initialData[startIdx + col];
            row.appendChild(span);
        }
    });

    // 定时器：每 45ms 随机翻转 1~2 个位
    setInterval(() => {
        const allSpans = document.querySelectorAll('.binary-matrix-stream .matrix-row span');
        if (allSpans.length === 0) return;

        const mutationCount = Math.floor(Math.random() * 2) + 1; // 1 或 2 次突变
        for (let i = 0; i < mutationCount; i++) {
            // 随机选取一个 <span>
            const randomSpan = allSpans[Math.floor(Math.random() * allSpans.length)];
            const bits = randomSpan.textContent.split('');

            // 随机翻转一位
            const flipIdx = Math.floor(Math.random() * bits.length);
            bits[flipIdx] = bits[flipIdx] === '0' ? '1' : '0';

            randomSpan.textContent = bits.join('');
        }
    }, 45);
}


/* ============================================
   3. 询价弹窗 + 邮件发送 (Formspree)
   ============================================ */
function initQuoteModal() {
    const modalOverlay = document.getElementById("quote-modal");
    const closeBtn = document.getElementById("modal-close-btn");
    const quoteForm = document.getElementById("quote-form");
    const textareaInfo = document.getElementById("form-info");

    if (!modalOverlay) return;

    // ----- 打开弹窗 -----
    document.addEventListener("click", (e) => {
        const triggerBtn = e.target.closest(".btn-cyber-red") || e.target.closest('[data-i18n="hero_btn_quote"]');
        if (triggerBtn && !triggerBtn.closest("#quote-form")) {
            e.preventDefault();
            modalOverlay.classList.add("is-open");
        }
    });

    // ----- 关闭弹窗 -----
    function closeModal() {
        modalOverlay.classList.remove("is-open");
        if (quoteForm) {
            const erroredGroups = quoteForm.querySelectorAll(".form-group.has-error");
            erroredGroups.forEach(group => group.classList.remove("has-error"));
            quoteForm.reset();
        }
    }

    if (closeBtn) closeBtn.addEventListener("click", closeModal);

    // 点击遮罩层关闭
    modalOverlay.addEventListener("click", (e) => {
        if (e.target === modalOverlay) closeModal();
    });

    // ESC 键关闭
    document.addEventListener('keydown', (e) => {
        if ((e.key === 'Escape' || e.key === 'Esc') && modalOverlay.classList.contains('is-open')) {
            closeModal();
        }
    });

    // 限制“其他信息” 500 字
    if (textareaInfo) {
        textareaInfo.addEventListener("input", () => {
            if (textareaInfo.value.length > 500) {
                textareaInfo.value = textareaInfo.value.substring(0, 500);
            }
        });
    }

    // ----- 表单提交：验证 + 发送邮件 -----
    if (quoteForm) {
        quoteForm.addEventListener("submit", async (e) => {
            e.preventDefault(); // 阻止默认提交

            // 清除旧错误状态
            const erroredGroups = quoteForm.querySelectorAll(".form-group.has-error");
            erroredGroups.forEach(group => group.classList.remove("has-error"));

            let passed = true;

            // 校验公司/项目
            const companyInput = document.getElementById("form-company");
            if (!companyInput || !companyInput.value.trim()) {
                companyInput?.closest(".form-group")?.classList.add("has-error");
                passed = false;
            }

            // 校验邮箱
            const emailInput = document.getElementById("form-email");
            const emailReg = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailInput || !emailInput.value.trim() || !emailReg.test(emailInput.value.trim())) {
                emailInput?.closest(".form-group")?.classList.add("has-error");
                passed = false;
            }

            // 校验联系方式
            const contactInput = document.getElementById("form-contact-val");
            if (!contactInput || !contactInput.value.trim()) {
                contactInput?.closest(".form-group")?.classList.add("has-error");
                passed = false;
            }

            // 验证不通过则停止
            if (!passed) return;

            // ----- 构建要发送的数据（无需修改 HTML 的 name 属性）-----
            const payload = {
                company: companyInput.value.trim(),
                email: emailInput.value.trim(),
                contact: contactInput.value.trim(),
                fullname: document.getElementById("form-name")?.value || '',
                role: document.getElementById("form-role")?.value || '',
                service: document.getElementById("form-service")?.value || '',
                message: document.getElementById("form-info")?.value || '',
                _subject: "新的咨询报价请求"   // 邮件标题
            };

            // 替换成你自己的 Formspree 端点
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
