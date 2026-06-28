// DewSecure 最终版（Web3Forms 双向邮件 + 自动回复 + 多语言）
document.addEventListener('DOMContentLoaded', () => {
    triggerStatsCounter();
    initQuoteModal();
    initBinaryStream();
    window.addEventListener('resize', triggerStatsCounter);
});
window.addEventListener('load', () => {
    document.body.classList.add('is-ready');
});

/* ========== 数字滚动 ========== */
function animateCounter(targetNumber) {
    const c = document.getElementById("stats-counter");
    if (!c) return;
    c.innerHTML = "";
    const digits = targetNumber.toString().split("");
    const slots = digits.map(() => {
        const slot = document.createElement("div");
        slot.className = "counter-digit-slot";
        for (let i = 0; i <= 9; i++) {
            const span = document.createElement("span");
            span.innerText = i;
            slot.appendChild(span);
        }
        c.appendChild(slot);
        return slot;
    });
    const h = slots[0]?.querySelector('span')?.offsetHeight || 0;
    digits.forEach((d, i) => {
        setTimeout(() => {
            slots[i].style.transform = `translateY(-${parseInt(d) * h}px)`;
        }, i * 60);
    });
}

function triggerStatsCounter() {
    const container = document.getElementById("stats-counter");
    if (container) {
        const target = parseInt(container.getAttribute("data-target")) || 69;
        animateCounter(target);
    }
}

/* ========== 二进制矩阵（4列跳动，保留<span>结构） ========== */
function initBinaryStream() {
    const rows = document.querySelectorAll('.binary-matrix-stream .matrix-row');
    if (!rows.length) return;

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

    rows.forEach((row, index) => {
        row.innerHTML = '';
        const startIdx = index * 4;
        for (let col = 0; col < 4; col++) {
            const span = document.createElement('span');
            span.textContent = initialData[startIdx + col];
            row.appendChild(span);
        }
    });

    setInterval(() => {
        const allSpans = document.querySelectorAll('.binary-matrix-stream .matrix-row span');
        if (allSpans.length === 0) return;

        const mutationCount = Math.floor(Math.random() * 2) + 1;
        for (let i = 0; i < mutationCount; i++) {
            const randomSpan = allSpans[Math.floor(Math.random() * allSpans.length)];
            const bits = randomSpan.textContent.split('');
            const flipIdx = Math.floor(Math.random() * bits.length);
            bits[flipIdx] = bits[flipIdx] === '0' ? '1' : '0';
            randomSpan.textContent = bits.join('');
        }
    }, 45);
}

/* ========== 弹窗 + Web3Forms 邮件 + 多语言 ========== */
function initQuoteModal() {
    const overlay = document.getElementById("quote-modal");
    if (!overlay) return;
    const closeBtn = document.getElementById("modal-close-btn");
    const form = document.getElementById("quote-form");
    const textarea = document.getElementById("form-info");

    // 打开弹窗
    document.addEventListener("click", (e) => {
        if (e.target.closest(".btn-cyber-red") || e.target.closest('[data-i18n="hero_btn_quote"]')) {
            if (!e.target.closest("#quote-form")) {
                e.preventDefault();
                overlay.classList.add("is-open");
            }
        }
    });

    // 关闭弹窗
    function close() {
        overlay.classList.remove("is-open");
        if (form) {
            form.querySelectorAll(".has-error").forEach(el => el.classList.remove("has-error"));
            form.reset();
        }
    }
    closeBtn?.addEventListener("click", close);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && overlay.classList.contains("is-open")) close();
    });

    // 限制输入长度
    textarea?.addEventListener("input", () => {
        if (textarea.value.length > 2000) textarea.value = textarea.value.substring(0, 2000);
    });

    // 表单提交
    form?.addEventListener("submit", async (e) => {
        e.preventDefault();

        // 清除错误样式
        form.querySelectorAll(".has-error").forEach(el => el.classList.remove("has-error"));
        let ok = true;

        const company = document.getElementById("form-company");
        if (!company?.value.trim()) { company?.closest(".form-group")?.classList.add("has-error"); ok = false; }

        const email = document.getElementById("form-email");
        if (!email?.value.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim())) { email?.closest(".form-group")?.classList.add("has-error"); ok = false; }

        const contact = document.getElementById("form-contact-val");
        if (!contact?.value.trim()) { contact?.closest(".form-group")?.classList.add("has-error"); ok = false; }

        if (!ok) return;

        // 获取服务名称（文本内容）
        const serviceSelect = document.getElementById("form-service");
        const serviceText = serviceSelect?.options[serviceSelect.selectedIndex]?.text || '';

        // 构建 Web3Forms 发送数据
        const payload = {
            access_key: 'b2e02c7e-07d5-4ac4-81e9-3be596d089fe',  // 你的 Access Key
            subject: '新的咨询报价请求',                         // 你收到的邮件标题
            from_name: 'DewSecure Contact Form',
            replyto: email.value.trim(),                        // 客户回复地址

            // 业务字段
            company: company.value.trim(),
            email: email.value.trim(),
            contact: contact.value.trim(),
            fullname: document.getElementById("form-name")?.value || '',
            role: document.getElementById("form-role")?.value || '',
            service: serviceText,
            message: document.getElementById("form-info")?.value || '',

            // 自动回复设置
            auto_reply: "true",
            auto_reply_subject: document.getElementById('auto-reply-subject')?.textContent || 'DewSecure 收到您的咨询',
            auto_reply_message: document.getElementById('auto-reply-message')?.textContent || '尊敬的客户，您好！我们已经收到您的咨询请求，我们的团队会尽快查看并回复您。感谢您的等待。'
        };

        // 多语言提示
        const msgSuccess = document.getElementById('alert-success')?.textContent || '提交成功！DewSecure 团队将尽快与您取得联系。';
        const msgEmailError = document.getElementById('alert-email-error')?.textContent || '请检查邮箱地址是否正确。';
        const msgNetworkError = document.getElementById('alert-network-error')?.textContent || '网络错误，请稍后再试。';

        try {
            const response = await fetch('https://api.web3forms.com/submit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (data.success) {
                alert(msgSuccess);
                close();
            } else {
                console.error('Web3Forms Error:', data);
                alert(data.message || msgNetworkError);
            }
        } catch (error) {
            console.error('Network Error:', error);
            alert(msgNetworkError);
        }
    });
}
