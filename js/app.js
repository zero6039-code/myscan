// DewSecure 交互脚本（含邮件发送）
document.addEventListener('DOMContentLoaded', () => {
    document.body.style.opacity = '1';
    triggerStatsCounter();
    initQuoteModal();
    initBinaryStream();
    window.addEventListener('resize', triggerStatsCounter);
});
window.addEventListener('load', () => {
    document.body.classList.add('is-ready');
});

/* ========== 1. 数字滚动 ========== */
function triggerStatsCounter() {
    const c = document.getElementById("stats-counter");
    if (!c) return;
    const target = parseInt(c.getAttribute("data-target")) || 69;
    const digits = target.toString().split("");
    c.innerHTML = "";
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

/* ========== 2. 二进制矩阵跳动 ========== */
function initBinaryStream() {
    const rows = document.querySelectorAll('.binary-matrix-stream .matrix-row');
    if (!rows.length) return;
    const data = [
        "11100011","01100001","01101100","10101011",
        "00001111","01011100","00011100","01101010",
        "10111001","10100000","00010111","11100001",
        "01110101","01101011","11110000","00011011",
        "11101011","10110011","00010111","10101000",
        "01011001","00100111","00010101","01110011",
        "01110110","00100100","01100100","11000110",
        "10001010","10000100","00100101","01011101",
        "00011010","10101101","10010001","11100011",
        "11010101","10001010","11001110","00001111"
    ];
    rows.forEach((row, i) => {
        row.innerHTML = '';
        for (let j = 0; j < 4; j++) {
            const span = document.createElement('span');
            span.textContent = data[i * 4 + j];
            row.appendChild(span);
        }
    });
    setInterval(() => {
        const spans = document.querySelectorAll('.binary-matrix-stream .matrix-row span');
        for (let k = 0; k < 2; k++) {
            const s = spans[Math.floor(Math.random() * spans.length)];
            if (!s) continue;
            const bits = s.textContent.split('');
            const idx = Math.floor(Math.random() * bits.length);
            bits[idx] = bits[idx] === '0' ? '1' : '0';
            s.textContent = bits.join('');
        }
    }, 45);
}

/* ========== 3. 弹窗 + 邮件发送 ========== */
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

    textarea?.addEventListener("input", () => {
        if (textarea.value.length > 500) textarea.value = textarea.value.substring(0, 500);
    });

    // 提交表单（async 关键字在这里！）
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

        if (!ok) return;   // 验证不通过，直接返回

        // 构建发送数据
        const payload = {
            company: company.value.trim(),
            email: email.value.trim(),
            contact: contact.value.trim(),
            fullname: document.getElementById("form-name")?.value || '',
            role: document.getElementById("form-role")?.value || '',
            service: document.getElementById("form-service")?.value || '',
            message: document.getElementById("form-info")?.value || '',
            _subject: "新的咨询报价请求"
        };

        const FORMSPREE_URL = 'https://formspree.io/f/xojojwrq';  // 替换为你的端点

        try {
            const response = await fetch(FORMSPREE_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                alert("提交成功！DewSecure 团队将尽快与您取得联系。");
                close();
            } else {
                const data = await response.json();
                alert(data.errors ? "请检查邮箱地址是否正确。" : "发送失败，请稍后重试。");
            }
        } catch (error) {
            console.error('发送错误:', error);
            alert("网络错误，请稍后再试。");
        }
    });
}
