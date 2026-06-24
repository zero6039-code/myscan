// DewSecure 最终版 (FormData 邮件稳定发送 + 多语言提示)
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

/* ========== 二进制矩阵 ========== */
function initBinaryStream() {
    const rows = document.querySelectorAll('.binary-matrix-stream .matrix-row');
    if (!rows.length) return;
    const data = [
        "11010101 00110111 01100111","01011001 00101001 00000111",
        "10000011 11111100 01110001","10100100 00111001 10001101",
        "00110111 00010110 01100111","11011111 10000110 00010110",
        "00110111 01101101 00011000","11101110 00110011 10100001",
        "10111011 11110111 01101011","01111101 10010101 00111001"
    ];
    rows.forEach((row, i) => {
        row.matrixData = Array.from(data[i] || data[0]);
        row.textContent = data[i] || data[0];
    });
    setInterval(() => {
        for (let k = 0; k < 2; k++) {
            const row = rows[Math.floor(Math.random() * rows.length)];
            if (!row || !row.matrixData) continue;
            const arr = row.matrixData;
            const idx = Math.floor(Math.random() * arr.length);
            if (arr[idx] === '0') arr[idx] = '1';
            else if (arr[idx] === '1') arr[idx] = '0';
            row.textContent = arr.join('');
        }
    }, 45);
}

/* ========== 弹窗 + 邮件 + 多语言 ========== */
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

    // 限制500字
    textarea?.addEventListener("input", () => {
        if (textarea.value.length > 500) textarea.value = textarea.value.substring(0, 500);
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

        // 构建 FormData (与测试成功的方式完全一致)
        const formData = new FormData();
        formData.append('email', email.value.trim());
        formData.append('company', company.value.trim());
        formData.append('contact', contact.value.trim());
        formData.append('fullname', document.getElementById("form-name")?.value || '');
        formData.append('role', document.getElementById("form-role")?.value || '');
        formData.append('service', document.getElementById("form-service")?.value || '');
        formData.append('message', document.getElementById("form-info")?.value || '');
        formData.append('_subject', '新的咨询报价请求');

        // 多语言提示
        const msgSuccess = document.getElementById('alert-success')?.textContent || '提交成功！';
        const msgEmailError = document.getElementById('alert-email-error')?.textContent || '请检查邮箱地址是否正确。';
        const msgNetworkError = document.getElementById('alert-network-error')?.textContent || '网络错误，请稍后再试。';

        try {
            const response = await fetch('https://formspree.io/f/xojojwrq', {
                method: 'POST',
                headers: { 'Accept': 'application/json' },
                body: formData
            });
            if (response.ok) {
                alert(msgSuccess);
                close();
            } else {
                const data = await response.json();
                alert(data.errors ? msgEmailError : msgNetworkError);
            }
        } catch (error) {
            alert(msgNetworkError);
        }
    });
}
