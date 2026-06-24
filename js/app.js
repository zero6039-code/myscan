// DewSecure 稳定版（无邮件功能，二进制跳动3列原始效果）
document.addEventListener('DOMContentLoaded', () => {
    document.body.style.opacity = '1';
    setTimeout(triggerStatsCounter, 350);
    initQuoteModal();
    initBinaryStream();
    window.addEventListener('resize', triggerStatsCounter);
});

window.addEventListener('load', () => {
    document.body.classList.add('is-ready');
});

// 1. 数字滚动
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

// 2. 二进制矩阵（保留你原本的3列空格跳动方式）
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

// 3. 弹窗（仅验证，无邮件）
function initQuoteModal() {
    const overlay = document.getElementById("quote-modal");
    if (!overlay) return;
    const closeBtn = document.getElementById("modal-close-btn");
    const form = document.getElementById("quote-form");
    const textarea = document.getElementById("form-info");

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

    form?.addEventListener("submit", (e) => {
        e.preventDefault();
        let ok = true;
        form.querySelectorAll(".has-error").forEach(el => el.classList.remove("has-error"));
        const company = document.getElementById("form-company");
        if (!company?.value.trim()) { company?.closest(".form-group")?.classList.add("has-error"); ok = false; }
        const email = document.getElementById("form-email");
        if (!email?.value.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim())) { email?.closest(".form-group")?.classList.add("has-error"); ok = false; }
        const contact = document.getElementById("form-contact-val");
        if (!contact?.value.trim()) { contact?.closest(".form-group")?.classList.add("has-error"); ok = false; }
        if (!ok) return;
        alert("提交成功！");
        close();
    });
}
