/**
 * DewSecure 核心交互脚本
 * 功能：页面淡入 | 数字滚动计数器 | 二进制矩阵跳动 | 询价弹窗
 */
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

/* 数字滚动 */
function triggerStatsCounter() {
    const container = document.getElementById("stats-counter");
    if (!container) return;
    const target = parseInt(container.getAttribute("data-target")) || 69;
    container.innerHTML = "";
    const digits = target.toString().split("");
    const slots = digits.map(() => {
        const slot = document.createElement("div");
        slot.className = "counter-digit-slot";
        for (let i = 0; i <= 9; i++) {
            const span = document.createElement("span");
            span.innerText = i;
            slot.appendChild(span);
        }
        container.appendChild(slot);
        return slot;
    });
    const h = slots[0]?.querySelector('span')?.offsetHeight || 0;
    digits.forEach((d, i) => {
        setTimeout(() => {
            slots[i].style.transform = `translateY(-${parseInt(d) * h}px)`;
        }, i * 60);
    });
}

/* 二进制矩阵 */
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

/* 弹窗 */
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
        let ok = true;
        form.querySelectorAll(".has-error").forEach(el => el.classList.remove("has-error"));
        const company = document.getElementById("form-company");
        if (!company?.value.trim()) { company?.closest(".form-group")?.classList.add("has-error"); ok = false; }
        const email = document.getElementById("form-email");
        const emailReg = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email?.value.trim() || !emailReg.test(email.value.trim())) { email?.closest(".form-group")?.classList.add("has-error"); ok = false; }
        const contact = document.getElementById("form-contact-val");
        if (!contact?.value.trim()) { contact?.closest(".form-group")?.classList.add("has-error"); ok = false; }
        if (!ok) { e.preventDefault(); return false; }
        e.preventDefault();
        alert("提交成功！DewSecure 团队将尽快与您取得联系。");
        close();
    });
}
