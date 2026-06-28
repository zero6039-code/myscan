// DewSecure 最终稳定版（4列二进制跳动 + Formspree 邮件 + 多语言 + 防滥用）
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

/* ========== 弹窗 + Formspree 邮件 + 多语言 + 防滥用 ========== */
function initQuoteModal() {
    const overlay = document.getElementById("quote-modal");
    if (!overlay) return;
    const closeBtn = document.getElementById("modal-close-btn");
    const form = document.getElementById("quote-form");
    const textarea = document.getElementById("form-info");

    // 防滥用变量
    let isSubmitting = false;
    const COOLDOWN_SECONDS = 30;          // 按钮冷却时间（秒）
    const MAX_SUBMISSIONS = 5;            // 每小时最大提交次数
    const STORAGE_KEY = 'dewsecure_submissions';

    // 获取当前时间窗口内的提交次数
    function getSubmissionCount() {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return 0;
        try {
            const records = JSON.parse(raw);
            const now = Date.now();
            // 保留最近一小时的记录
            const valid = records.filter(time => now - time < 3600000);
            localStorage.setItem(STORAGE_KEY, JSON.stringify(valid));
            return valid.length;
        } catch (e) {
            return 0;
        }
    }

    // 记录一次提交
    function recordSubmission() {
        const raw = localStorage.getItem(STORAGE_KEY);
        const records = raw ? JSON.parse(raw) : [];
        records.push(Date.now());
        localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
    }

    // 获取提交按钮
    const submitBtn = form?.querySelector('.btn-submit-quote');

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

    // 限制输入长度 (2000字，更友好)
    textarea?.addEventListener("input", () => {
        if (textarea.value.length > 2000) textarea.value = textarea.value.substring(0, 2000);
    });

    // 表单提交
    form?.addEventListener("submit", async (e) => {
        e.preventDefault();

        // 清除错误样式
        form.querySelectorAll(".has-error").forEach(el => el.classList.remove("has-error"));

        // 检查是否正在提交中（按钮锁定）
        if (isSubmitting) {
            alert('请稍等，您的请求正在处理中...');
            return;
        }

        // 频率限制检查
        const count = getSubmissionCount();
        if (count >= MAX_SUBMISSIONS) {
            alert('提交次数已超过每小时限制，请稍后再试。感谢您的关注！');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.style.opacity = '0.5';
                submitBtn.style.cursor = 'not-allowed';
            }
            return;
        }

        // 蜜罐检查：隐藏字段 #fax 被填写则拒绝（需要在HTML中添加 <input type="text" id="fax" style="display:none" tabindex="-1" autocomplete="off">）
        const honeypot = document.getElementById('fax');
        if (honeypot && honeypot.value.trim() !== '') {
            // 假装成功，但实际不发送
            const msgSuccess = document.getElementById('alert-success')?.textContent || '提交成功！';
            alert(msgSuccess);
            close();
            return;
        }

        let ok = true;

        const company = document.getElementById("form-company");
        if (!company?.value.trim()) { company?.closest(".form-group")?.classList.add("has-error"); ok = false; }

        const email = document.getElementById("form-email");
        if (!email?.value.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim())) { email?.closest(".form-group")?.classList.add("has-error"); ok = false; }

        const contact = document.getElementById("form-contact-val");
        if (!contact?.value.trim()) { contact?.closest(".form-group")?.classList.add("has-error"); ok = false; }

        if (!ok) return;

        // 锁定提交状态
        isSubmitting = true;
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.style.opacity = '0.6';
            submitBtn.style.cursor = 'wait';
        }

        // 构建 FormData
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
        const msgSuccess = document.getElementById('alert-success')?.textContent || '提交成功！DewSecure 团队将尽快与您取得联系。';
        const msgEmailError = document.getElementById('alert-email-error')?.textContent || '请检查邮箱地址是否正确。';
        const msgNetworkError = document.getElementById('alert-network-error')?.textContent || '网络错误，请稍后再试。';

        try {
            const response = await fetch('https://formspree.io/f/xojojwrq', {
                method: 'POST',
                headers: { 'Accept': 'application/json' },
                body: formData
            });

            if (response.ok) {
                recordSubmission();  // 记录成功提交
                alert(msgSuccess);
                close();
            } else {
                const data = await response.json();
                alert(data.errors ? msgEmailError : msgNetworkError);
            }
        } catch (error) {
            alert(msgNetworkError);
        } finally {
            // 冷却计时器：30秒后恢复按钮
            if (submitBtn) {
                setTimeout(() => {
                    isSubmitting = false;
                    submitBtn.disabled = false;
                    submitBtn.style.opacity = '1';
                    submitBtn.style.cursor = 'pointer';
                }, COOLDOWN_SECONDS * 1000);
            }
        }
    });
}
