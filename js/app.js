// DewSecure 最终版（抖动验证 + 防滥用 + 倒计时 + Formspree + 多语言 + 二进制跳动）
// 优化版 v2：修复冷却逻辑、国际化倒计时/按钮文本、防抖滚动、二进制可见性暂停

document.addEventListener('DOMContentLoaded', () => {
    triggerStatsCounter();
    initQuoteModal();
    initBinaryStream();
    // 防抖处理 resize 事件，避免高频重建数字滚动
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(triggerStatsCounter, 200);
    });
});

window.addEventListener('load', () => {
    document.body.classList.add('is-ready');
});

/* ========== 数字滚动 ========== */
function animateCounter(targetNumber) {
    const c = document.getElementById("stats-counter");
    if (!c) return;
    // 如果已有 slot 元素，说明动画正在进行，跳过重复触发
    if (c.querySelector('.counter-digit-slot')) return;

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

/* ========== 二进制矩阵（4列跳动，支持页面隐藏时暂停） ========== */
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

    let binaryInterval = setInterval(() => {
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

    // 页面隐藏时暂停，节省资源
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            clearInterval(binaryInterval);
            binaryInterval = null;
        } else if (!binaryInterval) {
            binaryInterval = setInterval(() => {
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
    });
}

/* ========== 弹窗 + Formspree + 多语言 + 防滥用 + 倒计时 + 抖动验证 ========== */
function initQuoteModal() {
    const overlay = document.getElementById("quote-modal");
    if (!overlay) return;
    const closeBtn = document.getElementById("modal-close-btn");
    const form = document.getElementById("quote-form");
    const textarea = document.getElementById("form-info");

    // 抖动动画函数
    function shakeElement(el) {
        if (!el) return;
        el.style.animation = 'none';
        el.offsetHeight; // 强制回流
        el.style.animation = 'shake-error 0.4s ease-in-out';
        el.addEventListener('animationend', () => {
            el.style.animation = '';
        }, { once: true });
    }

    // 防滥用变量
    let isSubmitting = false;
    const COOLDOWN_SECONDS = 30;
    const MAX_SUBMISSIONS = 5;
    const STORAGE_KEY = 'dewsecure_submissions';

    // 提交按钮及倒计时
    const submitBtn = form?.querySelector('.btn-submit-quote');
    const submitBtnTextSpan = submitBtn?.querySelector('span[data-i18n="hero_btn_quote"]');
    let originalBtnText = 'Consult an Expert'; // 英文默认，与 en.json 保持一致
    let countdownTimer = null;

    /**
     * 从语言包获取当前按钮文本
     * 优先使用 fallbackTranslations，其次取 DOM 文本
     */
    function updateOriginalBtnText() {
        if (submitBtnTextSpan) {
            const key = submitBtnTextSpan.getAttribute('data-i18n');
            if (key && window.fallbackTranslations?.[key]) {
                originalBtnText = window.fallbackTranslations[key];
            } else {
                originalBtnText = submitBtnTextSpan.textContent || 'Consult an Expert';
            }
        }
    }
    // 调用一次初始值
    updateOriginalBtnText();

    /**
     * 获取多语言倒计时模板
     */
    function getCooldownTemplate() {
        // 优先从 fallback 语言包取 btn_wait
        if (window.fallbackTranslations?.btn_wait) {
            return window.fallbackTranslations.btn_wait;
        }
        // 其次根据当前语言硬编码兜底
        const lang = window.currentLang || 'en';
        if (lang === 'zh') return '请稍候 ({seconds}s)';
        if (lang === 'ms') return 'Sila tunggu ({seconds}s)';
        return 'Please wait ({seconds}s)';
    }

    function getSubmissionCount() {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return 0;
        try {
            const records = JSON.parse(raw);
            const now = Date.now();
            const valid = records.filter(time => now - time < 3600000);
            localStorage.setItem(STORAGE_KEY, JSON.stringify(valid));
            return valid.length;
        } catch (e) {
            return 0;
        }
    }

    function recordSubmission() {
        const raw = localStorage.getItem(STORAGE_KEY);
        const records = raw ? JSON.parse(raw) : [];
        records.push(Date.now());
        localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
    }

    function startCooldown(seconds) {
        let remaining = seconds;
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.style.opacity = '0.7';
            submitBtn.style.cursor = 'not-allowed';
        }
        const template = getCooldownTemplate();

        function updateBtnText() {
            if (submitBtnTextSpan) {
                submitBtnTextSpan.textContent = template.replace('{seconds}', remaining);
            }
        }
        updateBtnText();

        countdownTimer = setInterval(() => {
            remaining--;
            if (remaining <= 0) {
                clearInterval(countdownTimer);
                countdownTimer = null;
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.style.opacity = '1';
                    submitBtn.style.cursor = 'pointer';
                }
                if (submitBtnTextSpan) {
                    // 恢复时为当前语言的按钮文本
                    updateOriginalBtnText();
                    submitBtnTextSpan.textContent = originalBtnText;
                }
                isSubmitting = false;
            } else {
                updateBtnText();
            }
        }, 1000);
    }

    // 打开弹窗
    document.addEventListener("click", (e) => {
        if (e.target.closest(".btn-cyber-red") || e.target.closest('[data-i18n="hero_btn_quote"]')) {
            if (!e.target.closest("#quote-form")) {
                e.preventDefault();
                // 每次打开弹窗时刷新按钮文本（可能已切换语言）
                updateOriginalBtnText();
                overlay.classList.add("is-open");
            }
        }
    });

    /**
     * 关闭弹窗
     * @param {boolean} keepCooldown - 提交成功后传 true，不清除冷却状态
     */
    function close(keepCooldown = false) {
        overlay.classList.remove("is-open");
        if (form) {
            form.querySelectorAll(".has-error").forEach(el => el.classList.remove("has-error"));
            form.reset();
        }
        // 仅在非提交成功的情况下清除冷却
        if (!keepCooldown && countdownTimer) {
            clearInterval(countdownTimer);
            countdownTimer = null;
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.style.opacity = '1';
                submitBtn.style.cursor = 'pointer';
            }
            if (submitBtnTextSpan) {
                updateOriginalBtnText();
                submitBtnTextSpan.textContent = originalBtnText;
            }
            isSubmitting = false;
        }
    }

    closeBtn?.addEventListener("click", () => close());
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && overlay.classList.contains("is-open")) close();
    });

    // 输入长度限制
    textarea?.addEventListener("input", () => {
        if (textarea.value.length > 2000) textarea.value = textarea.value.substring(0, 2000);
    });

    // 表单提交
    form?.addEventListener("submit", async (e) => {
        e.preventDefault();

        // 清除错误样式
        form.querySelectorAll(".has-error").forEach(el => el.classList.remove("has-error"));

        if (isSubmitting) {
            // 使用语言包中的提示（如有）
            const waitMsg = (window.fallbackTranslations?.btn_wait || 'Please wait, your request is being processed...');
            alert(waitMsg.replace('{seconds}', ''));
            return;
        }

        const count = getSubmissionCount();
        if (count >= MAX_SUBMISSIONS) {
            // 超限提示：中文兜底
            const limitMsg = (window.currentLang === 'zh')
                ? '提交次数已超过每小时限制，请稍后再试。感谢您的关注！'
                : (window.currentLang === 'ms'
                    ? 'Anda telah melebihi had penyerahan setiap jam. Sila cuba lagi kemudian.'
                    : 'You have exceeded the hourly submission limit. Please try again later.');
            alert(limitMsg);
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.style.opacity = '0.5';
                submitBtn.style.cursor = 'not-allowed';
            }
            return;
        }

        // 蜜罐检查
        const honeypot = document.getElementById('fax');
        if (honeypot && honeypot.value.trim() !== '') {
            // 机器人填了蜜罐，假装成功
            alert(document.getElementById('alert-success')?.textContent || 'Submission successful!');
            close();
            return;
        }

        let ok = true;

        const company = document.getElementById("form-company");
        if (!company?.value.trim()) {
            company?.closest(".form-group")?.classList.add("has-error");
            shakeElement(company);
            ok = false;
        }

        const email = document.getElementById("form-email");
        const emailReg = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email?.value.trim() || !emailReg.test(email.value.trim())) {
            email?.closest(".form-group")?.classList.add("has-error");
            shakeElement(email);
            ok = false;
        }

        const contact = document.getElementById("form-contact-val");
        if (!contact?.value.trim()) {
            contact?.closest(".form-group")?.classList.add("has-error");
            // 抖动整个通道容器
            shakeElement(contact?.closest(".custom-single-channel"));
            ok = false;
        }

        if (!ok) return;

        // 锁定提交
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

        // 隐藏元素中的语言包文本（已由 i18n 填充）
        const msgSuccess = document.getElementById('alert-success')?.textContent
            || 'Submission successful! The DewSecure team will contact you shortly.';
        const msgEmailError = document.getElementById('alert-email-error')?.textContent
            || 'Please check if the email address is correct.';
        const msgNetworkError = document.getElementById('alert-network-error')?.textContent
            || 'Network error, please try again later.';

        // ★★★ 先启动冷却，再关闭弹窗（确保冷却不被清除）★★★
        const shouldCooldown = !countdownTimer;

        try {
            const response = await fetch('https://formspree.io/f/xojojwrq', {
                method: 'POST',
                headers: { 'Accept': 'application/json' },
                body: formData
            });

            if (response.ok) {
                recordSubmission();
                if (shouldCooldown) {
                    startCooldown(COOLDOWN_SECONDS);
                }
                alert(msgSuccess);
                // 关闭弹窗但保留冷却状态
                close(true);
            } else {
                // 提交失败，解锁
                const data = await response.json();
                alert(data.errors ? msgEmailError : msgNetworkError);
                isSubmitting = false;
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.style.opacity = '1';
                    submitBtn.style.cursor = 'pointer';
                }
            }
        } catch (error) {
            alert(msgNetworkError);
            isSubmitting = false;
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.style.opacity = '1';
                submitBtn.style.cursor = 'pointer';
            }
        }
    });
}
