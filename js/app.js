/**
 * ==========================================================================\n * 🚀 DewSecure 核心业务交互脚本 (性能优化与架构修复版)
 * ==========================================================================\n */

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

    // 触发重绘以确保 DOM 节点生成
    counterContainer.offsetHeight; 

    // 🛡️ 架构优化：多阶段安全提取精准高度，完美应对字体未加载或动态缩放
    const measureAndAnimate = () => {
        const firstSpan = slots[0]?.querySelector('span');
        if (!firstSpan) return;
        const singleDigitHeight = firstSpan.offsetHeight;
        if (singleDigitHeight === 0) return; // 如果尚未布局完成，等待下一轮机制触发

        digitStringArray.forEach((digitChar, index) => {
            const targetDigit = parseInt(digitChar, 10);
            const finalPixelOffset = targetDigit * singleDigitHeight;
            
            setTimeout(() => {
                if (slots[index]) {
                    slots[index].style.transform = `translateY(-${finalPixelOffset}px)`;
                }
            }, index * 60);
        });
    };

    measureAndAnimate();

    // 监听容器大小改变（比如由于视口缩放或字体加载完毕导致的高度坍塌），自适应重新对齐
    if (window.ResizeObserver && !counterContainer.hasObserver) {
        const ro = new ResizeObserver(() => {
            measureAndAnimate();
        });
        ro.observe(counterContainer);
        counterContainer.hasObserver = true;
    }
}

function triggerStatsCounter() {
    const counterContainer = document.getElementById("stats-counter");
    if (!counterContainer) return;
    // 固定的业务展现目标数字
    animateCounter(69);
}

// 2. 🔏 弹窗控制总线与防滚动穿透
function initQuoteModal() {
    const openBtn = document.getElementById("nav-btn-quote") || document.querySelector(".btn-hero-quote");
    const openBtnHero = document.querySelector(".hero-right-box .btn-submit-quote") || document.querySelector("[data-i18n='hero_btn_quote'] Folks")?.closest('button');
    const modalOverlay = document.getElementById("quote-modal-overlay");
    const closeBtn = document.getElementById("modal-close-btn");
    const quoteForm = document.getElementById("cyber-quote-form");

    if (!modalOverlay) return;

    const openModal = () => {
        modalOverlay.classList.add("active");
        // 🔒 防止移动端滚动穿透，死锁底层 body 手势
        document.body.style.overflow = "hidden";
    };

    const closeModal = () => {
        modalOverlay.classList.remove("active");
        document.body.style.overflow = "";
    };

    // 弹性绑定多个可能触发弹窗的按钮
    if (openBtn) openBtn.addEventListener("click", openModal);
    document.querySelectorAll(".btn-hero-quote, [data-open-modal]").forEach(btn => {
        btn.addEventListener("click", openModal);
    });

    if (closeBtn) closeBtn.addEventListener("click", closeModal);
    
    modalOverlay.addEventListener("click", (e) => {
        if (e.target === modalOverlay) closeModal();
    });

    // 表单健壮性校验
    if (quoteForm) {
        quoteForm.addEventListener("submit", function(e) {
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

// 3. 💾 高性能二进制密码流特效 (优化 DOM 频繁回流)
function initBinaryStream() {
    const streamContainer = document.getElementById("binary-stream");
    if (!streamContainer) return;

    const rowCount = 5;
    const byteCountPerRow = 4;
    
    // 初始化时仅生成一次 DOM 结构，后续只更新文本内容，杜绝 innerHTML 性能缺陷
    streamContainer.innerHTML = "";
    const textNodes = [];

    for (let i = 0; i < rowCount; i++) {
        const row = document.createElement("div");
        row.style.lineHeight = "1.4";
        for (let j = 0; j < byteCountPerRow; j++) {
            const span = document.createElement("span");
            span.style.marginRight = "12px";
            const textNode = document.createTextNode("");
            span.appendChild(textNode);
            row.appendChild(span);
            textNodes.push(textNode);
        }
        streamContainer.appendChild(row);
    }

    const getRandomByte = () => {
        return Math.floor(Math.random() * 256).toString(16).toUpperCase().padStart(2, '0');
    };

    // 高频定时器只修改纯文本节点，不引发布局树重构（Reflow）
    setInterval(() => {
        textNodes.forEach(node => {
            node.nodeValue = getRandomByte();
        });
    }, 140);
}

// 4. 🏁 统一生命周期多重防线
document.addEventListener('DOMContentLoaded', () => {
    initQuoteModal();
    initBinaryStream();
    triggerStatsCounter();
});

window.addEventListener('load', () => {
    // 终极防线：当网络资源及 WebFont 彻底全加载完后，强制修正一次数字高度
    triggerStatsCounter();
});

window.addEventListener('resize', triggerStatsCounter);
