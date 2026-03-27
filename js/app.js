// ==================== 配置 ====================
const API_BASE = 'https://myscan-henna.vercel.app'; // 替换为您的 Vercel 域名
const API_SCAN = `${API_BASE}/api/scan`;

// ==================== 国际化文本库（与之前相同，增加深度选择文本） ====================
const i18n = {
    en: {
        // ... 原有内容 ...
        quickScan: 'Quick Scan',
        deepScan: 'Deep Scan',
        // 新增阶段文本
        phaseBasic: 'Fetching basic info...',
        phaseSecurity: 'Checking security headers...',
        phaseSensitive: 'Scanning sensitive files...',
        phaseXss: 'Testing XSS...',
        phaseSql: 'Testing SQL injection...',
        phaseDir: 'Testing directory traversal...',
        phaseHttp: 'Checking HTTP methods...',
        phaseInfo: 'Analyzing information leakage...',
        phaseCors: 'Checking CORS...',
        phaseCms: 'Detecting CMS...',
        phaseSsl: 'Analyzing SSL/TLS...',
        phaseComplete: 'Complete!',
        // 新增折叠文本
        collapse: 'Collapse',
        expand: 'Expand'
    },
    zh: {
        // ... 原有内容 ...
        quickScan: '快速扫描',
        deepScan: '深度扫描',
        phaseBasic: '获取基础信息...',
        phaseSecurity: '检测安全头...',
        phaseSensitive: '扫描敏感文件...',
        phaseXss: '测试 XSS...',
        phaseSql: '测试 SQL 注入...',
        phaseDir: '测试目录遍历...',
        phaseHttp: '检查 HTTP 方法...',
        phaseInfo: '分析信息泄露...',
        phaseCors: '检查 CORS...',
        phaseCms: '识别 CMS...',
        phaseSsl: '分析 SSL/TLS...',
        phaseComplete: '完成！',
        collapse: '折叠',
        expand: '展开'
    }
};

// ... 其余辅助函数与之前相同（t, escapeHtml, getRemediationText, createCard, showDetailedInfo, safeFetchJson, renderResult, exportReport, exportPDF 等）...

// 新增：导出 HTML 报告
async function exportHTML() {
    if (!window.lastScanData) return;
    const element = resultContainer.cloneNode(true);
    element.querySelectorAll('.copy-btn, .info-btn, .collapse-icon').forEach(btn => btn.remove());
    element.style.padding = '20px';
    element.style.backgroundColor = 'white';
    element.style.color = 'black';
    element.style.width = '800px';
    const htmlContent = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>MyScan Report</title><style>body{font-family:sans-serif;padding:20px} .result-card{border:1px solid #ccc;margin-bottom:20px;padding:10px}</style></head>
<body>${element.outerHTML}</body>
</html>`;
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_report_${new Date().toISOString()}.html`;
    a.click();
    URL.revokeObjectURL(url);
}

// 修改 createCard 支持折叠
function createCard(title, contentHtml, extraClass = '', vulnerabilityType = null, defaultCollapsed = false) {
    const card = document.createElement('div');
    card.className = `result-card ${extraClass}`;
    const copyBtnHtml = `<button class="copy-btn" data-copy="${escapeHtml(contentHtml).replace(/"/g, '&quot;')}">${t('copy')}</button>`;
    const infoBtnHtml = vulnerabilityType ? `<button class="info-btn" data-type="${vulnerabilityType}" data-title="${escapeHtml(title)}">${t('infoButton')}</button>` : '';
    const collapseIcon = defaultCollapsed ? '▶' : '▼';
    card.innerHTML = `
        <div class="card-header">
            <span><span class="collapse-icon">${collapseIcon}</span> 📋 ${escapeHtml(title)}</span>
            <div class="card-actions">
                ${infoBtnHtml}
                ${copyBtnHtml}
            </div>
        </div>
        <div class="card-body ${defaultCollapsed ? 'collapsed' : ''}">${contentHtml}</div>
    `;
    const header = card.querySelector('.card-header');
    const body = card.querySelector('.card-body');
    const icon = header.querySelector('.collapse-icon');
    header.addEventListener('click', (e) => {
        if (e.target.classList.contains('copy-btn') || e.target.classList.contains('info-btn')) return;
        const isCollapsed = body.classList.toggle('collapsed');
        icon.textContent = isCollapsed ? '▶' : '▼';
    });
    // ... 复制按钮和 info 按钮逻辑不变 ...
    return card;
}

// 修改 renderResult 中基础卡片默认折叠（例如响应头卡片）
function renderResult(data) {
    // ... 前面代码不变 ...
    // 基础信息卡片：折叠响应头（将响应头内容单独放入折叠部分？）但为了简单，我们让整个基础卡片折叠？不，我们只折叠响应头区域。为了保持结构，我们可以在基础卡片内部分离。更简单：让整个卡片可折叠，但基础信息本身重要，可以默认展开。我们只对非关键卡片（如响应头、CSP、信息泄露等）默认折叠。
    // 我们修改基础卡片，将响应头放入可折叠区域。但为了不复杂，我们保留原有基础卡片结构，单独为响应头添加折叠？但需要重构。我们选择让基础卡片整体可折叠？不合理。更好的做法：保持基础卡片展开，但在卡片内部为响应头添加折叠。由于时间，我们暂不实现内部折叠，而是让整个卡片可折叠，但基础卡片默认展开。
    // 我们修改 createCard 调用，传入 defaultCollapsed 参数。
    // 例如：响应头卡片（即安全头部卡片）默认折叠？但安全头部很重要，不折叠。我们折叠信息泄露、CORS、CMS等。
    const basicCard = createCard(t('basicInfo'), `...`, '', null, false); // 不折叠
    // 安全头部卡片默认展开
    const securityCard = createCard(t('securityHeaders'), securityHtml, '', 'securityHeaders', false);
    // 敏感文件卡片默认展开
    const sensitiveCard = createCard(t('sensitiveFiles'), sensitiveHtml, '', 'sensitiveFiles', false);
    // XSS、SQL、目录遍历、HTTP方法默认展开
    // 信息泄露、CORS、CMS、CSP、SSL 默认折叠
    const infoCard = createCard(t('infoLeakage'), infoHtml, '', 'infoLeakage', true);
    const corsCard = createCard(t('cors'), corsHtml, '', 'cors', true);
    const cmsCard = createCard(t('cms'), cmsHtml, '', 'cms', true);
    if (cspCard) cspCard = createCard(t('csp'), cspHtml, '', 'csp', true);
    // SSL 卡片（新增）
    let sslCard = null;
    if (data.ssl) {
        let sslHtml = '';
        if (data.ssl.error) {
            sslHtml = `<div class="info-value">Error: ${escapeHtml(data.ssl.error)}</div>`;
        } else {
            sslHtml = `
                <div class="info-row"><span class="info-label">Protocol:</span><span class="info-value">${escapeHtml(data.ssl.protocol)}</span></div>
                <div class="info-row"><span class="info-label">Cipher:</span><span class="info-value">${escapeHtml(data.ssl.cipher)}</span></div>
                <div class="info-row"><span class="info-label">Certificate:</span><span class="info-value">${escapeHtml(JSON.stringify(data.ssl.certificate, null, 2))}</span></div>
                <div class="info-row"><span class="info-label">Weak Protocol:</span><span class="info-value">${data.ssl.weakProtocol ? 'Yes' : 'No'}</span></div>
            `;
            if (data.ssl.vulnerabilities.weakProtocol) {
                sslHtml += `<div class="remediation-box"><strong>⚠️ Weak protocol detected. Upgrade to TLSv1.2 or higher.</strong></div>`;
            }
            if (data.ssl.vulnerabilities.expiredCert) {
                sslHtml += `<div class="remediation-box"><strong>⚠️ Certificate expired. Renew immediately.</strong></div>`;
            }
        }
        sslCard = createCard('SSL/TLS Configuration', sslHtml, '', 'ssl', true);
    }
    // 添加 SSL 卡片到 resultContainer
    if (sslCard) resultContainer.appendChild(sslCard);
    // ... 其余不变
}

// 修改 scan 函数：添加深度参数、阶段进度、输入校验
async function scan() {
    let url = targetInput.value.trim();
    if (!url) {
        errorContainer.textContent = t('pleaseEnterUrl');
        errorContainer.style.display = 'block';
        return;
    }
    // 输入校验：过滤危险协议
    if (/^javascript:/i.test(url) || /^data:/i.test(url) || /^vbscript:/i.test(url)) {
        errorContainer.textContent = t('errorPrefix') + 'Invalid URL protocol';
        errorContainer.style.display = 'block';
        return;
    }
    if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
        targetInput.value = url;
    }

    const depth = document.querySelector('input[name="depth"]:checked').value;
    scanBtn.disabled = true;
    scanBtn.textContent = t('scanning');
    loadingDiv.style.display = 'block';
    progressContainer.style.display = 'block';
    resultContainer.style.display = 'none';
    errorContainer.style.display = 'none';
    exportContainer.style.display = 'none';
    scanTimeDiv.style.display = 'none';

    // 模拟进度阶段
    const phases = [
        { text: t('phaseBasic'), duration: 800 },
        { text: t('phaseSecurity'), duration: 500 },
        { text: t('phaseSensitive'), duration: 1200 },
        { text: t('phaseXss'), duration: 1000 },
        { text: t('phaseSql'), duration: 1000 },
        { text: t('phaseDir'), duration: 800 },
        { text: t('phaseHttp'), duration: 600 },
        { text: t('phaseInfo'), duration: 800 },
        { text: t('phaseCors'), duration: 500 },
        { text: t('phaseCms'), duration: 700 },
        { text: t('phaseSsl'), duration: 1000 }
    ];
    let phaseIndex = 0;
    let progress = 0;
    progressFill.style.width = '0%';
    progressMessage.textContent = phases[0].text;

    const phaseInterval = setInterval(() => {
        if (phaseIndex < phases.length) {
            progressMessage.textContent = phases[phaseIndex].text;
            phaseIndex++;
        } else {
            clearInterval(phaseInterval);
        }
    }, 1000); // 每秒更新一次阶段，实际请求完成会覆盖

    // 实际请求开始计时
    scanStartTime = Date.now();

    try {
        const data = await safeFetchJson(API_SCAN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, depth })
        });
        clearInterval(phaseInterval);
        progressFill.style.width = '100%';
        progressMessage.textContent = t('phaseComplete');
        setTimeout(() => {
            progressContainer.style.display = 'none';
        }, 500);
        loadingDiv.style.display = 'none';
        renderResult(data);
    } catch (err) {
        clearInterval(phaseInterval);
        loadingDiv.style.display = 'none';
        progressContainer.style.display = 'none';
        errorContainer.textContent = t('errorPrefix') + err.message;
        errorContainer.style.display = 'block';
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = currentLang === 'en' ? 'Start Scan' : '开始扫描';
    }
}

// 添加 HTML 导出按钮事件
const htmlBtn = document.getElementById('html-btn');
if (htmlBtn) htmlBtn.addEventListener('click', exportHTML);

// ... 其他事件绑定不变
