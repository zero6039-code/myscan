// 在文件顶部添加修复建议映射
const remediationMap = {
    // 安全头部
    'X-Frame-Options': '缺少该头可能导致点击劫持攻击。建议添加: `X-Frame-Options: SAMEORIGIN`',
    'X-Content-Type-Options': '缺少该头可能导致 MIME 类型混淆攻击。建议添加: `X-Content-Type-Options: nosniff`',
    'X-XSS-Protection': '缺少该头可能降低浏览器 XSS 防护。建议添加: `X-XSS-Protection: 1; mode=block`',
    'Strict-Transport-Security': '缺少 HSTS 可能使 HTTPS 降级。建议添加: `Strict-Transport-Security: max-age=31536000; includeSubDomains`',
    'Content-Security-Policy': '缺少 CSP 可能导致 XSS 风险。建议添加合适的策略，如: `default-src \'self\'`',
    // 敏感文件
    '/robots.txt': '暴露了网站目录结构。建议限制敏感路径或移除不必要信息。',
    '/.env': '严重泄露环境变量。立即删除或禁止访问。',
    '/.git/config': '泄露 Git 仓库信息。删除或限制访问。',
    '/backup.zip': '备份文件可被下载。移除或设置强访问控制。',
    '/admin': '管理后台暴露。建议添加身份验证或隐藏路径。',
    '/phpinfo.php': '泄露 PHP 配置信息。删除该文件。',
    // XSS
    xss: '反射型 XSS 可被利用执行恶意脚本。建议对用户输入进行严格过滤和转义，使用内容安全策略。',
    // SQL 注入
    sql: 'SQL 注入可导致数据泄露或篡改。使用参数化查询、预编译语句，避免拼接 SQL。',
    // 目录遍历
    dirTraversal: '目录遍历漏洞可读取任意文件。严格限制文件路径，使用白名单验证。',
    // HTTP 方法
    httpMethods: (methods) => `允许危险 HTTP 方法: ${methods.join(', ')}。建议禁用不必要的方法（如 PUT, DELETE, TRACE）。`,
    // 信息泄露
    infoLeakage: '响应中可能包含敏感信息（邮箱、手机号、API 密钥）。审查并移除这些信息。',
    // CSP 问题
    cspUnsafeInline: 'CSP 中使用了 `unsafe-inline`，降低了 XSS 防护强度。建议使用 nonce 或 hash 替代。',
    cspMissingDefaultSrc: 'CSP 缺少 `default-src` 指令，可能导致策略不完整。建议添加 `default-src \'self\'`。'
};

// 生成修复建议文本
function getRemediationText(category, detail = null) {
    if (category === 'missingHeaders') {
        return remediationMap[detail] || '建议添加缺失的安全响应头以提高站点安全性。';
    }
    if (category === 'sensitiveFiles') {
        return remediationMap[detail] || '敏感文件泄露可能导致信息泄露，请限制访问或移除。';
    }
    if (category === 'xss') {
        return remediationMap.xss;
    }
    if (category === 'sql') {
        return remediationMap.sql;
    }
    if (category === 'dirTraversal') {
        return remediationMap.dirTraversal;
    }
    if (category === 'httpMethods') {
        return remediationMap.httpMethods(detail);
    }
    if (category === 'infoLeakage') {
        return remediationMap.infoLeakage;
    }
    if (category === 'cspUnsafeInline') {
        return remediationMap.cspUnsafeInline;
    }
    if (category === 'cspMissingDefaultSrc') {
        return remediationMap.cspMissingDefaultSrc;
    }
    return '';
}

// 修改 renderResult 函数，在每个卡片内部添加修复建议（如果有）
function renderResult(data) {
    resultContainer.innerHTML = '';
    errorContainer.style.display = 'none';

    // 基础信息卡片（不变）
    const basicCard = createCard(t('basicInfo'), `
        <div class="info-row"><span class="info-label">${t('urlLabel')}:</span><span class="info-value">${escapeHtml(data.url)}</span></div>
        <div class="info-row"><span class="info-label">${t('statusLabel')}:</span><span class="info-value">${data.basic.status || '?'}</span></div>
        <div class="info-row"><span class="info-label">${t('titleLabel')}:</span><span class="info-value">${escapeHtml(data.basic.title || '')}</span></div>
        <div class="info-row"><span class="info-label">${t('headersLabel')}:</span><span class="info-value"><pre>${escapeHtml(JSON.stringify(data.basic.headers, null, 2))}</pre></span></div>
    `);

    // 安全头部卡片（增加修复建议）
    const missing = data.security?.missingHeaders || [];
    let securityHtml = '';
    if (missing.length === 0) {
        securityHtml = `<div class="info-value">${t('noMissingHeaders')}</div>`;
    } else {
        securityHtml = `<div class="info-value">${missing.map(h => `<span class="badge">${escapeHtml(h)}</span>`).join('')}</div>`;
        // 为每个缺失的头添加修复建议
        securityHtml += `<div class="remediation-box"><strong>🔧 修复建议：</strong><br>${missing.map(h => `• ${escapeHtml(h)}: ${getRemediationText('missingHeaders', h)}`).join('<br>')}</div>`;
    }
    const securityCard = createCard(t('securityHeaders'), securityHtml);

    // 敏感文件卡片
    const sensitive = data.sensitiveFiles || [];
    let sensitiveHtml = '';
    if (sensitive.length === 0) {
        sensitiveHtml = `<div class="info-value">${t('noSensitiveFiles')}</div>`;
    } else {
        sensitiveHtml = `<div class="info-value">${sensitive.map(f => `<span class="badge vuln-badge">${escapeHtml(f)}</span>`).join('')}</div>`;
        sensitiveHtml += `<div class="remediation-box"><strong>🔧 修复建议：</strong><br>${sensitive.map(f => `• ${escapeHtml(f)}: ${getRemediationText('sensitiveFiles', f)}`).join('<br>')}</div>`;
    }
    const sensitiveCard = createCard(t('sensitiveFiles'), sensitiveHtml);

    // XSS 卡片
    let xssHtml = '';
    if (data.xss?.vulnerable) {
        xssHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.xss.param)}<br>URL: ${escapeHtml(data.xss.url)}</div>`;
        xssHtml += `<div class="remediation-box"><strong>🔧 修复建议：</strong> ${getRemediationText('xss')}</div>`;
    } else {
        xssHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noXss')}</div>`;
    }
    const xssCard = createCard(t('xss'), xssHtml);

    // SQL 注入卡片
    let sqlHtml = '';
    if (data.sqlInjection?.vulnerable) {
        sqlHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.sqlInjection.param)}<br>URL: ${escapeHtml(data.sqlInjection.url)}${data.sqlInjection.note ? `<br>${t('note')}: ${escapeHtml(data.sqlInjection.note)}` : ''}</div>`;
        sqlHtml += `<div class="remediation-box"><strong>🔧 修复建议：</strong> ${getRemediationText('sql')}</div>`;
    } else {
        sqlHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> ${t('noSql')}</div>`;
    }
    const sqlCard = createCard(t('sql'), sqlHtml);

    // 目录遍历卡片
    let dirHtml = '';
    if (data.directoryTraversal?.vulnerable) {
        dirHtml = `<div class="info-value"><span class="badge vuln-badge">${t('vulnerable')}</span> ${t('parameter')}: ${escapeHtml(data.directoryTraversal.param)}<br>Payload: ${escapeHtml(data.directoryTraversal.payload)}</div>`;
        dirHtml += `<div class="remediation-box"><strong>🔧 修复建议：</strong> ${getRemediationText('dirTraversal')}</div>`;
    } else {
        dirHtml = `<div class="info-value"><span class="badge safe-badge">${t('notVulnerable')}</span> 未检测到目录遍历漏洞。</div>`;
    }
    const dirCard = createCard('目录遍历 (Directory Traversal)', dirHtml);

    // HTTP 方法卡片
    let httpHtml = '';
    const allowed = data.httpMethods?.allowed || [];
    if (allowed.length > 0) {
        httpHtml = `<div class="info-value"><span class="badge vuln-badge">允许的危险方法</span> ${allowed.join(', ')}</div>`;
        httpHtml += `<div class="remediation-box"><strong>🔧 修复建议：</strong> ${getRemediationText('httpMethods', allowed)}</div>`;
    } else {
        httpHtml = `<div class="info-value"><span class="badge safe-badge">未发现危险 HTTP 方法</span></div>`;
    }
    const httpCard = createCard('HTTP 方法', httpHtml);

    // 信息泄露卡片
    let infoHtml = '';
    const leaks = data.infoLeakage || {};
    if (Object.keys(leaks).length > 0) {
        infoHtml = `<div class="info-value"><span class="badge vuln-badge">发现敏感信息</span><br>`;
        for (const [type, items] of Object.entries(leaks)) {
            infoHtml += `<strong>${type}:</strong> ${items.join(', ')}<br>`;
        }
        infoHtml += `</div><div class="remediation-box"><strong>🔧 修复建议：</strong> ${getRemediationText('infoLeakage')}</div>`;
    } else {
        infoHtml = `<div class="info-value"><span class="badge safe-badge">未发现明显信息泄露</span></div>`;
    }
    const infoCard = createCard('敏感信息泄露', infoHtml);

    // CSP 分析卡片（如果有）
    let cspCard = null;
    if (data.security?.csp) {
        const csp = data.security.csp;
        let cspHtml = `<div class="info-value"><pre>${escapeHtml(JSON.stringify(csp.directives, null, 2))}</pre></div>`;
        if (csp.issues.unsafeInline) {
            cspHtml += `<div class="remediation-box"><strong>🔧 修复建议：</strong> ${getRemediationText('cspUnsafeInline')}</div>`;
        }
        if (csp.issues.missingDefaultSrc) {
            cspHtml += `<div class="remediation-box"><strong>🔧 修复建议：</strong> ${getRemediationText('cspMissingDefaultSrc')}</div>`;
        }
        cspCard = createCard('CSP 策略分析', cspHtml);
    }

    // 免责声明卡片
    const disclaimerCard = createCard('', `<div style="font-size:14px;">${t('disclaimer')}</div>`, 'disclaimer-card');
    disclaimerCard.querySelector('.card-header').innerHTML = `⚠️ ${t('disclaimer')}`;

    // 按顺序添加
    resultContainer.appendChild(basicCard);
    resultContainer.appendChild(securityCard);
    resultContainer.appendChild(sensitiveCard);
    resultContainer.appendChild(xssCard);
    resultContainer.appendChild(sqlCard);
    resultContainer.appendChild(dirCard);
    resultContainer.appendChild(httpCard);
    resultContainer.appendChild(infoCard);
    if (cspCard) resultContainer.appendChild(cspCard);
    resultContainer.appendChild(disclaimerCard);

    resultContainer.style.display = 'block';
    exportContainer.style.display = 'block';
    window.lastScanData = data;
}