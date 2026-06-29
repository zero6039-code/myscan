// scan-handler.js
// Cloudflare Worker 扫描模块 —— 只读、合法、合规

export async function handleScan(request) {
  const url = new URL(request.url);
  const target = url.searchParams.get('url');

  if (!target) {
    return jsonResponse({ error: '缺少 url 参数' }, 400);
  }

  let targetUrl;
  try {
    targetUrl = new URL(target);
    if (!targetUrl.protocol.startsWith('http')) {
      throw new Error('仅支持 http/https 协议');
    }
    if (isPrivateIp(targetUrl.hostname)) {
      return jsonResponse({ error: '不允许扫描内网地址' }, 403);
    }
  } catch (e) {
    return jsonResponse({ error: '无效的 URL 格式' }, 400);
  }

  let response;
  try {
    response = await fetch(targetUrl.href, {
      method: 'HEAD',
      redirect: 'follow',
      headers: { 'User-Agent': 'DewSecure-Scanner/1.0' },
      signal: AbortSignal.timeout(8000)
    });
  } catch (err) {
    return jsonResponse({ error: '无法连接目标服务器' }, 502);
  }

  const headers = response.headers;

  // CSP 详细分析
  const cspHeader = headers.get('content-security-policy') || '';
  const hasUnsafeInline = /'unsafe-inline'/.test(cspHeader);
  const hasUnsafeEval = /'unsafe-eval'/.test(cspHeader);
  const cspValue = cspHeader || '未设置';
  const cspAnalysis = cspHeader
    ? (hasUnsafeInline && hasUnsafeEval
        ? '包含 unsafe-inline 和 unsafe-eval'
        : hasUnsafeInline
          ? '包含 unsafe-inline'
          : hasUnsafeEval
            ? '包含 unsafe-eval'
            : '策略较严格')
    : '';

  // 服务器信息泄漏分析
  const serverVal = headers.get('server');
  const poweredByVal = headers.get('x-powered-by');
  const serverLeakValue = [serverVal, poweredByVal].filter(Boolean).join(' ') || '未发现信息泄漏';
  const serverLeakRecommendation = serverVal
    ? `已检测到 Server 头暴露了 "${serverVal}"，这通常是 CDN 的正常行为，但请确认源站未额外泄漏技术栈信息。`
    : '隐藏 Server/X-Powered-By 响应头，降低针对性攻击风险。';

  const checks = {
    // ---- 基础核心 8 项 ----
    https: {
      label: 'HTTPS 启用',
      passed: targetUrl.protocol === 'https:',
      value: targetUrl.protocol === 'https:' ? '已启用' : '未启用',
      recommendation: '请将网站迁移至 HTTPS，并强制所有流量使用加密连接。'
    },
    hsts: {
      label: 'Strict-Transport-Security (HSTS)',
      passed: headers.has('strict-transport-security'),
      value: headers.get('strict-transport-security') || '未设置',
      recommendation: '添加 HTTP 头 "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"。'
    },
    xFrameOptions: {
      label: 'X-Frame-Options',
      passed: headers.has('x-frame-options'),
      value: headers.get('x-frame-options') || '未设置',
      recommendation: '设置 "X-Frame-Options: DENY" 或 "SAMEORIGIN" 防止点击劫持。'
    },
    xContentTypeOptions: {
      label: 'X-Content-Type-Options',
      passed: headers.has('x-content-type-options') && headers.get('x-content-type-options').toLowerCase() === 'nosniff',
      value: headers.get('x-content-type-options') || '未设置',
      recommendation: '添加 "X-Content-Type-Options: nosniff" 阻止 MIME 类型嗅探。'
    },
    contentSecurityPolicy: {
      label: 'Content-Security-Policy (CSP)',
      passed: headers.has('content-security-policy'),
      value: cspValue,
      sub: cspAnalysis ? `分析: ${cspAnalysis}` : '',
      recommendation: headers.has('content-security-policy')
        ? (hasUnsafeInline || hasUnsafeEval
            ? 'CSP 存在但包含不安全的指令 (unsafe-inline/unsafe-eval)，建议使用 nonce 或 hash 替代。'
            : 'CSP 策略配置良好。')
        : '实施严格的 CSP 策略，限制资源来源，防范 XSS 攻击。'
    },
    referrerPolicy: {
      label: 'Referrer-Policy',
      passed: headers.has('referrer-policy'),
      value: headers.get('referrer-policy') || '未设置',
      recommendation: '设置 "Referrer-Policy: strict-origin-when-cross-origin"。'
    },
    permissionsPolicy: {
      label: 'Permissions-Policy',
      passed: headers.has('permissions-policy'),
      value: headers.get('permissions-policy') || '未设置',
      recommendation: '使用 Permissions-Policy 限制浏览器 API 访问。'
    },
    serverInfoLeak: {
      label: '服务器信息泄漏',
      passed: !serverVal && !poweredByVal,
      value: serverLeakValue,
      recommendation: serverLeakRecommendation
    },

    // ---- 新增 4 项 ----
    xPermittedCrossDomain: {
      label: 'X-Permitted-Cross-Domain-Policies',
      passed: headers.has('x-permitted-cross-domain-policies'),
      value: headers.get('x-permitted-cross-domain-policies') || '未设置',
      recommendation: '设置 "X-Permitted-Cross-Domain-Policies: none" 以限制 Adobe 产品的跨域请求。'
    },
    crossOriginResourcePolicy: {
      label: 'Cross-Origin-Resource-Policy (CORP)',
      passed: headers.has('cross-origin-resource-policy'),
      value: headers.get('cross-origin-resource-policy') || '未设置',
      recommendation: '设置 "Cross-Origin-Resource-Policy: same-origin" 以限制跨域资源加载。'
    },
    crossOriginOpenerPolicy: {
      label: 'Cross-Origin-Opener-Policy (COOP)',
      passed: headers.has('cross-origin-opener-policy'),
      value: headers.get('cross-origin-opener-policy') || '未设置',
      recommendation: '设置 "Cross-Origin-Opener-Policy: same-origin" 以隔离跨域窗口。'
    },
    cacheControl: {
      label: 'Cache-Control',
      passed: headers.has('cache-control'),
      value: headers.get('cache-control') || '未设置',
      recommendation: '合理设置 Cache-Control 策略，防止敏感页面被缓存（如 "no-store, max-age=0"）。'
    }
  };

  const total = Object.keys(checks).length;
  const passedCount = Object.values(checks).filter(c => c.passed).length;
  const score = `${passedCount}/${total}`;

  const failedItems = Object.values(checks).filter(c => !c.passed);
  const generalAdvice = failedItems.length > 0
    ? `共发现 ${failedItems.length} 个安全问题，请优先修复。此扫描仅检查 HTTP 响应头。`
    : '所有基础安全头均已正确配置。';

  return jsonResponse({
    url: targetUrl.href,
    status: response.status,
    score,
    general_advice: generalAdvice,
    checks: Object.fromEntries(
      Object.entries(checks).map(([key, val]) => [
        key,
        {
          label: val.label,
          passed: val.passed,
          current_value: val.value,
          sub: val.sub || '',
          recommendation: val.recommendation
        }
      ])
    ),
    disclaimer: '本扫描仅读取公开响应头信息，不进行任何主动攻击或未授权渗透测试。完整安全审计请联系 DewSecure 专家。'
  }, 200);
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

function isPrivateIp(hostname) {
  if (hostname === '[::1]' || hostname === 'localhost') return true;
  const parts = hostname.split('.');
  if (parts.length !== 4) return false;
  const nums = parts.map(p => parseInt(p, 10));
  if (nums.some(n => isNaN(n))) return false;
  const [a, b] = nums;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}
