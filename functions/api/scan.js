// functions/api/scan.js
// Cloudflare Pages Function: 简易HTTP安全头扫描器
// 仅检查公开响应头，不进行任何主动攻击或深入扫描，完全合规。

export async function onRequestGet(context) {
  const { request } = context;
  const requestUrl = new URL(request.url);
  const target = requestUrl.searchParams.get('url');

  // 1. 基础校验
  if (!target) {
    return new Response(JSON.stringify({ error: '缺少 url 参数' }), {
      status: 400,
      headers: corsHeaders()
    });
  }

  let targetUrl;
  try {
    targetUrl = new URL(target);
    if (!targetUrl.protocol.startsWith('http')) {
      throw new Error('仅支持 http/https 协议');
    }
    // 防止 SSRF：屏蔽内网地址
    if (isPrivateIp(targetUrl.hostname)) {
      return new Response(JSON.stringify({ error: '不允许扫描内网地址' }), {
        status: 403,
        headers: corsHeaders()
      });
    }
  } catch (e) {
    return new Response(JSON.stringify({ error: '无效的 URL 格式' }), {
      status: 400,
      headers: corsHeaders()
    });
  }

  // 2. 发起 HEAD 请求，仅获取头部信息
  let response;
  try {
    response = await fetch(targetUrl.href, {
      method: 'HEAD',
      redirect: 'follow',
      headers: {
        'User-Agent': 'DewSecure-Scanner/1.0 (Security Headers Check)'
      },
      cf: {
        cacheTtl: 600, // 缓存10分钟，减少重复请求
        timeout: 15   // 超时15秒
      }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: '无法连接目标服务器' }), {
      status: 502,
      headers: corsHeaders()
    });
  }

  const headers = response.headers;

  // 3. 定义检查项及修复建议
  const checks = {
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
      recommendation: '添加 HTTP 头 "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" 以强制浏览器使用 HTTPS。'
    },
    xFrameOptions: {
      label: 'X-Frame-Options',
      passed: headers.has('x-frame-options'),
      value: headers.get('x-frame-options') || '未设置',
      recommendation: '设置 "X-Frame-Options: DENY" 或 "SAMEORIGIN" 防止点击劫持攻击。'
    },
    xContentTypeOptions: {
      label: 'X-Content-Type-Options',
      passed: headers.has('x-content-type-options') && headers.get('x-content-type-options').toLowerCase() === 'nosniff',
      value: headers.get('x-content-type-options') || '未设置',
      recommendation: '添加 "X-Content-Type-Options: nosniff" 以阻止浏览器 MIME 类型嗅探。'
    },
    contentSecurityPolicy: {
      label: 'Content-Security-Policy (CSP)',
      passed: headers.has('content-security-policy'),
      value: headers.get('content-security-policy') || '未设置',
      recommendation: '实施严格的 CSP 策略，限制脚本、样式等资源来源，防范 XSS 攻击。示例: "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'" 。'
    },
    referrerPolicy: {
      label: 'Referrer-Policy',
      passed: headers.has('referrer-policy'),
      value: headers.get('referrer-policy') || '未设置',
      recommendation: '设置 "Referrer-Policy: strict-origin-when-cross-origin" 以控制 Referer 信息泄漏。'
    },
    permissionsPolicy: {
      label: 'Permissions-Policy',
      passed: headers.has('permissions-policy'),
      value: headers.get('permissions-policy') || '未设置',
      recommendation: '使用 Permissions-Policy 头限制浏览器 API（如摄像头、麦克风）的访问，减少隐私风险。'
    },
    serverInfoLeak: {
      label: '服务器信息泄漏',
      passed: !headers.has('server') && !headers.has('x-powered-by'),
      value: [headers.get('server'), headers.get('x-powered-by')].filter(Boolean).join(' ') || '未发现信息泄漏',
      recommendation: '隐藏或修改 Server/X-Powered-By 响应头，避免暴露技术栈版本，降低针对性攻击风险。'
    }
  };

  // 4. 计算评分
  const total = Object.keys(checks).length;
  const passedCount = Object.values(checks).filter(c => c.passed).length;
  const score = `${passedCount}/${total}`;

  // 5. 生成综合建议
  const failedItems = Object.values(checks).filter(c => !c.passed);
  let generalAdvice = '';
  if (failedItems.length > 0) {
    generalAdvice = `共发现 ${failedItems.length} 个安全问题。请优先修复标记为“未通过”的项。注意：此扫描仅检查 HTTP 响应头，不包含更深层的安全漏洞检测，全面的安全评估需要专业授权测试。`;
  } else {
    generalAdvice = '恭喜！所有基础安全头均已正确配置。请注意，这只是基础检查，仍需定期进行深度安全审计。';
  }

  // 6. 构造返回结果
  const result = {
    url: targetUrl.href,
    status: response.status,
    score,
    general_advice: generalAdvice,
    checks: Object.entries(checks).reduce((acc, [key, check]) => {
      acc[key] = {
        label: check.label,
        passed: check.passed,
        current_value: check.value,
        recommendation: check.recommendation
      };
      return acc;
    }, {}),
    disclaimer: '本扫描仅读取公开响应头信息，不进行任何主动攻击或未授权渗透测试。完整安全审计请联系 DewSecure 专家。'
  };

  return new Response(JSON.stringify(result, null, 2), {
    headers: {
      ...corsHeaders(),
      'Content-Type': 'application/json'
    }
  });
}

// CORS 头（允许前端跨域访问）
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
}

// 简单内网地址判断（防止 SSRF）
function isPrivateIp(hostname) {
  // 忽略 localhost 和 IPv4 内网段
  const privateRanges = [
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^0\./,
    /^169\.254\./,
    /^::1$/,
    /^fc00:/,
    /^fe80:/
  ];
  if (hostname === 'localhost' || hostname === '[::1]') return true;
  return privateRanges.some(pattern => pattern.test(hostname));
}
