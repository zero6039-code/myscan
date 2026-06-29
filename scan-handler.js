// scan-handler.js
// Cloudflare Worker 扫描模块 —— 只读、合法、合规

export async function handleScan(request) {
  const url = new URL(request.url);
  const target = url.searchParams.get('url');

  if (!target) {
    return jsonResponse({ error: 'Missing url parameter' }, 400);
  }

  let targetUrl;
  try {
    targetUrl = new URL(target);
    if (!targetUrl.protocol.startsWith('http')) {
      throw new Error('Only http/https protocols are supported');
    }
    if (isPrivateIp(targetUrl.hostname)) {
      return jsonResponse({ error: 'Scanning internal addresses is not allowed' }, 403);
    }
  } catch (e) {
    return jsonResponse({ error: 'Invalid URL format' }, 400);
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
    return jsonResponse({ error: 'Unable to connect to target server' }, 502);
  }

  const headers = response.headers;

  // CSP analysis
  const cspHeader = headers.get('content-security-policy') || '';
  const hasUnsafeInline = /'unsafe-inline'/.test(cspHeader);
  const hasUnsafeEval = /'unsafe-eval'/.test(cspHeader);
  const cspValue = cspHeader || 'Not set';
  const cspSub = cspHeader
    ? (hasUnsafeInline && hasUnsafeEval
        ? 'unsafe_inline_eval'
        : hasUnsafeInline
          ? 'unsafe_inline'
          : hasUnsafeEval
            ? 'unsafe_eval'
            : 'strict')
    : '';

  // Server info leak analysis
  const serverVal = headers.get('server');
  const poweredByVal = headers.get('x-powered-by');
  const serverLeakValue = [serverVal, poweredByVal].filter(Boolean).join(' ') || 'No information leakage detected';
  const serverLeakSub = serverVal ? 'cloudflare' : '';

  const checks = {
    https: {
      id: 'https',
      label: 'HTTPS Enabled',
      passed: targetUrl.protocol === 'https:',
      value: targetUrl.protocol === 'https:' ? 'Enabled' : 'Not enabled',
      sub: '',
      recommendation: 'Migrate your site to HTTPS and enforce encryption for all traffic.'
    },
    hsts: {
      id: 'hsts',
      label: 'Strict-Transport-Security (HSTS)',
      passed: headers.has('strict-transport-security'),
      value: headers.get('strict-transport-security') || 'Not set',
      sub: '',
      recommendation: 'Add the header "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".'
    },
    xFrameOptions: {
      id: 'x_frame_options',
      label: 'X-Frame-Options',
      passed: headers.has('x-frame-options'),
      value: headers.get('x-frame-options') || 'Not set',
      sub: '',
      recommendation: 'Set "X-Frame-Options: DENY" or "SAMEORIGIN" to prevent clickjacking.'
    },
    xContentTypeOptions: {
      id: 'x_content_type_options',
      label: 'X-Content-Type-Options',
      passed: headers.has('x-content-type-options') && headers.get('x-content-type-options').toLowerCase() === 'nosniff',
      value: headers.get('x-content-type-options') || 'Not set',
      sub: '',
      recommendation: 'Add "X-Content-Type-Options: nosniff" to prevent MIME sniffing.'
    },
    contentSecurityPolicy: {
      id: 'csp',
      label: 'Content-Security-Policy (CSP)',
      passed: headers.has('content-security-policy'),
      value: cspValue,
      sub: cspSub,
      recommendation: headers.has('content-security-policy')
        ? (hasUnsafeInline || hasUnsafeEval
            ? 'CSP is present but contains unsafe directives (unsafe-inline/unsafe-eval). Consider using nonce or hash.'
            : 'CSP policy is well configured.')
        : 'Implement a strict CSP policy to restrict resource sources and prevent XSS attacks.'
    },
    referrerPolicy: {
      id: 'referrer_policy',
      label: 'Referrer-Policy',
      passed: headers.has('referrer-policy'),
      value: headers.get('referrer-policy') || 'Not set',
      sub: '',
      recommendation: 'Set "Referrer-Policy: strict-origin-when-cross-origin".'
    },
    permissionsPolicy: {
      id: 'permissions_policy',
      label: 'Permissions-Policy',
      passed: headers.has('permissions-policy'),
      value: headers.get('permissions-policy') || 'Not set',
      sub: '',
      recommendation: 'Use Permissions-Policy to limit browser API access.'
    },
    serverInfoLeak: {
      id: 'server_info_leak',
      label: 'Server Information Leakage',
      passed: !serverVal && !poweredByVal,
      value: serverLeakValue,
      sub: serverLeakSub,
      recommendation: serverVal
        ? `The Server header reveals "${serverVal}". This is often normal for a CDN, but ensure the origin server does not leak additional information.`
        : 'Hide Server/X-Powered-By headers to reduce attack surface.'
    },
    xPermittedCrossDomain: {
      id: 'x_permitted_cross_domain',
      label: 'X-Permitted-Cross-Domain-Policies',
      passed: headers.has('x-permitted-cross-domain-policies'),
      value: headers.get('x-permitted-cross-domain-policies') || 'Not set',
      sub: '',
      recommendation: 'Set "X-Permitted-Cross-Domain-Policies: none" to restrict Adobe cross-domain requests.'
    },
    crossOriginResourcePolicy: {
      id: 'corp',
      label: 'Cross-Origin-Resource-Policy (CORP)',
      passed: headers.has('cross-origin-resource-policy'),
      value: headers.get('cross-origin-resource-policy') || 'Not set',
      sub: '',
      recommendation: 'Set "Cross-Origin-Resource-Policy: same-origin" to limit cross-origin resource loading.'
    },
    crossOriginOpenerPolicy: {
      id: 'coop',
      label: 'Cross-Origin-Opener-Policy (COOP)',
      passed: headers.has('cross-origin-opener-policy'),
      value: headers.get('cross-origin-opener-policy') || 'Not set',
      sub: '',
      recommendation: 'Set "Cross-Origin-Opener-Policy: same-origin" to isolate cross-origin windows.'
    },
    cacheControl: {
      id: 'cache_control',
      label: 'Cache-Control',
      passed: headers.has('cache-control'),
      value: headers.get('cache-control') || 'Not set',
      sub: '',
      recommendation: 'Set appropriate Cache-Control policy, e.g., "no-store, max-age=0" for sensitive pages.'
    }
  };

  const total = Object.keys(checks).length;
  const passedCount = Object.values(checks).filter(c => c.passed).length;
  const score = `${passedCount}/${total}`;

  const failedItems = Object.values(checks).filter(c => !c.passed);
  const generalAdvice = failedItems.length > 0
    ? `Found ${failedItems.length} security issues. This scan only checks HTTP response headers.`
    : 'All basic security headers are properly configured.';

  return jsonResponse({
    url: targetUrl.href,
    status: response.status,
    score,
    general_advice: generalAdvice,
    checks: Object.fromEntries(
      Object.entries(checks).map(([key, val]) => [
        key,
        {
          id: val.id,
          label: val.label,
          passed: val.passed,
          current_value: val.value,
          sub: val.sub || '',
          recommendation: val.recommendation
        }
      ])
    ),
    disclaimer: 'This scan only reads publicly available response headers. No active attacks or unauthorized penetration testing is performed. For a full security audit, please contact DewSecure experts.'
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
