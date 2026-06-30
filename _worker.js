// worker.js - Cloudflare Worker + 静态站点（安全头增强版）
import { handleScan } from './scan-handler.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // /api/scan 路由 → 扫描处理
    if (url.pathname === '/api/scan') {
      return handleScan(request);
    }

    // 其他所有请求 → 获取静态资源并注入安全响应头
    let response = await env.ASSETS.fetch(request);

    // 复制原始响应头
    const newHeaders = new Headers(response.headers);

    // --- 强制安全头 (可根据需要调整) ---
    newHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    newHeaders.set('X-Frame-Options', 'DENY');                // 或 SAMEORIGIN，根据需求
    newHeaders.set('X-Content-Type-Options', 'nosniff');
    newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    newHeaders.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    newHeaders.set('Cross-Origin-Resource-Policy', 'same-origin');
    newHeaders.set('Cross-Origin-Opener-Policy', 'same-origin');
    newHeaders.set('X-Permitted-Cross-Domain-Policies', 'none');
    newHeaders.set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://use.fontawesome.com; font-src 'self' https://use.fontawesome.com; img-src 'self' data:;");

    // 隐藏 Cloudflare 服务器信息 (非必须，但可减少指纹)
    newHeaders.delete('server');

    // 返回携带新头的响应
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  }
};
