// worker.js - Cloudflare Worker + 静态站点
import { handleScan } from './scan-handler.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // /api/scan 路由 → 扫描处理
    if (url.pathname === '/api/scan') {
      return handleScan(request);
    }

    // 其他所有请求 → 返回静态资源
    return env.ASSETS.fetch(request);
  }
};
