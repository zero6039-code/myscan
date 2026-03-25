# MyScan - 网页漏洞扫描器

前端：GitHub Pages  
后端：Vercel Serverless Functions

## 部署步骤

1. 将代码推送到 GitHub 仓库。
2. 在 GitHub 仓库设置中启用 Pages，选择根目录 `/` 作为源。
3. 在 Vercel 导入该项目，根目录选择 `backend`，部署后获得后端域名。
4. 修改 `js/app.js` 中的 `API_URL` 为你的 Vercel 后端地址。
5. 提交修改，前端会自动更新。

## 使用

访问 GitHub Pages 地址，输入目标 URL，点击扫描即可看到后端返回的结果。
