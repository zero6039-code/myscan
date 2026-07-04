// blog.js - 简易博客引擎
(async function() {
    const listView = document.getElementById('post-list-view');
    const detailView = document.getElementById('post-detail-view');
    const postListEl = document.getElementById('post-list');
    const backBtn = document.getElementById('back-to-list');

    // 显示文章列表
    async function loadList() {
        try {
            const res = await fetch('/blog/posts.json');
            const posts = await res.json();
            postListEl.innerHTML = posts.map(p => `
                <a href="#" class="post-item" data-file="${p.file}">
                    <span class="post-title">${p.title}</span>
                    <span class="post-date">${p.date}</span>
                    <p style="margin:4px 0 0;font-size:14px;color:#8896a7;">${p.summary}</p>
                </a>
            `).join('');

            // 绑定点击事件
            document.querySelectorAll('.post-item').forEach(link => {
                link.addEventListener('click', async (e) => {
                    e.preventDefault();
                    const file = link.dataset.file;
                    await loadArticle(file);
                });
            });
        } catch (err) {
            postListEl.innerHTML = '<p style="color:#ef4444;">文章列表加载失败，请稍后再试。</p>';
        }
    }

    // 加载并显示单篇文章
    async function loadArticle(filename) {
        try {
            const res = await fetch(`/blog/${filename}`);
            const raw = await res.text();
            // 使用 marked.js 解析 Markdown（如果未加载，自动注入）
            if (typeof marked === 'undefined') {
                await loadScript('https://cdn.jsdelivr.net/npm/marked/marked.min.js');
            }
            const html = marked.parse(raw);
            document.getElementById('article-title').textContent = '';
            document.getElementById('article-date').textContent = '';
            document.getElementById('article-content').innerHTML = html;
            listView.style.display = 'none';
            detailView.style.display = 'block';

            // 从列表中获取标题和日期（简单实现：从文件名推断，也可修改逻辑从索引获取）
            const posts = await fetch('/blog/posts.json').then(r => r.json());
            const meta = posts.find(p => p.file === filename);
            if (meta) {
                document.getElementById('article-title').textContent = meta.title;
                document.getElementById('article-date').textContent = meta.date;
            }
        } catch (err) {
            alert('文章加载失败');
        }
    }

    // 动态加载脚本
    function loadScript(src) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src;
            script.onload = resolve;
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    // 返回列表
    backBtn.addEventListener('click', (e) => {
        e.preventDefault();
        detailView.style.display = 'none';
        listView.style.display = 'block';
    });

    // 初始加载列表
    loadList();
})();
