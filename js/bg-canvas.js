// 最终版背景动画 - 基于测试成功的网格绘制
(function() {
    console.log('🟢 最终背景动画启动');

    // 创建画布
    const canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.style.cssText = 'position:fixed; top:0; left:0; width:100%; height:100%; z-index:-2; pointer-events:none;';
    document.body.prepend(canvas);

    const ctx = canvas.getContext('2d');
    let w, h;

    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    const STEP = 110; // 网格间距

    // 绘制网格（与测试代码完全相同，保证可见）
    function drawGrid() {
        ctx.strokeStyle = 'rgba(100, 200, 255, 0.8)';
        ctx.lineWidth = 2;
        for (let x = 0; x <= w; x += STEP) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, h);
            ctx.stroke();
        }
        for (let y = 0; y <= h; y += STEP) {
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();
        }
    }

    // 移动的红色线条（粗、亮、带发光）
    let pos = 0;

    function drawLine() {
        ctx.strokeStyle = 'rgba(255, 50, 50, 0.9)';
        ctx.lineWidth = 4;
        ctx.shadowColor = 'rgba(255,0,0,0.5)';
        ctx.shadowBlur = 10;
        ctx.beginPath();
        // 绘制从左下到右上的斜线（动态移动）
        ctx.moveTo(pos, 0);
        ctx.lineTo(pos + 120, h);
        ctx.stroke();
        ctx.shadowBlur = 0;
    }

    function animate() {
        ctx.clearRect(0, 0, w, h);
        drawGrid();
        drawLine();
        pos += 2.5; // 移动速度
        if (pos > w + 20) pos = -120; // 循环
        requestAnimationFrame(animate);
    }

    animate();
    console.log('✅ 最终背景动画已启动，网格+红线可见');
})();
