(function() {
    console.log('🟢 最终背景动画启动 - 开启 Shadow DOM 隔离');

    // 1. 创建一个宿主 div
    const host = document.createElement('div');
    host.style.cssText = 'position:fixed; top:0; left:0; width:100vw; height:100vh; z-index:-9999; pointer-events:none; overflow:hidden;';
    document.documentElement.appendChild(host);

    // 2. 开启 Shadow DOM (mode: closed 彻底拒绝外界干预)
    const shadow = host.attachShadow({ mode: 'closed' });

    // 3. 在 Shadow DOM 内部创建 canvas
    const canvas = document.createElement('canvas');
    canvas.style.cssText = 'width:100%; height:100%; display:block;';
    shadow.appendChild(canvas);

    const ctx = canvas.getContext('2d');
    let w, h;

    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    const STEP = 110;

    function drawGrid() {
        ctx.strokeStyle = 'rgba(100, 200, 255, 0.8)';
        ctx.lineWidth = 2;
        for (let x = 0; x <= w; x += STEP) {
            ctx.beginPath();
            ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
        }
        for (let y = 0; y <= h; y += STEP) {
            ctx.beginPath();
            ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
        }
    }

    let pos = 0;
    function drawLine() {
        ctx.strokeStyle = 'rgba(255, 50, 50, 0.9)';
        ctx.lineWidth = 4;
        ctx.shadowColor = 'rgba(255,0,0,0.5)';
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.moveTo(pos, 0);
        ctx.lineTo(pos + 120, h);
        ctx.stroke();
        ctx.shadowBlur = 0;
    }

    function animate() {
        ctx.clearRect(0, 0, w, h);
        drawGrid();
        drawLine();
        pos += 2.5;
        if (pos > w + 20) pos = -120;
        requestAnimationFrame(animate);
    }

    animate();
    console.log('✅ 最终背景动画已启动，运行在隔离的 Shadow DOM 中');
})();
