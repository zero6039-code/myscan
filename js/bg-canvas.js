// 背景动画 - 亮色网格 + 红线移动
(function() {
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

    const STEP = 80;

    function drawGrid() {
        ctx.strokeStyle = 'rgba(100, 200, 255, 0.9)';
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

    let posX = 0;

    function drawLine() {
        ctx.strokeStyle = 'rgba(255, 0, 0, 1)';
        ctx.lineWidth = 6;
        ctx.shadowColor = 'rgba(255, 0, 0, 0.8)';
        ctx.shadowBlur = 20;
        ctx.beginPath();
        ctx.moveTo(posX, 0);
        ctx.lineTo(posX + 150, h);
        ctx.stroke();
        ctx.shadowBlur = 0;
    }

    function animate() {
        ctx.clearRect(0, 0, w, h);
        drawGrid();
        drawLine();
        posX += 3;
        if (posX > w + 50) posX = -150;
        requestAnimationFrame(animate);
    }

    animate();
})();
