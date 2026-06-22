(function() {
    console.log('🟢 最终背景动画启动');

    // 1. 确保在 body 准备好后执行，避开插件注入干扰
    const initCanvas = () => {
        if (!document.body) {
            setTimeout(initCanvas, 100);
            return;
        }

        const canvas = document.createElement('canvas');
        canvas.id = 'bg-canvas';
        // 使用绝对定位，确保它独立于 body 的内容流
        canvas.style.cssText = 'position:fixed; top:0; left:0; width:100vw; height:100vh; z-index:-9999; pointer-events:none;';
        
        // 避开直接操作 body 的 prepend，防止干扰到插件监听器
        document.documentElement.appendChild(canvas);

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
    };

    initCanvas();
})();
