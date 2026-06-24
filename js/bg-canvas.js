/**
 * 🌌 DewSecure 高性能背景矩阵流 (优化版)
 * 修正了层级冲突与渲染阻塞问题
 */
(function() {
    const canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    // 关键修正：确保背景始终在最底层，且不拦截鼠标事件
    canvas.style.cssText = 'position:fixed; top:0; left:0; width:100%; height:100%; z-index:-1; pointer-events:none;';
    document.body.prepend(canvas);

    const ctx = canvas.getContext('2d');
    let w, h, dpr;

    function resize() {
        dpr = window.devicePixelRatio || 1;
        w = window.innerWidth;
        h = window.innerHeight;
        canvas.width = w * dpr;
        canvas.height = h * dpr;
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        ctx.scale(dpr, dpr);
    }
    
    window.addEventListener('resize', () => {
        resize();
        // 重新初始化路径以适配新尺寸
        [lineA, lineB, lineC].forEach(l => l.active = false);
    });
    resize();

    const STEP = 110;
    const DURATION = 3000;
    const OFFSET = 200;

    class FlowLine {
        constructor() {
            this.active = false;
            this.tail = [];
            this.tailLen = 80;
            this.startTime = 0;
        }

        start(dir, pos) {
            this.direction = dir;
            switch (dir) {
                case 0: this.startX = -OFFSET; this.startY = pos; this.endX = w + OFFSET; this.endY = pos; break;
                case 1: this.startX = w + OFFSET; this.startY = pos; this.endX = -OFFSET; this.endY = pos; break;
                case 2: this.startX = pos; this.startY = -OFFSET; this.endX = pos; this.endY = h + OFFSET; break;
                case 3: this.startX = pos; this.startY = h + OFFSET; this.endX = pos; this.endY = -OFFSET; break;
            }
            this.x = this.startX;
            this.y = this.startY;
            this.startTime = performance.now();
            this.tail = [{ x: this.x, y: this.y }];
            this.active = true;
        }

        update() {
            if (!this.active) return;
            const progress = (performance.now() - this.startTime) / DURATION;
            this.x = this.startX + (this.endX - this.startX) * progress;
            this.y = this.startY + (this.endY - this.startY) * progress;
            this.tail.push({ x: this.x, y: this.y });
            if (this.tail.length > this.tailLen) this.tail.shift();
            if (progress >= 1) this.active = false;
        }

        draw(ctx) {
            if (!this.active) return;
            ctx.beginPath();
            ctx.moveTo(this.tail[0].x, this.tail[0].y);
            ctx.lineTo(this.x, this.y);
            ctx.strokeStyle = 'rgba(255, 50, 50, 0.2)';
            ctx.lineWidth = 1;
            ctx.stroke();
        }
    }

    const [lineA, lineB, lineC] = [new FlowLine(), new FlowLine(), new FlowLine()];

    function animate() {
        ctx.clearRect(0, 0, w, h);
        
        // 绘制网格
        ctx.strokeStyle = 'rgba(100, 200, 255, 0.05)';
        for (let x = 0; x <= w; x += STEP) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
        for (let y = 0; y <= h; y += STEP) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }

        [lineA, lineB, lineC].forEach((line, i) => {
            if (!line.active) {
                if (Math.random() > 0.99) {
                    const pos = i % 2 === 0 ? Math.random() * h : Math.random() * w;
                    line.start(Math.floor(Math.random() * 4), pos);
                }
            } else {
                line.update();
                line.draw(ctx);
            }
        });
        requestAnimationFrame(animate);
    }
    animate();
})();
