// 背景动画 - 淡网格 + 两条红色线条沿网格方向移动（带拖尾）
(function() {
    const canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.style.cssText = 'position:fixed; top:0; left:0; width:100%; height:100%; z-index:-2; pointer-events:none;';
    document.body.prepend(canvas);

    const ctx = canvas.getContext('2d');
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.lineCap = 'round';

    let w, h;

    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    const STEP = 110;

    function drawGrid() {
        ctx.strokeStyle = 'rgba(100, 200, 255, 0.08)';
        ctx.lineWidth = 1;
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

    class FlowLine {
        constructor() {
            this.active = false;
            this.tail = [];
            this.tailLen = 80;
            this.x = 0;
            this.y = 0;
            this.startTime = 0;
            this.duration = 3000; // 3秒走完
            this.startX = 0;
            this.startY = 0;
            this.endX = 0;
            this.endY = 0;
            // 随机颜色微调（红/橙红差异，视觉上更自然）
            this.hue = Math.floor(Math.random() * 20) + 340; // 340~360 红色系
        }

        start() {
            const dir = Math.floor(Math.random() * 4);
            const offset = 200;
            switch(dir) {
                case 0:
                    this.startX = -offset;
                    this.startY = Math.floor(Math.random() * (h / STEP)) * STEP;
                    this.endX = w + offset;
                    this.endY = this.startY;
                    break;
                case 1:
                    this.startX = w + offset;
                    this.startY = Math.floor(Math.random() * (h / STEP)) * STEP;
                    this.endX = -offset;
                    this.endY = this.startY;
                    break;
                case 2:
                    this.startX = Math.floor(Math.random() * (w / STEP)) * STEP;
                    this.startY = -offset;
                    this.endX = this.startX;
                    this.endY = h + offset;
                    break;
                case 3:
                    this.startX = Math.floor(Math.random() * (w / STEP)) * STEP;
                    this.startY = h + offset;
                    this.endX = this.startX;
                    this.endY = -offset;
                    break;
            }
            this.x = this.startX;
            this.y = this.startY;
            this.startTime = performance.now();
            this.tail = [];
            this.active = true;
        }

        update() {
            if (!this.active) return false;

            const elapsed = (performance.now() - this.startTime) / this.duration;
            const progress = elapsed; // 不限制，允许超过1.0

            this.x = this.startX + (this.endX - this.startX) * progress;
            this.y = this.startY + (this.endY - this.startY) * progress;

            if (this.tail.length === 0 || 
                Math.abs(this.tail[this.tail.length-1].x - this.x) > 0.3 ||
                Math.abs(this.tail[this.tail.length-1].y - this.y) > 0.3) {
                this.tail.push({ x: this.x, y: this.y });
            }
            if (this.tail.length > this.tailLen) {
                this.tail.shift();
            }

            // 尾部完全离开屏幕 → 同步重置，立即开始新线条
            if (this.tail.length > 0) {
                const tailEnd = this.tail[0];
                const margin = 50;
                const out = (tailEnd.x < -margin || tailEnd.x > w + margin || tailEnd.y < -margin || tailEnd.y > h + margin);
                if (out) {
                    // 直接重置，不依赖 setTimeout
                    this.start();
                    return false; // 告诉调用者已重置，无需再更新
                }
            }
            return true;
        }

        draw(ctx) {
            if (!this.active || this.tail.length < 2) return;
            for (let i = 1; i < this.tail.length; i++) {
                const progress = i / this.tail.length;
                const alpha = 0.02 + progress * 0.35;
                const widthFactor = Math.sin(progress * Math.PI);
                const lineWidth = 0.5 + widthFactor * 2.0;
                ctx.beginPath();
                ctx.moveTo(this.tail[i-1].x, this.tail[i-1].y);
                ctx.lineTo(this.tail[i].x, this.tail[i].y);
                // 使用动态色相（红色系微调）
                ctx.strokeStyle = `hsla(${this.hue}, 90%, 50%, ${alpha})`;
                ctx.lineWidth = lineWidth;
                ctx.shadowColor = `hsla(${this.hue}, 90%, 50%, 0.05)`;
                ctx.shadowBlur = 3;
                ctx.stroke();
            }
            ctx.shadowBlur = 0;
        }
    }

    // 创建两条线
    const line1 = new FlowLine();
    const line2 = new FlowLine();

    line1.start(); // 第一条立即启动

    // 第二条延迟 1~2 秒启动，避免同步
    setTimeout(() => {
        line2.start();
    }, 1000 + Math.random() * 1000);

    function animate() {
        ctx.clearRect(0, 0, w, h);
        drawGrid();

        // 更新并绘制两条线
        line1.update();
        line1.draw(ctx);

        line2.update();
        line2.draw(ctx);

        requestAnimationFrame(animate);
    }

    animate();

    window.addEventListener('resize', () => {
        // 如果线条超出新边界，强制重置（但我们的自动重置已处理）
        // 可留空，因为 update() 中会检测尾部离开
    });
})();
