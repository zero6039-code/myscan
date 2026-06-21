// js/bg-canvas.js
(function() {
    const canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.style.cssText = 'position:fixed; top:0; left:0; width:100%; height:100%; z-index:-2; pointer-events:none;';
    document.body.prepend(canvas);
    
    const ctx = canvas.getContext('2d');
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';

    let w, h;

    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    const STEP = 110; // 网格间距

    // 绘制网格
    function drawGrid() {
        ctx.strokeStyle = 'rgba(100, 200, 255, 0.1)';
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

    // 单条脉冲线
    class FlowLine {
        constructor() {
            this.active = false;
            this.tail = [];
            this.tailLen = 90;          // 长拖尾
            this.x = 0;
            this.y = 0;
            this.vx = 0;
            this.vy = 0;
            this.timer = null;
        }

        start() {
            const dir = Math.floor(Math.random() * 4);
            // 2 秒走完全屏（120 帧）
            const speedX = w / 180;
            const speedY = h / 180;

            switch(dir) {
                case 0: // 左→右
                    this.x = -20;
                    this.y = Math.floor(Math.random() * (h / STEP)) * STEP;
                    this.vx = speedX;
                    this.vy = 0;
                    break;
                case 1: // 右→左
                    this.x = w + 20;
                    this.y = Math.floor(Math.random() * (h / STEP)) * STEP;
                    this.vx = -speedX;
                    this.vy = 0;
                    break;
                case 2: // 上→下
                    this.x = Math.floor(Math.random() * (w / STEP)) * STEP;
                    this.y = -20;
                    this.vx = 0;
                    this.vy = speedY;
                    break;
                case 3: // 下→上
                    this.x = Math.floor(Math.random() * (w / STEP)) * STEP;
                    this.y = h + 20;
                    this.vx = 0;
                    this.vy = -speedY;
                    break;
            }
            this.tail = [];          // 不预填充，自然生成
            this.active = true;
        }

        update() {
            if (!this.active) return false;

            this.x += this.vx;
            this.y += this.vy;

            // 记录尾迹（间隔 1 像素）
            if (this.tail.length === 0 || 
                Math.abs(this.tail[this.tail.length-1].x - this.x) > 0.3 ||
                Math.abs(this.tail[this.tail.length-1].y - this.y) > 0.3) {
                this.tail.push({ x: this.x, y: this.y });
            }
            if (this.tail.length > this.tailLen) {
                this.tail.shift();
            }

            // 检测尾部最旧的点（拖尾末端）是否完全离开屏幕
            if (this.tail.length > 0) {
                const tailEnd = this.tail[0]; // 最旧的点
                const margin = 50;
                const out = (tailEnd.x < -margin || tailEnd.x > w + margin || tailEnd.y < -margin || tailEnd.y > h + margin);
                if (out) {
                    this.active = false;
                    this.tail = [];
                    clearTimeout(this.timer);
                    this.timer = setTimeout(() => this.start(), 200);
                    return false;
                }
            }
            return true;
        }

        draw(ctx) {
            if (!this.active || this.tail.length < 2) return;

            for (let i = 1; i < this.tail.length; i++) {
                const progress = i / this.tail.length; // 0~1，尾部→头部
                const alpha = 0.03 + progress * 0.67;
                const widthFactor = Math.sin(progress * Math.PI);
                const lineWidth = 0.3 + widthFactor * 1.5;
                ctx.beginPath();
                ctx.moveTo(this.tail[i-1].x, this.tail[i-1].y);
                ctx.lineTo(this.tail[i].x, this.tail[i].y);
                ctx.strokeStyle = `rgba(255, 50, 50, ${alpha})`;
                ctx.lineWidth = lineWidth;
                ctx.shadowColor = 'rgba(255,0,0,0.08)';
                ctx.shadowBlur = 3;
                ctx.stroke();
            }
            ctx.shadowBlur = 0;
        }
    }

    const flowLine = new FlowLine();
    flowLine.start();

    function animate() {
        ctx.clearRect(0, 0, w, h);
        drawGrid();
        flowLine.update();
        flowLine.draw(ctx);
        requestAnimationFrame(animate);
    }

    animate();

    window.addEventListener('resize', () => {
        if (flowLine.active) {
            const margin = 200;
            if (flowLine.x < -margin || flowLine.x > w + margin || flowLine.y < -margin || flowLine.y > h + margin) {
                flowLine.active = false;
                flowLine.tail = [];
                clearTimeout(flowLine.timer);
                flowLine.timer = setTimeout(() => flowLine.start(), 200);
            }
        }
    });
})();
