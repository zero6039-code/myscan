// js/bg-canvas.js - 独立背景动画，不依赖任何其他脚本
(function() {
    console.log('✅ bg-canvas.js 已加载');

    // 创建画布
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

    class FlowLine {
        constructor() {
            this.active = false;
            this.tail = [];
            this.tailLen = 90;
            this.x = 0;
            this.y = 0;
            this.timer = null;
            this.startTime = 0;
            this.duration = 3000;
            this.startX = 0;
            this.startY = 0;
            this.endX = 0;
            this.endY = 0;
        }

        start() {
            const dir = Math.floor(Math.random() * 4);
            const offset = 20;
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
            const progress = Math.min(elapsed, 1.0);
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

            if (progress >= 1.0) {
                this.active = false;
                this.tail = [];
                clearTimeout(this.timer);
                this.timer = setTimeout(() => this.start(), 200);
                return false;
            }
            return true;
        }

        draw(ctx) {
            if (!this.active || this.tail.length < 2) return;
            for (let i = 1; i < this.tail.length; i++) {
                const progress = i / this.tail.length;
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

    console.log('✅ bg-canvas.js 初始化完成');
})();
