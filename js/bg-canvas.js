// js/bg-canvas.js
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

    // 绘制科技网格（颜色调亮为 rgba(100,200,255,0.2)）
    function drawGrid() {
        ctx.strokeStyle = 'rgba(100, 200, 255, 0.2)';
        ctx.lineWidth = 1;
        for (let x = 0; x <= w; x += 50) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, h);
            ctx.stroke();
        }
        for (let y = 0; y <= h; y += 50) {
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();
        }
    }

    // 红色流动线条（9条）
    class FlowLine {
        constructor() {
            this.reset();
        }
        reset() {
            this.x = Math.random() * w;
            this.y = Math.random() * h;
            const angle = Math.random() * Math.PI * 2;
            const speed = 1.0 + Math.random() * 2.0;
            this.vx = Math.cos(angle) * speed;
            this.vy = Math.sin(angle) * speed;
            this.tailLen = 30 + Math.floor(Math.random() * 40);
            this.tail = [];
            for (let i = 0; i < this.tailLen; i++) {
                this.tail.push({
                    x: this.x - this.vx * i * 0.8,
                    y: this.y - this.vy * i * 0.8
                });
            }
        }
        update() {
            this.x += this.vx;
            this.y += this.vy;
            if (this.x < -50) this.x = w + 50;
            if (this.x > w + 50) this.x = -50;
            if (this.y < -50) this.y = h + 50;
            if (this.y > h + 50) this.y = -50;
            this.tail.push({ x: this.x, y: this.y });
            if (this.tail.length > this.tailLen) {
                this.tail.shift();
            }
        }
        draw(ctx) {
            if (this.tail.length < 2) return;
            for (let i = 1; i < this.tail.length; i++) {
                const progress = i / this.tail.length;
                const alpha = 0.1 + progress * 0.8;
                ctx.beginPath();
                ctx.moveTo(this.tail[i - 1].x, this.tail[i - 1].y);
                ctx.lineTo(this.tail[i].x, this.tail[i].y);
                ctx.strokeStyle = `rgba(255, 50, 50, ${alpha})`;
                ctx.lineWidth = 1.2 + progress * 1.5;
                ctx.shadowColor = 'rgba(255, 0, 0, 0.3)';
                ctx.shadowBlur = 8;
                ctx.stroke();
            }
            ctx.shadowBlur = 0;
        }
    }

    // 9 条红色线条
    const flowLines = [];
    const lineCount = 9;
    for (let i = 0; i < lineCount; i++) {
        flowLines.push(new FlowLine());
    }

    function animate() {
        ctx.clearRect(0, 0, w, h);
        drawGrid();
        flowLines.forEach(line => {
            line.update();
            line.draw(ctx);
        });
        requestAnimationFrame(animate);
    }

    animate();

    window.addEventListener('resize', () => {
        flowLines.forEach(line => {
            if (line.x > w) line.x = w * 0.5;
            if (line.y > h) line.y = h * 0.5;
        });
    });
})();
