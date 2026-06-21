// js/bg-canvas.js
(function() {
    // 创建画布
    const canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.style.cssText = 'position:fixed; top:0; left:0; width:100%; height:100%; z-index:-2; pointer-events:none;';
    document.body.prepend(canvas);
    
    const ctx = canvas.getContext('2d');
    let w, h;

    // 自适应尺寸
    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    // ========== 1. 绘制科技网格 ==========
    function drawGrid() {
        ctx.strokeStyle = 'rgba(100, 200, 255, 0.08)'; // 淡蓝色，很细微
        ctx.lineWidth = 1;
        
        // 垂直线（间距 50px）
        for (let x = 0; x <= w; x += 50) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, h);
            ctx.stroke();
        }
        // 水平线（间距 50px）
        for (let y = 0; y <= h; y += 50) {
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();
        }
    }

    // ========== 2. 红色流动线条（粒子+尾迹） ==========
    class FlowLine {
        constructor() {
            this.reset();
        }

        reset() {
            // 随机起始位置
            this.x = Math.random() * w;
            this.y = Math.random() * h;
            // 随机方向（角度）
            const angle = Math.random() * Math.PI * 2;
            // 速度 1.0 ~ 3.0 像素/帧
            const speed = 1.0 + Math.random() * 2.0;
            this.vx = Math.cos(angle) * speed;
            this.vy = Math.sin(angle) * speed;
            // 尾迹长度（30~70个点）
            this.tailLen = 30 + Math.floor(Math.random() * 40);
            // 存储历史坐标
            this.tail = [];
            // 随机初始化尾迹，避免全部从一点开始
            for (let i = 0; i < this.tailLen; i++) {
                this.tail.push({
                    x: this.x - this.vx * i * 0.8,
                    y: this.y - this.vy * i * 0.8
                });
            }
        }

        update() {
            // 移动
            this.x += this.vx;
            this.y += this.vy;

            // 边界反弹（超出画布则从另一侧穿入，保持连续）
            if (this.x < -50) this.x = w + 50;
            if (this.x > w + 50) this.x = -50;
            if (this.y < -50) this.y = h + 50;
            if (this.y > h + 50) this.y = -50;

            // 更新尾迹
            this.tail.push({ x: this.x, y: this.y });
            if (this.tail.length > this.tailLen) {
                this.tail.shift();
            }
        }

        draw(ctx) {
            if (this.tail.length < 2) return;

            // 绘制尾迹线条（从透明到亮红渐变）
            for (let i = 1; i < this.tail.length; i++) {
                // 透明度从 0.1 到 0.9 渐变（尾部淡出）
                const progress = i / this.tail.length;
                const alpha = 0.1 + progress * 0.8;
                
                ctx.beginPath();
                ctx.moveTo(this.tail[i - 1].x, this.tail[i - 1].y);
                ctx.lineTo(this.tail[i].x, this.tail[i].y);
                
                // 线条颜色：红色系，带一点发光感
                ctx.strokeStyle = `rgba(255, 50, 50, ${alpha})`;
                ctx.lineWidth = 1.2 + progress * 1.5; // 头部粗，尾部细
                ctx.shadowColor = 'rgba(255, 0, 0, 0.3)';
                ctx.shadowBlur = 8;
                ctx.stroke();
            }
            // 重置阴影避免影响网格
            ctx.shadowBlur = 0;
        }
    }

    // 创建 5~8 条流动线（数量适中，不会太密集）
    const flowLines = [];
    const lineCount = 6; // 可自行调整
    for (let i = 0; i < lineCount; i++) {
        flowLines.push(new FlowLine());
    }

    // ========== 3. 动画循环 ==========
    function animate() {
        // 清除画布（透明，露出黑色背景）
        ctx.clearRect(0, 0, w, h);
        
        // 绘制网格
        drawGrid();
        
        // 更新并绘制流动线条
        flowLines.forEach(line => {
            line.update();
            line.draw(ctx);
        });
        
        requestAnimationFrame(animate);
    }

    animate();

    // ========== 4. 窗口变化时重置一些线条位置（可选） ==========
    window.addEventListener('resize', () => {
        // 重新计算边界，让线条不跑出太远
        flowLines.forEach(line => {
            if (line.x > w) line.x = w * 0.5;
            if (line.y > h) line.y = h * 0.5;
        });
    });
})();
