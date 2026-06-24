(function() {
    const canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.style.cssText = 'position:fixed; top:0; left:0; width:100%; height:100%; z-index:-2; pointer-events:none;';
    document.body.prepend(canvas);

    const ctx = canvas.getContext('2d');
    ctx.lineCap = 'round';

    let w, h;
    let dpr = window.devicePixelRatio || 1;

    function resize() {
        dpr = window.devicePixelRatio || 1;
        w = window.innerWidth;
        h = window.innerHeight;
        
        // 核心修复：画布像素大小放大 DPR 倍，解决高清屏模糊问题
        canvas.width = w * dpr;
        canvas.height = h * dpr;
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        
        ctx.scale(dpr, dpr);
        ctx.imageSmoothingEnabled = true;
        ctx.imageSmoothingQuality = 'high';
    }
    
    resize();

    const STEP = 110;
    const DURATION = 3000;          
    const OFFSET = 200;             

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

    function getGridIndices(maxVal) {
        const count = Math.floor(maxVal / STEP) + 1;
        return Array.from({ length: count }, (_, i) => i * STEP);
    }

    class FlowLine {
        constructor() {
            this.active = false;
            this.tail = [];
            this.tailLen = 80;
            this.x = 0;
            this.y = 0;
            this.startTime = 0;
            this.duration = DURATION;
            this.startX = 0;
            this.startY = 0;
            this.endX = 0;
            this.endY = 0;
            this.direction = 0; 
        }

        start(direction, gridPos) {
            this.direction = direction;
            switch (direction) {
                case 0: 
                    this.startX = -OFFSET; this.startY = gridPos;
                    this.endX = w + OFFSET; this.endY = gridPos;
                    break;
                case 1: 
                    this.startX = w + OFFSET; this.startY = gridPos;
                    this.endX = -OFFSET; this.endY = gridPos;
                    break;
                case 2: 
                    this.startX = gridPos; this.startY = -OFFSET;
                    this.endX = gridPos; this.endY = h + OFFSET;
                    break;
                case 3: 
                    this.startX = gridPos; this.startY = h + OFFSET;
                    this.endX = gridPos; this.endY = -OFFSET;
                    break;
            }
            this.x = this.startX;
            this.y = this.startY;
            this.startTime = performance.now();
            this.tail = [{ x: this.x, y: this.y }];
            this.active = true;
        }

        update() {
            if (!this.active) return false;
            const elapsed = (performance.now() - this.startTime) / this.duration;
            const progress = elapsed;

            this.x = this.startX + (this.endX - this.startX) * progress;
            this.y = this.startY + (this.endY - this.startY) * progress;

            if (this.tail.length === 0 ||
                Math.abs(this.tail[this.tail.length - 1].x - this.x) > 0.3 ||
                Math.abs(this.tail[this.tail.length - 1].y - this.y) > 0.3) {
                this.tail.push({ x: this.x, y: this.y });
            }
            if (this.tail.length > this.tailLen) {
                this.tail.shift();
            }

            if (progress >= 1.0 && this.tail.length > 0) {
                const tailEnd = this.tail[0];
                const margin = 50;
                const out = (tailEnd.x < -margin || tailEnd.x > w + margin ||
                             tailEnd.y < -margin || tailEnd.y > h + margin);
                if (out) {
                    this.active = false;
                    this.tail = [];
                    return false;
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
                ctx.moveTo(this.tail[i - 1].x, this.tail[i - 1].y);
                ctx.lineTo(this.tail[i].x, this.tail[i].y);
                ctx.strokeStyle = `rgba(255, 50, 50, ${alpha})`;
                ctx.lineWidth = lineWidth;
                ctx.shadowColor = 'rgba(255,0,0,0.05)';
                ctx.shadowBlur = 3;
                ctx.stroke();
            }
            ctx.shadowBlur = 0;
        }
    }

    const lineA = new FlowLine();
    const lineB = new FlowLine();
    const lineC = new FlowLine();

    function getActiveLines() {
        const active = [];
        if (lineA.active) active.push(lineA);
        if (lineB.active) active.push(lineB);
        if (lineC.active) active.push(lineC);
        return active;
    }

    function choosePathForNewLine() {
        const activeLines = getActiveLines();
        const forbiddenHoriz = new Set(); 
        const forbiddenVert = new Set();  

        for (const line of activeLines) {
            if (line.direction === 0 || line.direction === 1) {
                forbiddenHoriz.add(line.startY);
            } else {
                forbiddenVert.add(line.startX);
            }
        }

        const horizIndices = getGridIndices(h).filter(y => !forbiddenHoriz.has(y));
        const vertIndices = getGridIndices(w).filter(x => !forbiddenVert.has(x));

        const canHorizontal = horizIndices.length > 0;
        const canVertical = vertIndices.length > 0;

        if (!canHorizontal && !canVertical) {
            const dir = Math.floor(Math.random() * 4);
            if (dir <= 1) {
                const allY = getGridIndices(h);
                return { dir, pos: allY[Math.floor(Math.random() * allY.length)] };
            } else {
                const allX = getGridIndices(w);
                return { dir, pos: allX[Math.floor(Math.random() * allX.length)] };
            }
        }

        const allowedDirs = [];
        if (canHorizontal) allowedDirs.push(0, 1);
        if (canVertical) allowedDirs.push(2, 3);
        const chosenDir = allowedDirs[Math.floor(Math.random() * allowedDirs.length)];

        if (chosenDir <= 1) {
            const y = horizIndices[Math.floor(Math.random() * horizIndices.length)];
            return { dir: chosenDir, pos: y };
        } else {
            const x = vertIndices[Math.floor(Math.random() * vertIndices.length)];
            return { dir: chosenDir, pos: x };
        }
    }

    function animate() {
        ctx.clearRect(0, 0, w, h);
        drawGrid();

        lineA.update();
        lineB.update();
        lineC.update();

        lineA.draw(ctx);
        lineB.draw(ctx);
        lineC.draw(ctx);

        [lineA, lineB, lineC].forEach(line => {
            if (!line.active && line.tail.length === 0 && !line._restartScheduled) {
                line._restartScheduled = true;
                setTimeout(() => {
                    line._restartScheduled = false;
                    if (!line.active) {
                        const { dir, pos } = choosePathForNewLine();
                        line.start(dir, pos);
                    }
                }, 10);
            }
        });

        requestAnimationFrame(animate);
    }

    let timers = [];
    function startAllWithDelay() {
        timers.forEach(clearTimeout);
        timers = [];

        const { dir: dirA, pos: posA } = choosePathForNewLine();
        lineA.start(dirA, posA);

        timers.push(setTimeout(() => {
            const { dir, pos } = choosePathForNewLine();
            lineB.start(dir, pos);
        }, 1500));

        timers.push(setTimeout(() => {
            const { dir, pos } = choosePathForNewLine();
            lineC.start(dir, pos);
        }, 2500));
    }

    startAllWithDelay();
    animate();

    // 引入防抖处理 resize，避免高频清空和重开导致的极端冲突
    let resizeTimeout;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
            lineA.active = false; lineB.active = false; lineC.active = false;
            lineA.tail = []; lineB.tail = []; lineC.tail = [];
            lineA._restartScheduled = false; lineB._restartScheduled = false; lineC._restartScheduled = false;

            resize();
            startAllWithDelay();
        }, 150);
    });
})();
