// ==================== 进度存储（内存版，仅演示） ====================
// ⚠️ 警告：内存存储在多实例环境下会丢失进度，生产环境请使用 Vercel KV
// 推荐升级方案见下方注释

// 内存存储（每个 Vercel 实例独立，不跨实例共享）
const tasks = new Map();

// 导出存储供 scan.js 写入（需要在 scan.js 中引入并赋值）
// 更好的做法：使用 Vercel KV
module.exports.tasks = tasks;

// 进度查询接口
module.exports = async (req, res) => {
    // CORS 设置
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();

    // 只允许 GET
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { taskId } = req.query;
    if (!taskId) {
        return res.status(400).json({ error: 'Missing taskId' });
    }

    const task = tasks.get(taskId);
    if (!task) {
        return res.status(404).json({ error: 'Task not found' });
    }

    // 返回进度或结果
    res.json(task);
};