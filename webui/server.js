// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const https = require('https');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour
const COOKIE_SECRET = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString('hex'); // 未设置环境变量时重启会使现有会话失效
const activeSessions = new Map();
if (!process.env.COOKIE_SECRET) {
    console.warn('COOKIE_SECRET 未设置，重启后会清除当前登录会话');
}

// HTTPS 设置 (请提供有效的证书和私钥)
const options = {
    key: fs.readFileSync('/root/nftables-nat-rust-webui/ssl/private-key.pem'),
    cert: fs.readFileSync('/root/nftables-nat-rust-webui/ssl/certificate.pem')
};

// 中间件
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(COOKIE_SECRET));

// 读取和处理密码
let users = {};
fs.readFile('passwd.md', 'utf8', (err, data) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    const lines = data.trim().split('\n');
    lines.forEach(line => {
        const [user, hashedPassword] = line.split(':');
        users[user] = hashedPassword;
    });
});

const normalizeRule = (rule) => ({
    type: String(rule.type || '').trim().toUpperCase(),
    startPort: String(rule.startPort || '').trim(),
    endPort: String(rule.endPort || '').trim(),
    destination: String(rule.destination || '').trim(),
    protocol: rule.protocol === undefined || rule.protocol === null ? '' : String(rule.protocol).trim().toLowerCase()
});

const isValidPort = (value) => /^\d{1,5}$/.test(value) && Number(value) >= 1 && Number(value) <= 65535;
const isValidProtocol = (value) => value === '' || value === 'tcp' || value === 'udp';
const isValidDestination = (value) => !!value && !/[\s#]/.test(value) && !value.includes(',');

const validateNormalizedRule = (normalized) => {
    if (!['SINGLE', 'RANGE'].includes(normalized.type)) return false;
    if (!isValidPort(normalized.startPort) || !isValidPort(normalized.endPort || normalized.startPort)) return false;
    if (!isValidDestination(normalized.destination)) return false;
    if (!isValidProtocol(normalized.protocol)) return false;
    if (normalized.type === 'RANGE' && Number(normalized.startPort) > Number(normalized.endPort || normalized.startPort)) return false;
    return true;
};

const validateRule = (rule) => validateNormalizedRule(normalizeRule(rule));

// 从 /etc/nat.conf 读取规则
let rules = [];
const readRulesFile = () => {
    fs.readFile('/etc/nat.conf', 'utf8', (err, data) => {
        if (err) {
            console.error('读取配置文件失败:', err);
            return;
        }
        rules = data.trim().split('\n').map(line => {
            line = line.split('#')[0].trim(); // 移除注释
            return line ? line.split(',') : null;
        }).filter(Boolean).map(parts => {
            const normalized = normalizeRule({
                type: parts[0],
                startPort: parts[1],
                endPort: parts[2] || null,
                destination: parts[3],
                protocol: parts[4] || null // 新增协议字段
            });
            return validateNormalizedRule(normalized) ? normalized : null;
        }).filter(Boolean);
    });
};
readRulesFile();

// 身份验证中间件
function isAuthenticated(req, res, next) {
    const sessionId = req.signedCookies.auth;
    const session = sessionId && activeSessions.get(sessionId);
    if (!session) {
        res.clearCookie('auth');
        return res.redirect('/index');
    }
    const isExpired = Date.now() - session.created > SESSION_TTL_MS;
    if (isExpired) {
        activeSessions.delete(sessionId);
        res.clearCookie('auth');
        return res.redirect('/index');
    }
    return next();
}
const cleanExpiredSessions = () => {
    const now = Date.now();
    for (const [id, session] of activeSessions.entries()) {
        if (now - session.created > SESSION_TTL_MS) {
            activeSessions.delete(id);
        }
    }
};
setInterval(cleanExpiredSessions, SESSION_TTL_MS).unref();

// 路由: 登录页面
app.get('/index', (req, res) => {
    if (req.signedCookies.auth && activeSessions.has(req.signedCookies.auth)) {
        return res.redirect('/admin');
    }
    res.sendFile(path.join(__dirname, 'public/index.html'));
});

// 路由: 后台管理，需身份验证
app.get('/admin', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin.html'));
});

// 路由: 登录请求处理
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = users[username];

    if (hashedPassword && await bcrypt.compare(password, hashedPassword)) {
        const sessionId = crypto.randomBytes(32).toString('hex');
        activeSessions.set(sessionId, { user: username, created: Date.now() });
        res.cookie('auth', sessionId, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            signed: true,
            maxAge: SESSION_TTL_MS
        }); // 设置cookie
        res.redirect('/admin');
    } else {
        res.status(401).send('用户名或密码错误');
    }
});

// 其他需要身份验证的路由
app.get('/api/rules', isAuthenticated, (req, res) => {
    res.json(rules);
});

app.post('/edit-rule', isAuthenticated, (req, res) => {
    const { index, startPort, endPort, destination, protocol } = req.body;
    if (index < 0 || index >= rules.length) {
        return res.status(400).json({ message: '无效的规则索引' });
    }

    const candidate = {
        type: rules[index].type,
        startPort,
        endPort,
        destination,
        protocol // 更新协议
    };

    const normalized = normalizeRule(candidate);
    if (!validateNormalizedRule(normalized)) {
        return res.status(400).json({ message: '规则验证失败，请检查输入' });
    }
    normalized.endPort = normalized.endPort || normalized.startPort;

    rules[index] = normalized;
    res.json({ message: '规则编辑成功' });
});

// 处理保存规则的请求
app.post('/save-rules', isAuthenticated, (req, res) => {
    if (!Array.isArray(req.body.rules)) {
        return res.status(400).json({ message: '规则格式错误' });
    }

    const normalizedRules = [];
    for (const rule of req.body.rules) {
        const normalized = normalizeRule(rule);
        if (!validateNormalizedRule(normalized)) {
            return res.status(400).json({ message: '规则验证失败，请检查输入' });
        }
        const endPort = normalized.endPort || normalized.startPort;
        normalizedRules.push({ ...normalized, endPort });
    }

    const rulesData = normalizedRules.map(rule => {
        return `${rule.type},${rule.startPort},${rule.endPort},${rule.destination}${rule.protocol ? ',' + rule.protocol : ''}`;
    }).join('\n');

    fs.writeFile('/etc/nat.conf', rulesData, (err) => {
        if (err) {
            return res.status(500).json({ message: '保存规则失败' });
        }
        readRulesFile(); // 重新加载规则
        res.json({ message: '规则保存成功' });
    });
});

// 登出
app.post('/logout', (req, res) => {
    const sessionId = req.signedCookies.auth;
    if (sessionId) {
        activeSessions.delete(sessionId);
    }
    res.clearCookie('auth'); // 清除cookie
    res.redirect('/index'); // 重定向到登录页面
});

// 错误处理
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('服务器内部发生错误！');
});

// 启动服务器
https.createServer(options, app).listen(PORT, () => {
    console.log(`服务器在 https://localhost:${PORT} 上运行`);
});
