require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const PORT = process.env.PORT || 3000;


let idCounter = 1;
const users = new Map();
const userById = new Map(); 
const activeSession = new Map();


function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}


function logLoginAttempt(username, success, ip) {
  const time = new Date().toISOString();
  const status = success ? 'SUCCESS' : 'FAIL';
  console.log(`[${time}] LOGIN ${status} username=${escapeHtml(username)} ip=${ip || 'unknown'}`);
}


const loginRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  message: { error: 'Слишком много попыток входа. Попробуйте через минуту.' },
  standardHeaders: true,
});


function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const storedToken = activeSession.get(payload.userId);
    if (storedToken !== token) {
      return res.status(401).json({ error: 'Сессия недействительна (вход с другого устройства)' });
    }
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Недействительный или истёкший токен' });
  }
}


function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}


app.get('/', (req, res) => {
  res.json({
    name: 'Auth API',
    routes: {
      'POST /register': 'Регистрация',
      'POST /login': 'Вход (3 попытки/мин)',
      'POST /refresh': 'Обновление токена',
      'POST /logout': 'Выход',
      'GET /profile': 'Профиль (нужен токен)',
      'GET /admin': 'Только admin',
      'GET /moderator': 'moderator или admin',
    },
  });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Укажите username и password' });
  }
  if (users.has(username)) {
    return res.status(400).json({ error: 'Пользователь уже существует' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: idCounter++,
    username,
    passwordHash,
    role: 'user',
    lastLogin: null,
  };
  users.set(username, user);
  userById.set(user.id, user);
  res.status(201).json({
    id: user.id,
    username: escapeHtml(user.username),
    role: user.role,
  });
});


app.post('/login', loginRateLimiter, async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip || req.connection?.remoteAddress;
  if (!username || !password) {
    logLoginAttempt(username || '', false, ip);
    return res.status(400).json({ error: 'Укажите username и password' });
  }
  const user = users.get(username);
  if (!user) {
    logLoginAttempt(username, false, ip);
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    logLoginAttempt(username, false, ip);
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  user.lastLogin = new Date();
  const token = jwt.sign(
    { userId: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
  activeSession.set(user.id, token);
  logLoginAttempt(username, true, ip);
  res.json({
    token,
    expiresIn: '15m',
    user: {
      id: user.id,
      username: escapeHtml(user.username),
      role: user.role,
    },
  });
});


app.post('/refresh', authenticate, (req, res) => {
  const user = userById.get(req.user.userId);
  if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
  const newToken = jwt.sign(
    { userId: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
  activeSession.set(user.id, newToken);
  res.json({
    token: newToken,
    expiresIn: '15m',
  });
});


app.post('/logout', authenticate, (req, res) => {
  activeSession.delete(req.user.userId);
  res.json({ message: 'Выход выполнен' });
});


app.get('/profile', authenticate, (req, res) => {
  const user = userById.get(req.user.userId);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({
    id: user.id,
    username: escapeHtml(user.username),
    role: user.role,
    lastLogin: user.lastLogin,
  });
});


app.get('/admin', authenticate, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin panel' });
});


app.get('/moderator', authenticate, requireRole('moderator', 'admin'), (req, res) => {
  res.json({ message: 'Moderator panel' });
});


async function createTestAdmin() {
  if (users.has('admin')) return;
  const passwordHash = await bcrypt.hash('admin123', 10);
  const user = {
    id: idCounter++,
    username: 'admin',
    passwordHash,
    role: 'admin',
    lastLogin: null,
  };
  users.set('admin', user);
  userById.set(user.id, user);
  console.log('Создан тестовый admin / admin123');
}

app.listen(PORT, async () => {
  await createTestAdmin();
  console.log(`Сервер: http://localhost:${PORT}`);
});
