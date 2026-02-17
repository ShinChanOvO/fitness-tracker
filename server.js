const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fitness-tracker-secret-key-2024';

// 中间件
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// 数据库初始化 - 支持 Railway/Render 的持久化目录
const dbPath = process.env.DB_PATH || './fitness.db';
const db = new sqlite3.Database(dbPath);

// 用户表
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// 健身记录表
db.run(`CREATE TABLE IF NOT EXISTS workouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  duration INTEGER,
  reps INTEGER,
  sets INTEGER,
  weight REAL,
  notes TEXT,
  date DATE DEFAULT (date('now')),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// 饮食记录表
db.run(`CREATE TABLE IF NOT EXISTS meals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  food TEXT NOT NULL,
  calories INTEGER,
  protein REAL,
  carbs REAL,
  fat REAL,
  date DATE DEFAULT (date('now')),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// 体重记录表
db.run(`CREATE TABLE IF NOT EXISTS weights (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  weight REAL NOT NULL,
  date DATE DEFAULT (date('now')),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// 喝水记录表
db.run(`CREATE TABLE IF NOT EXISTS water (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  date DATE DEFAULT (date('now')),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// 用户设置表
db.run(`CREATE TABLE IF NOT EXISTS settings (
  user_id INTEGER PRIMARY KEY,
  theme TEXT DEFAULT 'dark',
  daily_water_goal INTEGER DEFAULT 2000,
  daily_calorie_goal INTEGER DEFAULT 2000,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// 中间件：验证 Token
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: '请先登录' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
};

// 注册
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: '请填写邮箱和密码' });
  }
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [email, hashedPassword], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: '该邮箱已被注册' });
        }
        return res.status(500).json({ error: '注册失败' });
      }
      
      db.run(`INSERT INTO settings (user_id) VALUES (?)`, [this.lastID]);
      
      const token = jwt.sign({ userId: this.lastID }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, message: '注册成功' });
    });
  } catch (err) {
    res.status(500).json({ error: '注册失败' });
  }
});

// 登录
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error: '邮箱或密码错误' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: '邮箱或密码错误' });
    }
    
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email: user.email });
  });
});

// 获取用户设置
app.get('/api/settings', authenticate, (req, res) => {
  db.get(`SELECT * FROM settings WHERE user_id = ?`, [req.userId], (err, settings) => {
    if (err) return res.status(500).json({ error: '获取设置失败' });
    res.json(settings || { theme: 'dark', daily_water_goal: 2000, daily_calorie_goal: 2000 });
  });
});

// 更新设置
app.put('/api/settings', authenticate, (req, res) => {
  const { theme, daily_water_goal, daily_calorie_goal } = req.body;
  db.run(`UPDATE settings SET theme = ?, daily_water_goal = ?, daily_calorie_goal = ? WHERE user_id = ?`,
    [theme, daily_water_goal, daily_calorie_goal, req.userId], (err) => {
      if (err) return res.status(500).json({ error: '保存设置失败' });
      res.json({ message: '设置已保存' });
    });
});

// 健身记录
app.post('/api/workouts', authenticate, (req, res) => {
  const { type, duration, reps, sets, weight, notes, date } = req.body;
  db.run(`INSERT INTO workouts (user_id, type, duration, reps, sets, weight, notes, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [req.userId, type, duration, reps, sets, weight, notes, date], function(err) {
      if (err) return res.status(500).json({ error: '保存失败' });
      res.json({ id: this.lastID, message: '记录已保存' });
    });
});

app.get('/api/workouts', authenticate, (req, res) => {
  const { startDate, endDate } = req.query;
  let sql = `SELECT * FROM workouts WHERE user_id = ?`;
  const params = [req.userId];
  
  if (startDate && endDate) {
    sql += ` AND date BETWEEN ? AND ?`;
    params.push(startDate, endDate);
  }
  sql += ` ORDER BY date DESC, created_at DESC`;
  
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: '获取失败' });
    res.json(rows);
  });
});

app.delete('/api/workouts/:id', authenticate, (req, res) => {
  db.run(`DELETE FROM workouts WHERE id = ? AND user_id = ?`, [req.params.id, req.userId], (err) => {
    if (err) return res.status(500).json({ error: '删除失败' });
    res.json({ message: '已删除' });
  });
});

// 饮食记录
app.post('/api/meals', authenticate, (req, res) => {
  const { type, food, calories, protein, carbs, fat, date } = req.body;
  db.run(`INSERT INTO meals (user_id, type, food, calories, protein, carbs, fat, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [req.userId, type, food, calories, protein, carbs, fat, date], function(err) {
      if (err) return res.status(500).json({ error: '保存失败' });
      res.json({ id: this.lastID, message: '记录已保存' });
    });
});

app.get('/api/meals', authenticate, (req, res) => {
  const { startDate, endDate } = req.query;
  let sql = `SELECT * FROM meals WHERE user_id = ?`;
  const params = [req.userId];
  
  if (startDate && endDate) {
    sql += ` AND date BETWEEN ? AND ?`;
    params.push(startDate, endDate);
  }
  sql += ` ORDER BY date DESC, created_at DESC`;
  
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: '获取失败' });
    res.json(rows);
  });
});

app.delete('/api/meals/:id', authenticate, (req, res) => {
  db.run(`DELETE FROM meals WHERE id = ? AND user_id = ?`, [req.params.id, req.userId], (err) => {
    if (err) return res.status(500).json({ error: '删除失败' });
    res.json({ message: '已删除' });
  });
});

// 体重记录
app.post('/api/weights', authenticate, (req, res) => {
  const { weight, date } = req.body;
  db.run(`INSERT INTO weights (user_id, weight, date) VALUES (?, ?, ?)`,
    [req.userId, weight, date], function(err) {
      if (err) return res.status(500).json({ error: '保存失败' });
      res.json({ id: this.lastID, message: '记录已保存' });
    });
});

app.get('/api/weights', authenticate, (req, res) => {
  const { startDate, endDate } = req.query;
  let sql = `SELECT * FROM weights WHERE user_id = ?`;
  const params = [req.userId];
  
  if (startDate && endDate) {
    sql += ` AND date BETWEEN ? AND ?`;
    params.push(startDate, endDate);
  }
  sql += ` ORDER BY date DESC`;
  
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: '获取失败' });
    res.json(rows);
  });
});

app.delete('/api/weights/:id', authenticate, (req, res) => {
  db.run(`DELETE FROM weights WHERE id = ? AND user_id = ?`, [req.params.id, req.userId], (err) => {
    if (err) return res.status(500).json({ error: '删除失败' });
    res.json({ message: '已删除' });
  });
});

// 喝水记录
app.post('/api/water', authenticate, (req, res) => {
  const { amount, date } = req.body;
  db.run(`INSERT INTO water (user_id, amount, date) VALUES (?, ?, ?)`,
    [req.userId, amount, date], function(err) {
      if (err) return res.status(500).json({ error: '保存失败' });
      res.json({ id: this.lastID, message: '记录已保存' });
    });
});

app.get('/api/water', authenticate, (req, res) => {
  const { startDate, endDate } = req.query;
  let sql = `SELECT * FROM water WHERE user_id = ?`;
  const params = [req.userId];
  
  if (startDate && endDate) {
    sql += ` AND date BETWEEN ? AND ?`;
    params.push(startDate, endDate);
  }
  sql += ` ORDER BY date DESC, created_at DESC`;
  
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: '获取失败' });
    res.json(rows);
  });
});

app.delete('/api/water/:id', authenticate, (req, res) => {
  db.run(`DELETE FROM water WHERE id = ? AND user_id = ?`, [req.params.id, req.userId], (err) => {
    if (err) return res.status(500).json({ error: '删除失败' });
    res.json({ message: '已删除' });
  });
});

// 统计数据
app.get('/api/stats', authenticate, (req, res) => {
  const { startDate, endDate } = req.query;
  
  const stats = {};
  
  db.get(`SELECT COUNT(*) as count, SUM(duration) as totalDuration FROM workouts WHERE user_id = ? AND date BETWEEN ? AND ?`, 
    [req.userId, startDate || '1970-01-01', endDate || '2100-12-31'], (err, row) => {
    stats.workouts = row;
    
    db.get(`SELECT COUNT(*) as count, SUM(calories) as totalCalories, SUM(protein) as totalProtein FROM meals WHERE user_id = ? AND date BETWEEN ? AND ?`,
      [req.userId, startDate || '1970-01-01', endDate || '2100-12-31'], (err, row) => {
      stats.meals = row;
      
      db.get(`SELECT AVG(weight) as avgWeight, MIN(weight) as minWeight, MAX(weight) as maxWeight FROM weights WHERE user_id = ? AND date BETWEEN ? AND ?`,
        [req.userId, startDate || '1970-01-01', endDate || '2100-12-31'], (err, row) => {
        stats.weights = row;
        
        db.get(`SELECT SUM(amount) as totalWater FROM water WHERE user_id = ? AND date BETWEEN ? AND ?`,
          [req.userId, startDate || '1970-01-01', endDate || '2100-12-31'], (err, row) => {
          stats.water = row;
          res.json(stats);
        });
      });
    });
  });
});

// Vercel 适配
if (process.env.VERCEL) {
  app.use(express.static('./public'));
  
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

app.listen(PORT, () => {
  console.log(`🚀 Fitness Tracker 运行在端口 ${PORT}`);
});
