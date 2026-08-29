const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());

const db = new Database(path.join(__dirname, 'social.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    UNIQUE(post_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

function genToken() {
  return crypto.randomBytes(24).toString('hex');
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Chưa đăng nhập' });
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Phiên đăng nhập không hợp lệ' });
  req.userId = session.user_id;
  next();
}

function optionalAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token) {
    const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    if (session) req.userId = session.user_id;
  }
  next();
}

app.post('/api/social/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !username.trim() || !password || password.length < 4) {
    return res.status(400).json({ error: 'Tên đăng nhập và mật khẩu (tối thiểu 4 ký tự) là bắt buộc' });
  }
  const cleanUsername = username.trim();
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(cleanUsername);
  if (existing) return res.status(409).json({ error: 'Tên đăng nhập đã tồn tại' });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(cleanUsername, hash);
  const token = genToken();
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, info.lastInsertRowid);
  res.status(201).json({ token, user: { id: info.lastInsertRowid, username: cleanUsername } });
});

app.post('/api/social/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get((username || '').trim());
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu' });
  }
  const token = genToken();
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, user.id);
  res.json({ token, user: { id: user.id, username: user.username } });
});

app.get('/api/social/posts', optionalAuth, (req, res) => {
  const posts = db.prepare(`
    SELECT posts.id, posts.content, posts.created_at, users.username,
      (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) AS like_count,
      (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) AS comment_count
    FROM posts JOIN users ON posts.user_id = users.id
    ORDER BY posts.id DESC
  `).all();

  const likedStmt = db.prepare('SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?');
  posts.forEach(p => {
    p.liked_by_me = req.userId ? !!likedStmt.get(p.id, req.userId) : false;
  });
  res.json(posts);
});

app.post('/api/social/posts', auth, (req, res) => {
  const content = (req.body.content || '').trim();
  if (!content) return res.status(400).json({ error: 'Nội dung không được để trống' });
  const info = db.prepare('INSERT INTO posts (user_id, content) VALUES (?, ?)').run(req.userId, content);
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.userId);
  res.status(201).json({
    id: info.lastInsertRowid,
    content,
    username: user.username,
    created_at: new Date().toISOString(),
    like_count: 0,
    comment_count: 0,
    liked_by_me: false,
  });
});

app.post('/api/social/posts/:id/like', auth, (req, res) => {
  const postId = Number(req.params.id);
  const existing = db.prepare('SELECT id FROM likes WHERE post_id = ? AND user_id = ?').get(postId, req.userId);
  if (existing) {
    db.prepare('DELETE FROM likes WHERE id = ?').run(existing.id);
  } else {
    db.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)').run(postId, req.userId);
  }
  const count = db.prepare('SELECT COUNT(*) AS c FROM likes WHERE post_id = ?').get(postId).c;
  res.json({ liked: !existing, like_count: count });
});

app.get('/api/social/posts/:id/comments', (req, res) => {
  const postId = Number(req.params.id);
  const comments = db.prepare(`
    SELECT comments.id, comments.content, comments.created_at, users.username
    FROM comments JOIN users ON comments.user_id = users.id
    WHERE post_id = ? ORDER BY comments.id ASC
  `).all(postId);
  res.json(comments);
});

app.post('/api/social/posts/:id/comments', auth, (req, res) => {
  const postId = Number(req.params.id);
  const content = (req.body.content || '').trim();
  if (!content) return res.status(400).json({ error: 'Bình luận không được để trống' });
  db.prepare('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)').run(postId, req.userId, content);
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.userId);
  res.status(201).json({ content, username: user.username, created_at: new Date().toISOString() });
});

const PORT = 3003;
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Social API running on http://127.0.0.1:${PORT}`);
});
