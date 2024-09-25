const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const crypto = require('crypto');

const app = express();
const port = 5050;
const SECRET_KEY = 'your_secret_key';
const ENCRYPTION_KEY = crypto.randomBytes(32); // 32 байта для AES-256
const IV_LENGTH = 16; // Длина инициализационного вектора для AES

app.use(express.json());

// Функция для шифрования пароля
function encryptPassword(password) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(password, 'utf-8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

// Функция для расшифровки пароля
function decryptPassword(encryptedPassword) {
  const parts = encryptedPassword.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encryptedText = Buffer.from(parts[1], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
  decrypted += decipher.final('utf-8');
  return decrypted;
}

// Регистрация пользователя
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, password], function(err) {
    if (err) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    res.status(201).json({ message: 'User registered successfully!' });
  });
});

// Логин и получение токена
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT id, password FROM users WHERE username = ?`, [username], (err, user) => {
    if (!user || user.password !== password) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ user_id: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Middleware для аутентификации
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Добавление пароля для сервиса
app.post('/add_password', authenticateToken, (req, res) => {
  const { service_name, password } = req.body;
  const encryptedPassword = encryptPassword(password);

  db.run(`INSERT INTO passwords (user_id, service_name, password) VALUES (?, ?, ?)`,
    [req.user.user_id, service_name, encryptedPassword],
    function(err) {
      if (err) {
        return res.status(500).json({ message: 'Failed to add password' });
      }
      res.status(201).json({ message: 'Password added successfully!' });
    });
});

// Получение всех паролей пользователя
app.get('/get_passwords', authenticateToken, (req, res) => {
  db.all(`SELECT service_name, password FROM passwords WHERE user_id = ?`, [req.user.user_id], (err, passwords) => {
    if (err) {
      return res.status(500).json({ message: 'Failed to retrieve passwords' });
    }

    // Расшифровка каждого пароля перед возвратом
    const decryptedPasswords = passwords.map(p => ({
      service_name: p.service_name,
      password: decryptPassword(p.password)
    }));

    res.json({ passwords: decryptedPasswords });
  });
});

// Получение пароля по имени сервиса
app.get('/get_password/:service_name', authenticateToken, (req, res) => {
  const service_name = req.params.service_name;

  db.get(`SELECT password FROM passwords WHERE user_id = ? AND service_name = ?`, [req.user.user_id, service_name], (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'Error retrieving password' });
    }

    if (!row) {
      return res.status(404).json({ message: 'Service not found' });
    }

    const decryptedPassword = decryptPassword(row.password);
    res.json({ service_name, password: decryptedPassword });
  });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
