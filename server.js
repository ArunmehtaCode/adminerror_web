const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Serve static files, allow dotfiles to expose .git
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'allow' }));

const SECRET_KEY = 'super_secret_key_that_is_never_actually_checked';

// Mock Database
let users = [
  { id: 1, name: 'Admin User', email: 'admin@corpadmin.local', role: 'admin', lastLogin: '2023-10-01' },
  { id: 2, name: 'John Doe', email: 'john@corpadmin.local', role: 'user', lastLogin: '2023-10-02' },
  { id: 3, name: 'Jane Smith', email: 'jane@corpadmin.local', role: 'user', lastLogin: '2023-10-05' },
  { id: 4, name: 'Bob Wilson', email: 'bob@corpadmin.local', role: 'user', lastLogin: '2023-09-28' },
  { id: 5, name: 'Alice Brown', email: 'alice@corpadmin.local', role: 'manager', lastLogin: '2023-10-06' },
  { id: 6, name: 'Charlie Davis', email: 'charlie@corpadmin.local', role: 'user', lastLogin: '2023-09-15' },
  { id: 7, name: 'Eve White', email: 'eve@corpadmin.local', role: 'user', lastLogin: '2023-10-07' },
  { id: 8, name: 'Frank Miller', email: 'frank@corpadmin.local', role: 'user', lastLogin: '2023-10-04' },
  { id: 9, name: 'Grace Lee', email: 'grace@corpadmin.local', role: 'user', lastLogin: '2023-10-03' },
  { id: 10, name: 'Hank Green', email: 'hank@corpadmin.local', role: 'user', lastLogin: '2023-09-30' }
];

// Vulnerability 1 & 4: Broken Authentication & JWT
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'admin') {
    const token = jwt.sign({ username: 'admin', role: 'admin' }, SECRET_KEY);
    res.json({ success: true, token, redirect: '/admin' });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

// Middleware vulnerability: Broken JWT verification
// It checks if token exists, but DOES NOT verify signature.
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    // Intentionally vulnerable: decode without verifying signature
    const decoded = jwt.decode(token);
    if (decoded) {
      req.user = decoded;
      return next();
    }
  }
  // Let it pass anyway sometimes? No, let's just accept any string as a token for maximum vulnerability
  if (authHeader) {
     req.user = { role: 'admin' }; // Fallback to admin if token is completely garbage
     return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
};

// API Routes
app.get('/api/users', verifyToken, (req, res) => {
  res.json(users);
});

// Vulnerability 5: Privilege Escalation
// No check to see if the requesting user is actually an admin before updating roles.
app.put('/api/users/:id', verifyToken, (req, res) => {
  const userId = parseInt(req.params.id);
  const { role } = req.body;
  
  const userIndex = users.findIndex(u => u.id === userId);
  if (userIndex !== -1) {
    if (role) {
      users[userIndex].role = role;
    }
    res.json({ success: true, user: users[userIndex] });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// Vulnerability 6: Verbose Error Messages (Information Exposure)
app.get('/api/debug', (req, res) => {
  try {
    throw new Error('Database connection failed at TCP port 5432. Invalid credentials provided for internal DB.');
  } catch (err) {
    res.status(500).json({
      error: err.message,
      stack: err.stack,
      env: process.env,
      process: {
        pid: process.pid,
        versions: process.versions,
        cwd: process.cwd()
      }
    });
  }
});

// Vulnerability 7: Outdated Dependency Exposure
app.get('/api/system-info', verifyToken, (req, res) => {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
    res.json({
      serviceName: 'CorpAdmin Backend service',
      uptime: process.uptime(),
      dependencies: pkg.dependencies || {}
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to read package.json' });
  }
});

// Expose /admin explicitly for the static files if not already picked up by express.static
app.get('/admin', (req, res) => {
   res.sendFile(path.join(__dirname, 'public/admin/dashboard.html'));
});

// Start Server
const PORT = process.env.PORT || 3002;
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`CorpAdmin Pro Demo running on http://localhost:${PORT}`);
  });
}

module.exports = app;
