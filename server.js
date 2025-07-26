const fs = require('fs');
const fsp = fs.promises;
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Database file paths
const ordersDBPath = path.join(__dirname, 'orders.json');
const usersDBPath = path.join(__dirname, 'users.json');

// Ensure directories exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Initialize databases
async function initializeDB() {
  const dbs = [
    { path: ordersDBPath, init: '[]' },
    { path: usersDBPath, init: '[]' }
  ];
  
  for (const db of dbs) {
    try {
      await fsp.access(db.path);
    } catch {
      await fsp.writeFile(db.path, db.init, 'utf8');
    }
  }
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname))); // Serve current directory
app.use('/uploads', express.static(uploadDir));

// Email transporter setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Add this verification check during server startup
transporter.verify((error) => {
  if (error) {
    console.error('Mail transporter setup failed:', error);
  } else {
    console.log('Mail transporter is ready');
  }
});

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    message: 'Server is running and ready to accept orders'
  });
});

// OTP storage (in-memory)
const otpStorage = {};

// Password reset token storage (in-memory)
const resetTokens = {};

// Helper function to read JSON files
async function readJSONFile(filePath) {
  try {
    const data = await fsp.readFile(filePath, 'utf8');
    return data.trim() ? JSON.parse(data) : [];
  } catch (error) {
    console.error(`Error reading ${filePath}:`, error);
    return [];
  }
}

// Send OTP endpoint
app.post('/api/send-otp', async (req, res) => {
  const { emailOrMobile } = req.body;
  
  if (!emailOrMobile) {
    return res.status(400).json({ success: false, message: 'Email or mobile required' });
  }

  // Generate OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStorage[emailOrMobile] = otp;
  console.log(`OTP for ${emailOrMobile}: ${otp}`);

  try {
    const mailOptions = {
      from: `Golden Fabric <${process.env.EMAIL_USER}>`,
      to: emailOrMobile,
      subject: 'Your Verification Code',
      text: `Your OTP is: ${otp}`,
      html: `<p>Your OTP for Golden Fabric registration is: <b>${otp}</b></p>`
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`Email sent: ${info.messageId}`);
    
    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Email send error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send OTP',
      error: error.response || error.message
    });
  }
});

// User registration endpoint
app.post('/api/register', async (req, res) => {
  const { email, password, otp } = req.body;
  
  // Validate input
  if (!email || !password || !otp) {
    return res.status(400).json({ success: false, message: 'All fields required' });
  }

  // Verify OTP
  if (otpStorage[email] !== otp) {
    return res.status(400).json({ success: false, message: 'Invalid OTP' });
  }

  // Check existing users
  let users = await readJSONFile(usersDBPath);
  
  if (users.some(user => user.email.toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ success: false, message: 'User already exists' });
  }

  // Create new user
  const newUser = {
    id: uuidv4(),
    email,
    password,
    createdAt: new Date().toISOString()
  };

  // Save user
  users.push(newUser);
  await fsp.writeFile(usersDBPath, JSON.stringify(users, null, 2));
  
  // Clear OTP
  delete otpStorage[email];
  
  res.json({ success: true, message: 'Registration successful' });
});

// User login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password required' });
  }

  let users = await readJSONFile(usersDBPath);
  
  // Case-insensitive email matching
  const user = users.find(u => 
    u.email.toLowerCase() === email.toLowerCase() && 
    u.password === password
  );
  
  if (!user) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }

  // Remove password from response
  const { password: _, ...safeUser } = user;
  
  res.json({ 
    success: true, 
    message: 'Login successful', 
    user: safeUser 
  });
});

// Forgot password endpoint
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email required' });
  }

  // Check if email exists
  let users = await readJSONFile(usersDBPath);
  
  // Case-insensitive search
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  
  // Always return success to prevent email enumeration
  if (!user) {
    return res.json({ 
      success: true, 
      message: 'If this email is registered, you will receive a password reset link' 
    });
  }

  // Generate reset token (valid for 1 hour)
  const resetToken = uuidv4();
  const expiration = Date.now() + 3600000; // 1 hour
  
  resetTokens[resetToken] = {
    email: user.email,
    expiration
  };

  // Send reset email
  const resetLink = `http://localhost:${PORT}/reset-password.html?token=${resetToken}`;
  
  try {
    const mailOptions = {
      from: `Golden Fabric <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <p>Password reset requested for ${email}</p>
        <p>Click here to reset: <a href="${resetLink}">Reset Password</a></p>
        <p><small>Link valid for 1 hour</small></p>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`Reset email sent: ${info.messageId}`);
    
    res.json({ 
      success: true, 
      message: 'Password reset link sent' 
    });
  } catch (error) {
    console.error('Password reset email error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send reset email',
      error: error.response || error.message
    });
  }
});

// Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  
  if (!token || !newPassword) {
    return res.status(400).json({ 
      success: false, 
      message: 'Token and new password required' 
    });
  }

  // Verify token
  const tokenData = resetTokens[token];
  if (!tokenData) {
    return res.status(400).json({ 
      success: false, 
      message: 'Invalid or expired reset token' 
    });
  }

  // Check expiration
  if (Date.now() > tokenData.expiration) {
    delete resetTokens[token];
    return res.status(400).json({ 
      success: false, 
      message: 'Reset token has expired' 
    });
  }

  // Update user password
  let users = await readJSONFile(usersDBPath);
  
  // Find user and update password
  const userIndex = users.findIndex(u => 
    u.email.toLowerCase() === tokenData.email.toLowerCase()
  );
  
  if (userIndex === -1) {
    return res.status(400).json({ 
      success: false, 
      message: 'User not found' 
    });
  }
  
  users[userIndex].password = newPassword;
  
  // Save updated users
  try {
    await fsp.writeFile(usersDBPath, JSON.stringify(users, null, 2));
    // Delete the used token
    delete resetTokens[token];
    
    res.json({ 
      success: true, 
      message: 'Password reset successfully' 
    });
  } catch (error) {
    console.error('Error writing users DB:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to reset password' 
    });
  }
});

// Order submission endpoint
app.post('/api/orders', upload.single('screenshot'), async (req, res) => {
  try {
    if (!req.body.data) {
      return res.status(400).json({ success: false, error: "Invalid content type" });
    }

    const orderData = JSON.parse(req.body.data);
    let orders = await readJSONFile(ordersDBPath);
    
    const newOrder = {
      id: uuidv4(),
      ...orderData,
      status: 'Received',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      screenshot: req.file ? `/uploads/${req.file.filename}` : null
    };
    
    orders.push(newOrder);
    await fsp.writeFile(ordersDBPath, JSON.stringify(orders, null, 2));
    
    res.status(201).json({ 
      success: true,
      message: "Order placed successfully!",
      orderId: newOrder.id
    });
  } catch (error) {
    console.error("Order error:", error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Start server
initializeDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🚀 Server running on http://localhost:${PORT}`);
    console.log(`📋 API Endpoints:`);
    console.log(`   POST http://localhost:${PORT}/api/orders          - Submit order`);
    console.log(`   POST http://localhost:${PORT}/api/send-otp        - Send OTP`);
    console.log(`   POST http://localhost:${PORT}/api/register        - Register user`);
    console.log(`   POST http://localhost:${PORT}/api/login           - User login`);
    console.log(`   POST http://localhost:${PORT}/api/forgot-password - Forgot password`);
    console.log(`   POST http://localhost:${PORT}/api/reset-password  - Reset password`);
    console.log(`   GET  http://localhost:${PORT}/api/health         - Health check\n`);
  });
});

// Error handling
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});