const dns = require('dns');
dns.setDefaultResultOrder('ipv4first'); // Ép Node.js luôn ưu tiên phân giải IPv4

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// 1. Kết nối MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Đã kết nối MongoDB thành công!'))
  .catch(err => console.error('Lỗi kết nối MongoDB:', err));

// 2. Schema người dùng
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  balance: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Lưu tạm OTP trong bộ nhớ (Email -> { otp, username, password, expires })
const otpStore = new Map();

// 3. Cấu hình Nodemailer gửi mail qua Gmail (IPv4)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// API: Gửi mã OTP về Gmail
app.post('/api/send-otp', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin!' });
    }

    // Kiểm tra username hoặc email đã tồn tại chưa
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Tên đăng nhập hoặc Email đã được sử dụng!' });
    }

    // Tạo mã OTP 6 chữ số
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Lưu thông tin tạm thời (hết hạn sau 5 phút)
    otpStore.set(email, {
      username,
      password,
      otp,
      expires: Date.now() + 5 * 60 * 1000
    });

    // Nội dung Email OTP
    const mailOptions = {
      from: `"TaskNova Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Mã xác thực OTP đăng ký tài khoản TaskNova',
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
          <div style="max-width: 500px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px;">
            <h2 style="color: #0284c7; text-align: center;">TaskNova OTP</h2>
            <p>Chào bạn,</p>
            <p>Mã xác thực OTP để đăng ký tài khoản của bạn là:</p>
            <div style="text-align: center; margin: 20px 0;">
              <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #0284c7; background: #e0f2fe; padding: 10px 20px; border-radius: 8px;">${otp}</span>
            </div>
            <p style="color: #666; font-size: 13px;">Mã này có hiệu lực trong 5 phút. Vui lòng không chia sẻ mã này cho ai.</p>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: 'Mã OTP đã được gửi về Gmail của bạn!' });

  } catch (err) {
    console.error('Lỗi gửi OTP:', err);
    res.status(500).json({ error: 'Không thể gửi email OTP. Kiểm tra lại địa chỉ Gmail!' });
  }
});

// API: Xác nhận OTP & Tạo tài khoản
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const record = otpStore.get(email);

    if (!record) {
      return res.status(400).json({ error: 'Mã OTP đã hết hạn hoặc chưa được yêu cầu!' });
    }

    if (Date.now() > record.expires) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'Mã OTP đã hết hạn!' });
    }

    if (record.otp !== otp) {
      return res.status(400).json({ error: 'Mã OTP không chính xác!' });
    }

    // Mã hóa mật khẩu và tạo user mới trong CSDL
    const hashedPassword = await bcrypt.hash(record.password, 10);
    const newUser = new User({
      username: record.username,
      password: hashedPassword,
      email: email,
      balance: 0
    });

    await newUser.save();
    otpStore.delete(email);

    // Tạo JWT Token
    const token = jwt.sign(
      { userId: newUser._id, username: newUser.username },
      process.env.SECRET_KEY || 'defaultsecretkey',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Đăng ký tài khoản thành công!',
      token,
      user: { id: newUser._id, name: newUser.username, email: newUser.email, balance: newUser.balance }
    });

  } catch (err) {
    console.error('Lỗi xác nhận OTP:', err);
    res.status(500).json({ error: 'Đã xảy ra lỗi khi tạo tài khoản!' });
  }
});

// API: Đăng nhập
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).json({ error: 'Tên đăng nhập hoặc mật khẩu không đúng!' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Tên đăng nhập hoặc mật khẩu không đúng!' });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.SECRET_KEY || 'defaultsecretkey',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Đăng nhập thành công!',
      token,
      user: { id: user._id, name: user.username, email: user.email, balance: user.balance }
    });

  } catch (err) {
    console.error('Lỗi đăng nhập:', err);
    res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống!' });
  }
});

// Phục vụ giao diện trang chủ
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Chạy Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại port ${PORT}`);
});