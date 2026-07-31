const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const JWT_SECRET = process.env.SECRET_KEY || 'bi_mat_khong_the_tiet_lo_123';
const MONGO_URI = process.env.MONGO_URI;

if (MONGO_URI) {
  mongoose.connect(MONGO_URI)
    .then(() => console.log('Đã kết nối thành công với MongoDB Cloud!'))
    .catch(err => console.error('Lỗi kết nối MongoDB:', err));
} else {
  console.error('CẢNH BÁO: Chưa tìm thấy biến MONGO_URI!');
}

// Cấu hình gửi Mail qua Gmail Nodemailer
// Cấu hình Nodemailer chuẩn cho Render (Ép buộc dùng IPv4)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // Bắt buộc false cho cổng 587
  family: 4,     // ÉP NGUYÊN NÚT DÙNG IPV4 (Sửa triệt để lỗi ENETUNREACH)
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Bộ nhớ tạm lưu OTP
const otpStore = {}; 

// Schema User
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  balance: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// ---------------- API ENDPOINTS ----------------

// 1. Gửi OTP đến Gmail
app.post('/api/send-otp', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin!' });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Tên đăng nhập hoặc Email đã tồn tại!' });
    }

    // Tạo mã OTP 6 số
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(password, 10);

    // Lưu thông tin tạm thời trong 5 phút
    otpStore[email] = { username, password: hashedPassword, otp, expiresAt: Date.now() + 5 * 60 * 1000 };

    // Gửi mail
    const mailOptions = {
      from: `"TaskNova System" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Mã xác thực OTP đăng ký TaskNova',
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0f172a; color: #ffffff; border-radius: 10px;">
          <h2 style="color: #38bdf8;">Xác thực tài khoản TaskNova</h2>
          <p>Mã OTP của bạn là: <b style="font-size: 24px; color: #4ade80;">${otp}</b></p>
          <p>Mã này có hiệu lực trong vòng 5 phút. Vui lòng không chia sẻ mã này cho ai.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: 'Mã OTP đã được gửi về Gmail của bạn!' });

  } catch (error) {
    console.error('Lỗi gửi OTP:', error);
    res.status(500).json({ error: 'Không thể gửi email OTP. Kiểm tra lại địa chỉ Gmail!' });
  }
});

// 2. Xác thực OTP & Tạo tài khoản
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const record = otpStore[email];

    if (!record) {
      return res.status(400).json({ error: 'Yêu cầu không hợp lệ hoặc đã hết hạn!' });
    }

    if (Date.now() > record.expiresAt) {
      delete otpStore[email];
      return res.status(400).json({ error: 'Mã OTP đã hết hạn!' });
    }

    if (record.otp !== otp) {
      return res.status(400).json({ error: 'Mã OTP không chính xác!' });
    }

    // Tạo tài khoản chính thức vào DB
    const newUser = new User({
      username: record.username,
      password: record.password,
      email: email
    });

    await newUser.save();
    delete otpStore[email];

    const token = jwt.sign({ userId: newUser._id, username: newUser.username }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Đăng ký thành công!',
      token,
      user: { name: newUser.username, email: newUser.email, balance: newUser.balance }
    });

  } catch (error) {
    console.error('Lỗi xác thực:', error);
    res.status(500).json({ error: 'Đã có lỗi xảy ra trên máy chủ!' });
  }
});

// 3. Đăng nhập với Username & Password
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Vui lòng điền Tên đăng nhập và Mật khẩu!' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Tên đăng nhập hoặc mật khẩu không đúng!' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Tên đăng nhập hoặc mật khẩu không đúng!' });
    }

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Đăng nhập thành công!',
      token,
      user: { name: user.username, email: user.email, balance: user.balance }
    });
  } catch (error) {
    res.status(500).json({ error: 'Lỗi máy chủ!' });
  }
});

app.get('{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server đang chạy tại port ${PORT}`));