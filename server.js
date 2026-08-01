const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
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
const otpStore = new Map();

// Hàm gửi Email qua Brevo REST API
async function sendBrevoEmail(toEmail, otp) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.EMAIL_USER || 'tasknova.team@gmail.com';

  if (!apiKey) {
    throw new Error('Thiếu BREVO_API_KEY trong biến môi trường!');
  }

  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': apiKey,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      sender: { name: 'TaskNova Support', email: senderEmail },
      to: [{ email: toEmail }],
      subject: 'Mã xác thực OTP đăng ký tài khoản TaskNova',
      htmlContent: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
          <div style="max-width: 500px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px;">
            <h2 style="color: #0284c7; text-align: center;">TaskNova OTP</h2>
            <p>Chào bạn,</p>
            <p>Mã xác thực OTP để đăng ký tài khoản của bạn là:</p>
            <div style="text-align: center; margin: 20px 0;">
              <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #0284c7; background: #e0f2fe; padding: 10px 20px; border-radius: 8px;">${otp}</span>
            </div>
            <p style="color: #666; font-size: 13px;">Mã này có hiệu lực trong 5 phút. Vui lòng không chia sẻ cho ai.</p>
          </div>
        </div>
      `
    })
  });

  const responseData = await response.json();

  if (!response.ok) {
    console.error('Chi tiết lỗi từ Brevo:', responseData);
    throw new Error(JSON.stringify(responseData));
  }

  return responseData;
}

// API: Gửi mã OTP
app.post('/api/send-otp', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin!' });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Tên đăng nhập hoặc Email đã được sử dụng!' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    otpStore.set(email, {
      username,
      password,
      otp,
      expires: Date.now() + 5 * 60 * 1000
    });

    await sendBrevoEmail(email, otp);

    res.json({ message: 'Mã OTP đã được gửi về Gmail của bạn!' });

  } catch (err) {
    console.error('Lỗi gửi OTP:', err.message);
    res.status(500).json({ error: 'Không thể gửi email OTP. Kiểm tra lại thông tin!' });
  }
});

// API: Xác nhận OTP & Đăng ký
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const record = otpStore.get(email);

    if (!record) return res.status(400).json({ error: 'Mã OTP đã hết hạn!' });
    if (Date.now() > record.expires) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'Mã OTP đã hết hạn!' });
    }
    if (record.otp !== otp) return res.status(400).json({ error: 'Mã OTP không chính xác!' });

    const hashedPassword = await bcrypt.hash(record.password, 10);
    const newUser = new User({
      username: record.username,
      password: hashedPassword,
      email: email,
      balance: 0
    });

    await newUser.save();
    otpStore.delete(email);

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
    res.status(500).json({ error: 'Lỗi hệ thống khi tạo tài khoản!' });
  }
});

// API: Đăng nhập
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Mật khẩu hoặc tên đăng nhập không đúng!' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Mật khẩu hoặc tên đăng nhập không đúng!' });

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
    res.status(500).json({ error: 'Lỗi hệ thống khi đăng nhập!' });
  }
});

// Sửa lỗi PathError wildcard ở đây (dùng /(.*) thay vì *)
app.get(/(.*)/, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server đang chạy tại port ${PORT}`));