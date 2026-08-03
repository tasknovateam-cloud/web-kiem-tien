const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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

// API 1: ĐĂNG KÝ TÀI KHOẢN TRỰC TIẾP TỪ FRONTEND
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'Vui lòng điền đầy đủ thông tin!' });
    }

    // Kiểm tra trùng lặp
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Tên đăng nhập hoặc Email đã được sử dụng!' });
    }

    // Mã hóa mật khẩu & tạo user mới
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      balance: 0
    });

    await newUser.save();

    res.json({
      success: true,
      message: 'Đăng ký tài khoản thành công!',
      user: { username: newUser.username, email: newUser.email, balance: newUser.balance }
    });

  } catch (err) {
    console.error('Lỗi Đăng Ký:', err);
    res.status(500).json({ success: false, message: 'Lỗi máy chủ khi tạo tài khoản!' });
  }
});

// API 2: ĐĂNG NHẬP (Hỗ trợ cả Username và Email)
app.post('/api/login', async (req, res) => {
  try {
    const { usernameOrEmail, password, username } = req.body;
    const inputUser = usernameOrEmail || username;

    if (!inputUser || !password) {
      return res.status(400).json({ success: false, message: 'Vui lòng nhập tài khoản và mật khẩu!' });
    }

    // Tìm user theo Username hoặc Email
    const user = await User.findOne({
      $or: [{ username: inputUser }, { email: inputUser }]
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Mật khẩu hoặc tên đăng nhập không đúng!' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Mật khẩu hoặc tên đăng nhập không đúng!' });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.SECRET_KEY || 'defaultsecretkey',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Đăng nhập thành công!',
      token,
      user: { id: user._id, username: user.username, email: user.email, balance: user.balance }
    });
  } catch (err) {
    console.error('Lỗi Đăng Nhập:', err);
    res.status(500).json({ success: false, message: 'Lỗi hệ thống khi đăng nhập!' });
  }
});

// API 3: LẤY THÔNG TIN USER VÀ SỐ DƯ TỪ MONGODB
app.get('/api/user/me', async (req, res) => {
  try {
    const username = req.query.username;
    if (!username) return res.status(400).json({ success: false, message: 'Thiếu username' });

    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'Không tìm thấy user' });

    res.json({
      success: true,
      user: {
        username: user.username,
        email: user.email,
        balance: user.balance || 0
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi máy chủ khi lấy thông tin user' });
  }
});

// CHÚ Ý: Bắt đường dẫn HTML phải đặt ở DƯỚI CÙNG các API
app.get(/(.*)/, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Cổng khởi chạy Server Render
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại port ${PORT}`);
});