const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const GOOGLE_CLIENT_ID = '1092262111091-dafa4j9otpil74ptqbemda4bbn2j9a1i.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const JWT_SECRET = process.env.SECRET_KEY || 'bi_mat_khong_the_tiet_lo_123';

// Kết nối MongoDB Cloud
const MONGO_URI = process.env.MONGO_URI;

if (MONGO_URI) {
  mongoose.connect(MONGO_URI)
    .then(() => console.log('Đã kết nối thành công với MongoDB Cloud!'))
    .catch(err => console.error('Lỗi kết nối MongoDB:', err));
} else {
  console.error('CẢNH BÁO: Chưa tìm thấy biến MONGO_URI trong Environment!');
}

// Schema User (Gọn nhẹ chỉ lưu dữ liệu từ Google)
const userSchema = new mongoose.Schema({
  googleId: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  name: { type: String },
  avatar: { type: String },
  balance: { type: Number, default: 0 }, // Số dư tiền tệ cho TaskNova
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// ---------------- API ENDPOINTS ----------------

// API Duy nhất: Đăng nhập / Đăng ký qua Google
app.post('/api/google-login', async (req, res) => {
  try {
    const { token } = req.body;
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    // Tìm hoặc tạo mới người dùng
    let user = await User.findOne({ googleId });

    if (!user) {
      user = new User({
        googleId,
        email,
        name,
        avatar: picture
      });
      await user.save();
      console.log(`Tạo tài khoản mới thành công: ${email}`);
    }

    // Tạo JWT Token cho phiên đăng nhập
    const authToken = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Đăng nhập Google thành công!',
      token: authToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        balance: user.balance
      }
    });
  } catch (error) {
    console.error('Google Auth Error:', error);
    res.status(400).json({ error: 'Xác thực Google thất bại!' });
  }
});

// Route phục vụ giao diện trang web (Tương thích Express v5)
app.get('{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server đang chạy tại port ${PORT}`));