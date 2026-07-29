const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Bật CORS cho phép file HTML ở máy bạn gọi tới API
app.use(cors());
app.use(express.json());

// Kết nối MongoDB
const MONGO_URI = process.env.MONGO_URI;
mongoose.connect(MONGO_URI)
    .then(() => console.log('Da ket noi thanh cong voi MongoDB Cloud!'))
    .catch((err) => console.error('Loi ket noi MongoDB:', err));

// Schema cho Người dùng (User)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// API Đăng ký
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu!' });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Tên đăng nhập này đã tồn tại!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'Đăng ký tài khoản thành công!' });
    } catch (err) {
        res.status(500).json({ message: 'Lỗi server khi đăng ký!', error: err.message });
    }
});

// API Đăng nhập
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu!' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Tên đăng nhập hoặc mật khẩu không chính xác!' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Tên đăng nhập hoặc mật khẩu không chính xác!' });
        }

        const secretKey = process.env.SECRET_KEY || 'secret123';
        const token = jwt.sign({ userId: user._id, username: user.username }, secretKey, { expiresIn: '24h' });

        res.json({
            message: 'Đăng nhập thành công!',
            token,
            user: { id: user._id, username: user.username, balance: user.balance }
        });
    } catch (err) {
        res.status(500).json({ message: 'Lỗi server khi đăng nhập!', error: err.message });
    }
});

// Trang chủ kiểm tra server
app.get('/', (req, res) => {
    res.send('Server Web Kiem Tien dang hoat dong 24/7!');
});

// Khởi chạy Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server đang chạy tại http://localhost:${PORT}`);
});