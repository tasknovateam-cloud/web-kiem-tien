const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

// Kết nối MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('>>> Ket noi MongoDB thanh cong! <<<'))
    .catch(err => console.error('Loi ket noi MongoDB:', err));

app.get('/', (req, res) => {
    res.send('Server Web Kiem Tien dang hoat dong tot va da ket noi Database!');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server dang chay tai http://localhost:${PORT}`);
});