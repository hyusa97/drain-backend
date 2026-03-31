require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5000;

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.log('MongoDB error:', err));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['mapper', 'admin'], default: 'mapper' },
  created_at: { type: Date, default: Date.now },
});

const drainSchema = new mongoose.Schema({
  name: { type: String, required: true },
  reported_condition: { type: String, enum: ['clean', 'blocked', 'medium'] },
  verified_condition: { type: String, enum: ['clean', 'blocked', 'medium'], default: null },
  status: { type: String, enum: ['draft', 'reviewed', 'locked'], default: 'draft' },
  image: String,
  path: Array,
  markers: Array,
  mapper_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  mapper_name: String,
  is_archived: { type: Boolean, default: false },
  parent_id: { type: mongoose.Schema.Types.ObjectId, default: null },
  locked_by: { type: mongoose.Schema.Types.ObjectId, default: null },
  locked_at: { type: Date, default: null },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Drain = mongoose.model('Drain', drainSchema);

app.use(cors());
app.use(express.json({ limit: '10mb' }));

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role,
    });

    await user.save();
    return res.json({ success: true, message: 'User created' });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({ token });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post('/drain', async (req, res) => {
  try {
    const drain = new Drain({
      ...req.body,
      mapper_id: null,
      mapper_name: null,
    });

    await drain.save();
    return res.json({ success: true, id: drain._id });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get('/drains', async (req, res) => {
  try {
    const drains = await Drain.find({ is_archived: false }).sort({ created_at: -1 });
    return res.json(drains);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log('Server running on port process.env.PORT || process.env.PORT || 5000');
});
