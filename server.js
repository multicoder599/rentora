// server.js
'use strict';

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// ─────────────────────────────────────────────────────────
// 1. Validate required env vars up front (fail fast)
// ─────────────────────────────────────────────────────────
const REQUIRED = ['MONGO_URI', 'JWT_SECRET'];
const missing = REQUIRED.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`[fatal] Missing required env vars: ${missing.join(', ')}`);
  process.exit(1);
}

const PORT = Number(process.env.PORT) || 5109;
const NODE_ENV = process.env.NODE_ENV || 'development';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || 'https://rentoracanada.com,https://www.rentoracanada.com,http://localhost:3000')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

// ─────────────────────────────────────────────────────────
// 2. Database Models
// ─────────────────────────────────────────────────────────
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
}, { timestamps: true }));

const Property = mongoose.model('Property', new mongoose.Schema({
  name: { type: String, required: true },
  type: { type: String, enum: ['rental', 'stay'], required: true },
  price: { type: Number, required: true },
  billing: { type: String, enum: ['month', 'night'], required: true },
  city: { type: String, required: true },
  province: { type: String, required: true },
  description: { type: String, required: true },
  bedrooms: { type: Number },
  bathrooms: { type: Number },
  sleeps: { type: Number },
  image: { type: String },
  images: [{ type: String }],
  rating: { type: Number, default: 5.0 },
  reviewsCount: { type: Number, default: 0 },
  featured: { type: Boolean, default: false },
  amenities: [{ type: String }],
}, { timestamps: true }));

const Favorite = mongoose.model('Favorite', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  propertyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Property', required: true },
}, { timestamps: true }));
Favorite.schema.index({ userId: 1, propertyId: 1 }, { unique: true });

const Message = mongoose.model('Message', new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, default: 'unread' }
}, { timestamps: true }));

// ─────────────────────────────────────────────────────────
// 3. App + Middleware
// ─────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1); 

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: CORS_ORIGINS, credentials: true }));

if (NODE_ENV !== 'test') app.use(morgan('dev'));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { message: 'Too many attempts. Please try again later.' }
});

// JWT Auth Middleware
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

const hashPassword = (pw) => crypto.createHash('sha256').update(pw).digest('hex');

// ─────────────────────────────────────────────────────────
// 4. Routes
// ─────────────────────────────────────────────────────────

// Health Check
app.get('/healthz', (_req, res) => {
  res.json({ ok: true, db: mongoose.connection.readyState === 1 });
});

// --- AUTH ROUTES ---
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) return res.status(409).json({ message: 'Email already in use.' });

    user = new User({ name, email, password: hashPassword(password) });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || user.password !== hashPassword(password)) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- PROPERTY ROUTES ---
app.get('/properties', async (req, res) => {
  try {
    const { q, province, city, type, sort, page = 1, limit = 12 } = req.query;
    let query = {};
    if (q) query.name = { $regex: q, $options: 'i' };
    if (province) query.province = province;
    if (city) query.city = city;
    if (type) query.type = type;

    let sortOptions = {};
    if (sort === 'price_asc') sortOptions.price = 1;
    if (sort === 'price_desc') sortOptions.price = -1;
    if (sort === 'rating_desc') sortOptions.rating = -1;
    if (sort === 'featured' || !sort) sortOptions.featured = -1;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [items, total] = await Promise.all([
      Property.find(query).sort(sortOptions).skip(skip).limit(parseInt(limit)),
      Property.countDocuments(query)
    ]);

    res.json({ items, total, hasMore: skip + items.length < total });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/properties/count', async (req, res) => {
  try {
    const count = await Property.countDocuments();
    res.json({ count });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/properties/:id', async (req, res) => {
  try {
    const property = await Property.findById(req.params.id);
    if (!property) return res.status(404).json({ message: 'Property not found' });
    res.json(property);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- FAVORITES ROUTES ---
app.post('/favorites', auth, async (req, res) => {
  try {
    const { propertyId } = req.body;
    const fav = new Favorite({ userId: req.user.id, propertyId });
    await fav.save();
    res.status(201).json({ message: 'Saved to favorites' });
  } catch (err) {
    if (err.code === 11000) return res.status(200).json({ message: 'Already saved' });
    res.status(500).json({ message: err.message });
  }
});

app.delete('/favorites/:propertyId', auth, async (req, res) => {
  try {
    await Favorite.findOneAndDelete({ userId: req.user.id, propertyId: req.params.propertyId });
    res.json({ message: 'Removed from favorites' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- CONTACT ROUTE ---
app.post('/contact', authLimiter, async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const newMessage = new Message({ name, email, message });
    await newMessage.save();
    res.status(201).json({ message: 'Message sent successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- ROOT ---
app.get('/', (_req, res) => {
  res.json({ name: 'Rentora API', status: 'online' });
});

// ─────────────────────────────────────────────────────────
// 5. Error Handling
// ─────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ message: `Not found: ${req.method} ${req.originalUrl}` }));
app.use((err, _req, res, _next) => {
  console.error('[error]', err);
  res.status(500).json({ message: err.message });
});

// ─────────────────────────────────────────────────────────
// 6. Connect and Start
// ─────────────────────────────────────────────────────────
async function start() {
  try {
    await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 10000 });
    console.log('[db] connected');

    app.listen(PORT, () => {
      console.log(`[api] listening on http://localhost:${PORT} (${NODE_ENV})`);
    });
  } catch (err) {
    console.error('[fatal] Failed to start:', err.message);
    process.exit(1);
  }
}

start();