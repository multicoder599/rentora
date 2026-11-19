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
const { Resend } = require('resend'); // <-- Import Resend

// Initialize Resend (if API key exists)
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

const REQUIRED = ['MONGO_URI', 'JWT_SECRET'];
if (REQUIRED.some(k => !process.env[k])) {
  console.error(`[fatal] Missing required env vars`);
  process.exit(1);
}

const PORT = Number(process.env.PORT) || 5109;
const NODE_ENV = process.env.NODE_ENV || 'development';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || 'https://rentoracanada.com,https://www.rentoracanada.com,http://localhost:3000')
  .split(',').map(s => s.trim()).filter(Boolean);

const app = express();
app.set('trust proxy', 1); 
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: CORS_ORIGINS, credentials: true }));
if (NODE_ENV !== 'test') app.use(morgan('dev'));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

// ─────────────────────────────────────────────────────────
// 1. MODELS
// ─────────────────────────────────────────────────────────
const User = mongoose.model('User', new mongoose.Schema({
  name: String, 
  email: { type: String, unique: true }, 
  password: String,
  isVerified: { type: Boolean, default: false }, // <-- Added
  verificationToken: String // <-- Added
}, { timestamps: true }));

const Property = mongoose.model('Property', new mongoose.Schema({
  name: String, type: String, price: Number, billing: String, city: String, province: String,
  description: String, bedrooms: Number, bathrooms: Number, sleeps: Number, image: String,
  images: [String], rating: Number, reviewsCount: Number, featured: Boolean, amenities: [String],
  cleaningFee: Number, taxRate: Number
}, { timestamps: true }));

const Favorite = mongoose.model('Favorite', new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId, propertyId: mongoose.Schema.Types.ObjectId
}, { timestamps: true }));
Favorite.schema.index({ userId: 1, propertyId: 1 }, { unique: true });

const Message = mongoose.model('Message', new mongoose.Schema({
  name: String, email: String, message: String
}, { timestamps: true }));

const Viewing = mongoose.model('Viewing', new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId, propertyId: mongoose.Schema.Types.ObjectId,
  moveInDate: String, leaseTermMonths: Number
}, { timestamps: true }));

const Booking = mongoose.model('Booking', new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId, propertyId: mongoose.Schema.Types.ObjectId,
  checkIn: String, checkOut: String, guests: Number
}, { timestamps: true }));

const Faq = mongoose.model('Faq', new mongoose.Schema({
  question: String, answer: String, order: Number
}, { timestamps: true }));


// ─────────────────────────────────────────────────────────
// 2. MIDDLEWARE
// ─────────────────────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); } 
  catch (err) { res.status(401).json({ message: 'Invalid token' }); }
};
const hashPassword = (pw) => crypto.createHash('sha256').update(pw).digest('hex');


// ─────────────────────────────────────────────────────────
// 3. ROUTES
// ─────────────────────────────────────────────────────────

// --- AUTH ---
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (await User.findOne({ email })) {
      return res.status(409).json({ message: 'Email already in use.' });
    }

    // Generate a random 32-character hex token
    const verificationToken = crypto.randomBytes(16).toString('hex');

    const user = await User.create({ 
      name, 
      email, 
      password: hashPassword(password),
      verificationToken,
      isVerified: false
    });

    // Send Verification Email via Resend
    if (resend) {
      const verifyUrl = `https://api.rentoracanada.com/auth/verify/${verificationToken}`;
      try {
        await resend.emails.send({
          from: 'Rentora <onboarding@resend.dev>', // Replace with your verified domain later (e.g. hello@rentoracanada.com)
          to: email,
          subject: 'Verify your Rentora account',
          html: `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; color: #1a1a1a;">
              <h2 style="font-family: Georgia, serif; color: #2a5e3a;">Welcome to Rentora, ${name}!</h2>
              <p>Please verify your email address to complete your registration.</p>
              <a href="${verifyUrl}" style="display: inline-block; background-color: #e07a5f; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 16px 0;">Verify Email Address</a>
              <p>Or copy and paste this link into your browser:</p>
              <p><a href="${verifyUrl}" style="color: #2a5e3a;">${verifyUrl}</a></p>
              <p style="color: #6b6560; font-size: 12px; margin-top: 32px;">If you didn't create an account, you can safely ignore this email.</p>
            </div>
          `
        });
      } catch (emailErr) {
        console.error('[Resend Error]', emailErr);
        // We don't fail the registration if the email fails, but we log it.
      }
    }

    // Note: We no longer return the JWT token here immediately if we want them to verify first.
    // However, to keep your current frontend working, we'll still return the token,
    // but the user's `isVerified` will be false in the DB.
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user._id, name, email, isVerified: false } });

  } catch (err) { 
    res.status(500).json({ message: err.message }); 
  }
});

// --- VERIFY EMAIL ROUTE ---
app.get('/auth/verify/:token', async (req, res) => {
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    
    if (!user) {
      return res.status(400).send('<h1>Invalid or expired verification link.</h1>');
    }

    user.isVerified = true;
    user.verificationToken = undefined; // Clear the token
    await user.save();

    // Redirect the user back to the frontend login page with a success flag
    res.redirect('https://rentoracanada.com/login?verified=true');
  } catch (err) {
    res.status(500).send('<h1>Something went wrong during verification.</h1>');
  }
});

// --- LOGIN ---
app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || user.password !== hashPassword(password)) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Optional: Block login if not verified
    // if (!user.isVerified) {
    //   return res.status(403).json({ message: 'Please verify your email before logging in.' });
    // }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, isVerified: user.isVerified } });
  } catch (err) { 
    res.status(500).json({ message: err.message }); 
  }
});

// --- PROPERTIES ---
app.get('/properties', async (req, res) => {
  try {
    const { q, province, city, type, sort, page = 1, limit = 12, featured } = req.query;
    let query = {};
    if (q) query.name = { $regex: q, $options: 'i' };
    if (province) query.province = province;
    if (city) query.city = city;
    if (type) query.type = type;
    if (featured) query.featured = true;

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
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.get('/properties/stats/cities', async (req, res) => {
  try {
    const stats = await Property.aggregate([
      { $group: { _id: "$city", count: { $sum: 1 } } },
      { $project: { city: "$_id", count: 1, _id: 0 } }
    ]);
    res.json(stats);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.get('/properties/count', async (req, res) => {
  try { res.json({ count: await Property.countDocuments() }); } 
  catch (err) { res.status(500).json({ message: err.message }); }
});

app.get('/properties/:id', async (req, res) => {
  try {
    const property = await Property.findById(req.params.id);
    if (!property) return res.status(404).json({ message: 'Property not found' });
    res.json(property);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// --- LOCATIONS ---
app.get('/locations/cities', async (req, res) => {
  try {
    const { province } = req.query;
    if (!province) return res.json([]);
    const cities = await Property.distinct('city', { province });
    res.json(cities.sort()); 
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// --- FAVORITES ---
app.post('/favorites', auth, async (req, res) => {
  try {
    await Favorite.create({ userId: req.user.id, propertyId: req.body.propertyId });
    res.status(201).json({ message: 'Saved' });
  } catch (err) { res.status(200).json({ message: 'Already saved' }); }
});

app.delete('/favorites/:propertyId', auth, async (req, res) => {
  try {
    await Favorite.findOneAndDelete({ userId: req.user.id, propertyId: req.params.propertyId });
    res.json({ message: 'Removed' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// --- CONTACT & FAQ & SITE STATS ---
app.post('/contact', authLimiter, async (req, res) => {
  try {
    await Message.create(req.body);
    res.status(201).json({ message: 'Sent' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.get('/faq', async (req, res) => {
  try {
    const faqs = await Faq.find().sort({ order: 1 });
    res.json(faqs);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.get('/site/stats', async (req, res) => {
  try {
    const [properties, cities, provinces] = await Promise.all([
      Property.countDocuments(),
      Property.distinct('city').then(arr => arr.length),
      Property.distinct('province').then(arr => arr.length)
    ]);
    res.json({ properties, cities, provinces });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// --- BOOKINGS & VIEWINGS ---
app.post('/viewings', auth, async (req, res) => {
  try {
    const { propertyId, moveInDate, leaseTermMonths } = req.body;
    await Viewing.create({ userId: req.user.id, propertyId, moveInDate, leaseTermMonths });
    res.status(201).json({ message: 'Viewing requested successfully' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post('/bookings', auth, async (req, res) => {
  try {
    const { propertyId, checkIn, checkOut, guests } = req.body;
    await Booking.create({ userId: req.user.id, propertyId, checkIn, checkOut, guests });
    res.status(201).json({ message: 'Booking confirmed successfully' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ─────────────────────────────────────────────────────────
// 4. START
// ─────────────────────────────────────────────────────────
app.get('/healthz', (req, res) => res.json({ ok: true }));
app.use((req, res) => res.status(404).json({ message: 'Not found' }));

async function start() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('[db] connected');
    app.listen(PORT, () => console.log(`[api] listening on ${PORT}`));
  } catch (err) { 
    console.error('[fatal] Failed to start:', err.message);
    process.exit(1); 
  }
}
start();