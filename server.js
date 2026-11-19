// server.js
'use strict';

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

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
const CORS_ORIGINS = (process.env.CORS_ORIGINS || 'http://localhost:5173')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

// ─────────────────────────────────────────────────────────
// 2. App + middleware
// ─────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1); // needed for correct IPs behind Render/Fly/Heroku

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin(origin, cb) {
      // Allow no-origin (curl, same-origin, server-to-server)
      if (!origin) return cb(null, true);
      if (CORS_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error(`Origin ${origin} not allowed by CORS`));
    },
    credentials: true
  })
);

if (NODE_ENV !== 'test') app.use(morgan('dev'));

// Basic rate limit on auth + contact endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many attempts. Please try again later.' }
});

// ─────────────────────────────────────────────────────────
// 3. Health check (useful for Render / Fly / Uptime)
// ─────────────────────────────────────────────────────────
app.get('/healthz', (_req, res) => {
  res.json({
    ok: true,
    env: NODE_ENV,
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    uptime: process.uptime()
  });
});

// ─────────────────────────────────────────────────────────
// 4. Routes — mount as you build them
// ─────────────────────────────────────────────────────────
// app.use('/auth',         require('./routes/auth'));
// app.use('/properties',   require('./routes/properties'));
// app.use('/viewings',     require('./routes/viewings'));
// app.use('/bookings',     require('./routes/bookings'));
// app.use('/favorites',    require('./routes/favorites'));
// app.use('/locations',    require('./routes/locations'));
// app.use('/contact',      authLimiter, require('./routes/contact'));
// app.use('/faq',          require('./routes/faq'));
// app.use('/site',         require('./routes/site'));

// Simple root so hitting the base URL doesn't 404
app.get('/', (_req, res) => {
  res.json({ name: 'Rentora API', version: '1.0.0', docs: '/healthz' });
});

// ─────────────────────────────────────────────────────────
// 5. 404 + error handler
// ─────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ message: `Not found: ${req.method} ${req.originalUrl}` });
});

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[error]', err);
  const status = err.status || 500;
  res.status(status).json({
    message: err.message || 'Internal server error',
    ...(NODE_ENV === 'development' ? { stack: err.stack } : {})
  });
});

// ─────────────────────────────────────────────────────────
// 6. Connect to Mongo, then start listening
// ─────────────────────────────────────────────────────────
async function start() {
  try {
    mongoose.set('strictQuery', true);
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10_000
    });
    console.log('[db] connected');

    const server = app.listen(PORT, () => {
      console.log(`[api] listening on http://localhost:${PORT} (${NODE_ENV})`);
    });

    // Graceful shutdown
    const shutdown = async (signal) => {
      console.log(`[shutdown] ${signal} received`);
      server.close(async () => {
        await mongoose.connection.close();
        process.exit(0);
      });
      setTimeout(() => process.exit(1), 10_000).unref();
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (err) {
    console.error('[fatal] Failed to start:', err.message);
    process.exit(1);
  }
}

start();