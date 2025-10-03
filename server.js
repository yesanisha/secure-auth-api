
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
require('dotenv').config();

const authRoutes = require('./src/routes/auth');
const { errorHandler } = require('./src/middleware/errorHandler');
const logger = require('./src/utils/logger');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// SECURITY MIDDLEWARE (OWASP Best Practices)
// ============================================

// 1. Helmet - Sets security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: { action: 'deny' },
    xssFilter: true,
    noSniff: true,
    referrerPolicy: { policy: 'no-referrer' }
}));

// 2. CORS - Configure allowed origins
const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// 3. Rate Limiting - Prevent brute force attacks
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// Stricter rate limit for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // 5 login attempts per 15 minutes
    skipSuccessfulRequests: true,
    message: 'Too many login attempts, please try again later.'
});

// 4. Body parser with size limits (prevent DoS)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 5. Custom Security Sanitization Middleware
app.use((req, res, next) => {
    // NoSQL Injection Prevention - Remove $ and . from keys
    if (req.body) req.body = sanitizeObject(req.body);
    if (req.query) req.query = sanitizeObject(req.query);
    if (req.params) req.params = sanitizeObject(req.params);

    // XSS Prevention - Escape HTML in string values
    if (req.body) req.body = escapeHtml(req.body);
    if (req.query) req.query = escapeHtml(req.query);
    if (req.params) req.params = escapeHtml(req.params);

    next();
});

// Helper: Remove $ and . from object keys (NoSQL injection prevention)
function sanitizeObject(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(item => sanitizeObject(item));

    const sanitized = {};
    for (let key in obj) {
        const sanitizedKey = key.replace(/^\$/, '').replace(/\./g, '');
        sanitized[sanitizedKey] = sanitizeObject(obj[key]);
    }
    return sanitized;
}

// Helper: Escape HTML characters (XSS prevention)
function escapeHtml(obj) {
    if (typeof obj === 'string') {
        return obj
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }
    if (obj === null || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(item => escapeHtml(item));

    const escaped = {};
    for (let key in obj) {
        escaped[key] = escapeHtml(obj[key]);
    }
    return escaped;
}

// 6. Prevent HTTP Parameter Pollution
app.use(hpp());

// ============================================
// ROUTES
// ============================================
app.use('/api/auth', authLimiter, authRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

// Global error handler
app.use(errorHandler);

// ============================================
// START SERVER
// ============================================
const { initDB } = require('./src/config/database');

// Initialize database then start server
initDB()
    .then(() => {
        app.listen(PORT, () => {
            logger.info(`🔒 Secure Auth API running on port ${PORT}`);
            logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
        });
    })
    .catch((error) => {
        logger.error('Failed to initialize database:', error);
        process.exit(1);
    });

module.exports = app;

