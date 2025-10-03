
// ============================================
// 2. src/config/database.js - Database Config
// ============================================

const { Pool } = require('pg');
const logger = require('../utils/logger');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

pool.on('error', (err) => {
    logger.error('Unexpected database error:', err);
    process.exit(-1);
});

// Initialize database tables
const initDB = async () => {
    const client = await pool.connect();
    try {
        await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        refresh_token VARCHAR(500),
        refresh_token_expires TIMESTAMP,
        failed_login_attempts INTEGER DEFAULT 0,
        account_locked_until TIMESTAMP,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE INDEX IF NOT EXISTS idx_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_refresh_token ON users(refresh_token);
    `);
        logger.info('✅ Database initialized successfully');
    } catch (error) {
        logger.error('Database initialization failed:', error);
        throw error;
    } finally {
        client.release();
    }
};

module.exports = { pool, initDB };

