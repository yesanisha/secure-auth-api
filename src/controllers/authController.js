
const bcrypt = require('bcryptjs');
const { pool } = require('../config/database');
const TokenManager = require('../utils/tokenManager');
const logger = require('../utils/logger');

class AuthController {
    // Register new user
    static async register(req, res) {
        const { email, password } = req.body;

        try {
            // Check if user exists
            const existingUser = await pool.query(
                'SELECT id FROM users WHERE email = $1',
                [email]
            );

            if (existingUser.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'User already exists'
                });
            }

            // Hash password with salt rounds of 12 (OWASP recommendation)
            const passwordHash = await bcrypt.hash(password, 12);

            // Insert user
            const result = await pool.query(
                'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
                [email, passwordHash]
            );

            const user = result.rows[0];

            // Generate tokens
            const tokens = TokenManager.generateTokenPair(user.id, user.email);

            // Store refresh token in database
            const refreshTokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
            await pool.query(
                'UPDATE users SET refresh_token = $1, refresh_token_expires = $2 WHERE id = $3',
                [tokens.refreshToken, refreshTokenExpiry, user.id]
            );

            logger.info(`New user registered: ${email}`);

            res.status(201).json({
                success: true,
                message: 'User registered successfully',
                data: {
                    user: {
                        id: user.id,
                        email: user.email,
                        createdAt: user.created_at
                    },
                    tokens
                }
            });

        } catch (error) {
            logger.error('Registration error:', error);
            res.status(500).json({
                success: false,
                message: 'Registration failed'
            });
        }
    }

    // Login user
    static async login(req, res) {
        const { email, password } = req.body;

        try {
            // Get user
            const result = await pool.query(
                'SELECT id, email, password_hash, failed_login_attempts, account_locked_until FROM users WHERE email = $1',
                [email]
            );

            if (result.rows.length === 0) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }

            const user = result.rows[0];

            // Check if account is locked
            if (user.account_locked_until && new Date() < new Date(user.account_locked_until)) {
                return res.status(403).json({
                    success: false,
                    message: 'Account temporarily locked due to multiple failed login attempts'
                });
            }

            // Verify password
            const isValidPassword = await bcrypt.compare(password, user.password_hash);

            if (!isValidPassword) {
                // Increment failed attempts
                const newFailedAttempts = user.failed_login_attempts + 1;
                let lockUntil = null;

                // Lock account after 5 failed attempts for 15 minutes
                if (newFailedAttempts >= 5) {
                    lockUntil = new Date(Date.now() + 15 * 60 * 1000);
                    logger.warn(`Account locked for user: ${email}`);
                }

                await pool.query(
                    'UPDATE users SET failed_login_attempts = $1, account_locked_until = $2 WHERE id = $3',
                    [newFailedAttempts, lockUntil, user.id]
                );

                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }

            // Successful login - reset failed attempts
            await pool.query(
                'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, last_login = NOW() WHERE id = $1',
                [user.id]
            );

            // Generate tokens
            const tokens = TokenManager.generateTokenPair(user.id, user.email);

            // Store refresh token
            const refreshTokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
            await pool.query(
                'UPDATE users SET refresh_token = $1, refresh_token_expires = $2 WHERE id = $3',
                [tokens.refreshToken, refreshTokenExpiry, user.id]
            );

            logger.info(`User logged in: ${email}`);

            res.status(200).json({
                success: true,
                message: 'Login successful',
                data: {
                    user: {
                        id: user.id,
                        email: user.email
                    },
                    tokens
                }
            });

        } catch (error) {
            logger.error('Login error:', error);
            res.status(500).json({
                success: false,
                message: 'Login failed'
            });
        }
    }

    // Refresh access token
    static async refreshToken(req, res) {
        const { refreshToken } = req.body;

        try {
            // Verify refresh token
            const decoded = TokenManager.verifyRefreshToken(refreshToken);

            // Check if refresh token exists in database and is not expired
            const result = await pool.query(
                'SELECT id, email, refresh_token, refresh_token_expires FROM users WHERE id = $1',
                [decoded.userId]
            );

            if (result.rows.length === 0) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid refresh token'
                });
            }

            const user = result.rows[0];

            // Verify token matches and is not expired
            if (
                user.refresh_token !== refreshToken ||
                new Date() > new Date(user.refresh_token_expires)
            ) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid or expired refresh token'
                });
            }

            // Generate new token pair (refresh token rotation)
            const newTokens = TokenManager.generateTokenPair(user.id, user.email);

            // Update refresh token in database
            const newRefreshTokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
            await pool.query(
                'UPDATE users SET refresh_token = $1, refresh_token_expires = $2 WHERE id = $3',
                [newTokens.refreshToken, newRefreshTokenExpiry, user.id]
            );

            logger.info(`Token refreshed for user: ${user.email}`);

            res.status(200).json({
                success: true,
                data: { tokens: newTokens }
            });

        } catch (error) {
            logger.error('Token refresh error:', error);
            res.status(401).json({
                success: false,
                message: 'Token refresh failed'
            });
        }
    }

    // Logout user
    static async logout(req, res) {
        try {
            const userId = req.user.userId;

            // Invalidate refresh token
            await pool.query(
                'UPDATE users SET refresh_token = NULL, refresh_token_expires = NULL WHERE id = $1',
                [userId]
            );

            logger.info(`User logged out: ${req.user.email}`);

            res.status(200).json({
                success: true,
                message: 'Logout successful'
            });

        } catch (error) {
            logger.error('Logout error:', error);
            res.status(500).json({
                success: false,
                message: 'Logout failed'
            });
        }
    }
}

module.exports = AuthController;