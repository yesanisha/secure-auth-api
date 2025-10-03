const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const logger = require('./logger');

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');

class TokenManager {
    // Generate Access Token (short-lived: 15 minutes)
    static generateAccessToken(userId, email) {
        return jwt.sign(
            { userId, email, type: 'access' },
            JWT_SECRET,
            { expiresIn: '15m', issuer: 'secure-auth-api' }
        );
    }

    // Generate Refresh Token (long-lived: 7 days)
    static generateRefreshToken(userId) {
        return jwt.sign(
            { userId, type: 'refresh' },
            JWT_REFRESH_SECRET,
            { expiresIn: '7d', issuer: 'secure-auth-api' }
        );
    }

    // Verify Access Token
    static verifyAccessToken(token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.type !== 'access') {
                throw new Error('Invalid token type');
            }
            return decoded;
        } catch (error) {
            logger.warn('Access token verification failed:', error.message);
            throw new Error('Invalid or expired access token');
        }
    }

    // Verify Refresh Token
    static verifyRefreshToken(token) {
        try {
            const decoded = jwt.verify(token, JWT_REFRESH_SECRET);
            if (decoded.type !== 'refresh') {
                throw new Error('Invalid token type');
            }
            return decoded;
        } catch (error) {
            logger.warn('Refresh token verification failed:', error.message);
            throw new Error('Invalid or expired refresh token');
        }
    }

    // Generate token pair
    static generateTokenPair(userId, email) {
        return {
            accessToken: this.generateAccessToken(userId, email),
            refreshToken: this.generateRefreshToken(userId),
            expiresIn: 900 // 15 minutes in seconds
        };
    }
}

module.exports = TokenManager;

