
const TokenManager = require('../utils/tokenManager');
const logger = require('../utils/logger');

const authenticate = (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify token
    const decoded = TokenManager.verifyAccessToken(token);
    
    // Attach user info to request
    req.user = decoded;
    next();

  } catch (error) {
    logger.warn('Authentication failed:', error.message);
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

module.exports = { authenticate };

