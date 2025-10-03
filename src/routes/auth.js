
const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/authController');
const { validateRegister, validateLogin, validateRefreshToken } = require('../middleware/validator');
const { authenticate } = require('../middleware/auth');

// Public routes
router.post('/register', validateRegister, AuthController.register);
router.post('/login', validateLogin, AuthController.login);
router.post('/refresh', validateRefreshToken, AuthController.refreshToken);

// Protected routes
router.post('/logout', authenticate, AuthController.logout);

// Test protected endpoint
router.get('/me', authenticate, async (req, res) => {
    res.json({
        success: true,
        data: {
            user: {
                id: req.user.userId,
                email: req.user.email
            }
        }
    });
});

module.exports = router;
