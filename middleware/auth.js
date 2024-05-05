const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');

exports.validateRegister = [
  check('userType').isIn(['driver', 'passenger']).withMessage('Invalid user type'),
  check('firstName').notEmpty().withMessage('First name is required'),
  check('lastName').notEmpty().withMessage('Last name is required'),
  check('email').isEmail().withMessage('Invalid email address'),
  check('phoneNumber').notEmpty().withMessage('Phone number is required'),
  check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

exports.validateLogin = [
  check('email').isEmail().withMessage('Invalid email address'),
  check('password').notEmpty().withMessage('Password is required'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

exports.generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      userType: user.userType
    },
    process.env.SECRET_KEY,
    { expiresIn: '1h' }
  );
};

exports.verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(403).json({ message: 'A token is required for authentication' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid Token' });
  }
};