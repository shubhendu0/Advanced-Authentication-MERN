const User = require("../models/userModel");
const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");

const protect = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({"message" : "Not authorized, please login."})
    }
    // Verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET_KEY);
    // Get user id from token
    const user = await User.findById(verified.id).select("-password");
    if (!user) {
      res.status(404).json({"message" : "User not found"});
    }
    if (user.role === "suspended") {
      res.status(400).json({"message" : "User suspended, please contact support"});
    }
    req.user = user;
    next();
  } 
  catch (error) {
    res.status(401).json({"message" : "Not authorized, please login"});
  }
})

const verifiedOnly = asyncHandler(async (req, res, next) => {
    if (req.user && req.user.isVerified) {
      next();
    } 
    else {
      res.status(401).json({"message" : "Not authorized, account not verified."})
    }
})

const authorOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role === "author" || req.user.role === "admin") {
    next();
  } 
  else {
    res.status(401).json({message : "Not authorized as an author"});
  }
})

const adminOnly = asyncHandler(async (req, res, next) => {
    if (req.user && req.user.role === "admin") {
        next();
    } 
    else {
        res.status(401).json({"message" : "Not authorized as an admin."})
    }
})

module.exports = {
    protect,
    verifiedOnly,
    authorOnly,
    adminOnly
}