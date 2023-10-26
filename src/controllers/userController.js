const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs"); // to making a secure password for save on MongoDB
const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");

// @desc    Register new user
// @route   POST /auth/register
// @access  Public
const registerUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body; // Getting the variables from frontend

  // Check to make sure all fields have been passed
  if (!email || !password) {
    res.status(400);
    throw new Error("Please add all fields");
  }

  // Check if user exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("User already exists");
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create user
  const user = await User.create({
    email,
    password: hashedPassword,
    role: "user",
  });

  if (user) {
    res.cookie("authToken", generateToken(user._id), { httpOnly: true });

    res.status(201).json({
      _id: user.id,
      email: user.email,
      token: generateToken(user._id), // creating a token for the user
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

// @desc    Authenticate a user for login
// @route   POST /auth/login
// @access  Public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Check for user email
  const user = await User.findOne({ email });

  // decrypt the password and check for the right password
  if (user && (await bcrypt.compare(password, user.password))) {
    res.cookie("authToken", generateToken(user._id), { httpOnly: true });

    res.json({
      _id: user.id,
      email: user.email,
      role: user.role,
      token: generateToken(user._id),
    });
  } else {
    res.status(400);
    throw new Error("Invalid credentials");
  }
});

// @desc    Logout user (clearing httpOnly Cookie)
// @route   POST /auth/logout
// @access  Public
const logoutUser = asyncHandler(async (req, res) => {
  // Clear the HTTP-only cookie on the server
  res.clearCookie("authToken", { httpOnly: true });

  res.status(200).send("Logout successful");
});

// @desc    Check if cookie exist
// @route   GET /auth/check-cookie
// @access  Public
const checkCookie = asyncHandler(async (req, res) => {
  // Check if the HTTP-only cookie exists (e.g., req.cookies.authToken)
  // If it exists, send a success response; otherwise, send an error response
  if (req.cookies.authToken) {
    res.status(200).json("exist");
  } else {
    res.status(401).json("not exist");
  }
});

// @desc    Get user data
// @route   GET /api/users/me
// @access  Private
const getMe = asyncHandler(async (req, res) => {
  res.status(200).json(req.user);
});

// Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
};

module.exports = {
  registerUser,
  loginUser,
  getMe,
  removeUser,
  logoutUser,
  checkCookie,
};
