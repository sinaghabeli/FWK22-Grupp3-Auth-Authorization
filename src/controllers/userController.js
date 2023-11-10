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
    const tokenPayload = {
      role: user.role,
      token: generateToken(user._id, user.role),
    };

    res.cookie("authToken", JSON.stringify(tokenPayload), {
      httpOnly: true,
    });

    // Creating cookie with token and role
    // res.cookie("authToken", generateToken(user._id, user.role), {
    //   httpOnly: true,
    // });

    res.status(201).json({
      _id: user.id,
      email: user.email,
      role: user.role,
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
    const tokenPayload = {
      role: user.role,
      token: generateToken(user._id, user.role),
    };

    res.cookie("authToken", JSON.stringify(tokenPayload), {
      httpOnly: true,
    });

    // Creating cookie with token and role
    // res.cookie("authToken", generateToken(user._id, user.role), {
    //   httpOnly: true,
    // });

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
// @route   GET /auth/logout
const logoutUser = asyncHandler(async (req, res) => {
  try {
    res.clearCookie("authToken", { httpOnly: true });
    res.status(200).send("Logout successful");
  } catch (error) {
    console.error("Error clearing cookie:", error);
    res.status(500).send("Internal Server Error");
  }
});

// @desc    Check if cookie exist
// @route   GET /auth/check-cookie
const checkCookie = asyncHandler(async (req, res) => {
  const checkCookieValue = req.cookies.authToken;

  const { role, token } = JSON.parse(checkCookieValue);

  if (req.cookies.authToken) {
    res.status(200).json({ role, token });
  } else {
    res.status(401).json("not exist");
  }
});

// Generate JWT (Token function)
const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
};

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  checkCookie,
};
