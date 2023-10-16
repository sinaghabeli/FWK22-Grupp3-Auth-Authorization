const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  getMe,
} = require("../controllers/userController");

// Private Auth
const { protect } = require("../middleware/authMiddleware");

// Declaring API for controllers
router.post("/", registerUser);
router.post("/login", loginUser);
router.get("/me", protect, getMe);

module.exports = router;
