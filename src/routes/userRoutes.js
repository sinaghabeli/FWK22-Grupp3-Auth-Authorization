const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  getMe,
  removeUser,
  logoutUser,
} = require("../controllers/userController");

// Private Auth
const { protect } = require("../middleware/authMiddleware");

// Declaring API for controllers
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/remove", removeUser);
router.post("/logout", logoutUser);

router.get("/me", protect, getMe);

module.exports = router;
