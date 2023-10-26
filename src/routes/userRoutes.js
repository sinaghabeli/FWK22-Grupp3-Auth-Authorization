const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  getMe,
  logoutUser,
  checkCookie,
} = require("../controllers/userController");

// Private Auth
const { protect } = require("../middleware/authMiddleware");

// Declaring API for controllers
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/logout", logoutUser);
router.get("/check-cookie", checkCookie);

router.get("/me", protect, getMe);

module.exports = router;
