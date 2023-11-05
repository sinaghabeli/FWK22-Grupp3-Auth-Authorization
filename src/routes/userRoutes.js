const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  logoutUser,
  checkCookie,
} = require("../controllers/userController");

// Declaring API for controllers
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/logout", logoutUser);
router.get("/check-cookie", checkCookie);

module.exports = router;
