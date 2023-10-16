// const express = require("express");
// const jwt = require("jsonwebtoken");

// const router = express.Router();

// router.post("/login", (req, res) => {
//   const { email, password } = req.body;

//   if (isValidUser(email, password)) {
//     const token = jwt.sign({ email, role: getUserRole(email) }, "secretKey", {
//       expiresIn: "1h",
//     });
//     res.json({ token });
//   } else {
//     res.status(401).json({ error: "Invalid login" });
//   }
// });

// const isValidUser = (email, password) => {
//   return email === "user@example.com" && password === "password";
// };

// const getUserRole = (email) => {
//   return email === "admin@example.com" ? "admin" : "user";
// };

// module.exports = router;

const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  getMe,
} = require("../controllers/useController");
const { protect } = require("../middleware/authMiddleware"); // Making sure the auth is private

// Declaring API for controllers
router.post("/", registerUser);
router.post("/login", loginUser);
router.get("/me", protect, getMe);

module.exports = router;
