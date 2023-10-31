const path = require("path");
const express = require("express");
const userRoutes = require("./routes/userRoutes");
const { errorHandler } = require("./middleware/errorMiddleware"); // Simplifies the errors
const cors = require("cors");
const connectDB = require("./config/db");
const cookieParser = require("cookie-parser");
const helmet = require("helmet"); // Helmet

const app = express();

// Adding helmet for security
// app.use(helmet());
// Use helmet middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "trusted-scripts.com"],
        styleSrc: ["style.com"],
      },
    },
    noCache: true, // Disable client-side caching
  })
);

// Enable/disable specific headers
app.use(helmet.frameguard({ action: "deny" }));

// Connecting to Mongodb
connectDB();

app.use(cors()); // Use CORS middleware without any restrictions
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Declaring route
app.use("/auth", userRoutes);

app.use(errorHandler);

module.exports = app;
