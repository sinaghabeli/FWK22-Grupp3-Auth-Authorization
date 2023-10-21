const path = require("path");
const express = require("express");
const userRoutes = require("./routes/userRoutes");
const { errorHandler } = require("./middleware/errorMiddleware"); // Simplifies the errors
const cors = require("cors");
const connectDB = require("./config/db");
const cookieParser = require("cookie-parser");

const app = express();

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
