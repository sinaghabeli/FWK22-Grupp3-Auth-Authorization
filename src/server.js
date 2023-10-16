const express = require("express");
const bodyParser = require("body-parser");
const userRoutes = require("./routes/userRoutes");
const cors = require("cors");
const connectDB = require("./config/db");

const app = express();

// Connecting to Mongodb
connectDB();

app.use(cors()); // Use CORS middleware without any restrictions
app.use(bodyParser.json());

// Declaring route
app.use("/auth", userRoutes);

module.exports = app;
