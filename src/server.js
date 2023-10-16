const express = require("express");
const bodyParser = require("body-parser");
const userRoutes = require("./routes/userRoutes");
const cors = require("cors");

const app = express();

app.use(cors()); // Use CORS middleware without any restrictions
app.use(bodyParser.json());
app.use("/auth", userRoutes);

module.exports = app;
