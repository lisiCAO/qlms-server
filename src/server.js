const express = require("express");
const db = require("./models");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const {
    sendSuccessResponse,
    sendErrorResponse,
} = require("./middleWares/responseHandler");
const authController = require("./controllers/authController");
const bodyParser = require("body-parser");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 8000;

// Express App Settings
app.use(
    cors({
        origin: process.env.CLIENT_URL || "http://localhost:3000",
        methods: "GET,POST,PUT,PATCH,DELETE",
        allowedHeaders: "Content-Type,Authorization",
        credentials: true,
    })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

// Error and Format Middlewares
app.use(sendSuccessResponse);
app.use(sendErrorResponse);

// Passport Init
app.use(passport.initialize());

// GoogleStrategy
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL:
                process.env.GOOGLE_CALLBACK_URL ||
                "http://localhost:8000/auth/google/callback",
        },
        // Handle by authController.googleAuthCallback function
        authController.googleAuthCallback
    )
);

// Database sync
db.sequelize
    .sync({ force: false }) // force: true will drop the table if it already exists, default value is false, Production environment should set it to false
    .then(() => {
        // Do not do  anything before database sync
        const authRoutes = require("./routes/authRoutes");
        const propertyRoutes = require("./routes/propertyRoutes.js");
        const userRoutes = require("./routes/userRoutes.js");
        const leaseRoutes = require("./routes/leaseRoutes.js");
        // Import other routes...

        // Use routes
        app.get("/", (req, res) => {
            res.json(`Hello, this is the QLMS backend server on port ${PORT}!`);
        });
        app.use("/auth", authRoutes);
        app.use("/api/properties", propertyRoutes);
        app.use("/api/users", userRoutes);
        app.use("/api/leases", leaseRoutes);
        // Use other routes...

        // Listen to port
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    })
    .catch((error) => {
        console.error("Error syncing database: ", error);
        throw error;
    });
