const express = require("express");
const passport = require("passport");
const authenticateToken = require("./../middleWares/authenticateToken");
const authController = require("../controllers/authController");
const router = express.Router();

// Google OAuth login route
router.get(
    "/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google OAuth callback route
router.get(
    "/google/callback",
    passport.authenticate("google", {
        failureRedirect: "/login",
        session: false,
    }),
    function (req, res) {
        res.cookie("jwt", req.user.token, { httpOnly: true });
        res.redirect(process.env.CLIENT_URL || "http://localhost:3000");
    }
);

// Other OAuth login routes
// register a new user
router.post(
    "/register",
    authController.registerValidationRules,
    authController.register
);

// user login
router.post(
    "/login",
    authController.loginValidationRules,
    authController.login
);

//user password reset
router.post("/resetpassword", authController.resetPassword);

// user logout
router.post("/logout", authenticateToken, authController.logout);

module.exports = router;
