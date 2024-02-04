const jwt = require("jsonwebtoken");
const { oauth_token, user, lease } = require("../models/index");
const OAuthToken = oauth_token;
const bcrypt = require("bcryptjs");
const { sequelize, Sequelize } = require("../models");
const { body, validationResult } = require("express-validator");

const User = user;

//add validation rules for user registration
exports.registerValidationRules = [
    body("username").trim().notEmpty().withMessage("Username is required"),
    body("email").isEmail().withMessage("Invalid email address"),
    body("password")
        .isLength({ min: 8 }) // at least 8 characters
        .withMessage("Password must be at least 8 characters long")
        .matches(/[A-Z]/)
        .withMessage("Password must contain at least one uppercase letter")
        .matches(/[a-z]/)
        .withMessage("Password must contain at least one lowercase letter")
        .matches(/[0-9]/)
        .withMessage("Password must contain at least one number")
        .matches(/[\W]/)
        .withMessage("Password must contain at least one special character"),
    body("role")
        .isIn(["tenant", "landlord"])
        .withMessage("Role must be either tenant or landlord"),
];

//add validation rules for user login
exports.loginValidationRules = [
    body("email").isEmail().withMessage("Invalid email address"),
    body("password").notEmpty().withMessage("Password is required"),
];

const findOrCreateUser = (userData, callback) => {
    User.findOrCreate({
        where: {
            oauth_provider_user_id: userData.oauth_provider_user_id,
            oauth_provider: userData.oauth_provider,
        },
        defaults: userData,
    })
        .then(([user, created]) => {
            callback(null, user);
        })
        .catch((err) => {
            callback(err, null);
        });
};

exports.googleAuthCallback = (accessToken, refreshToken, profile, done) => {
    const userData = {
        oauth_provider: profile.provider,
        oauth_provider_user_id: profile.id,
        email: profile.emails[0].value,
        first_name: profile.name.givenName,
        last_name: profile.name.familyName,
        username: profile.emails[0].value,
        role: "tenant",
    };
    findOrCreateUser(userData, (err, user) => {
        if (err) {
            return done(err);
        }
        saveOrUpdateOAuthToken(
            user.id,
            accessToken,
            refreshToken,
            profile.provider,
            profile.id
        );
        const token = jwt.sign(
            { userId: user.id, role: user.role },
            process.env.JWT_SECRET,
            {
                expiresIn: "1h",
            }
        );
        done(null, { user, token });
    });
};

const saveOrUpdateOAuthToken = (
    userId,
    accessToken,
    refreshToken,
    provider,
    oauth_provider_user_id
) => {
    OAuthToken.upsert({
        user_id: userId,
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_in: new Date(Date.now() + 3600000),
        provider: provider,
        oauth_provider_user_id: oauth_provider_user_id,
    })
        .then(() => console.log("OAuth Token saved or updated"))
        .catch((err) => console.error("Error saving OAuth Token:", err));
};

exports.googleSendToken = (req, res) => {
    res.cookie("jwt", req.user.token, { httpOnly: true });
    res.redirect("http://localhost:3000");
};

// Other Methods
// register a new user
exports.register = async (req, res) => {
    try {
        //check if user information is valid
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.sendError(
                "Registeration failed: " +
                    errors
                        .array()
                        .map((err) => err.msg)
                        .join(", "),
                422
            );
        }

        const { username, email, password, role } = req.body;

        // check if username or email already exists
        const existingUser = await User.findOne({
            where: {
                [Sequelize.Op.or]: [{ username }, { email }],
            },
        });

        if (existingUser) {
            return res.sendError("Username or email already exists", 409); // 409 Conflict
        }

        // hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // create a new user
        const newUser = await User.create({
            username,
            email,
            password_hash: hashedPassword,
            role,
        });

        // generate access and refresh tokens
        const accessToken = jwt.sign(
            { userId: newUser.id, role: newUser.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );
        const refreshToken = jwt.sign(
            { userId: newUser.id },
            process.env.JWT_SECRET,
            { expiresIn: "24h" }
        );

        // use saveOrUpdateOAuthToken function to save or update OAuth token info in oauth_token table
        saveOrUpdateOAuthToken(
            newUser.id,
            accessToken,
            refreshToken,
            "QLMS",
            newUser.id
        );

        // set HTTP-only cookie
        res.cookie("jwt", accessToken, { httpOnly: true, maxAge: 3600000 }); // 1 hour

        // send response
        res.sendSuccess(
            {
                userId: newUser.id,
                username: newUser.username,
                role: newUser.role,
            },
            "User registered successfully"
        );
    } catch (error) {
        res.sendError("Registration failed: " + error.message, 500);
    }
};

// user login
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        //check if login information is valid
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.sendError(
                "Login failed: " +
                    errors
                        .array()
                        .map((err) => err.msg)
                        .join(", "),
                422
            );
        }

        // check if username or email already exists
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.sendError("User not found", 404);
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.sendError("Password is incorrect", 401);
        }

        // generate access and refresh tokens
        const token = jwt.sign(
            { userId: user.id, role: user.role },
            process.env.JWT_SECRET,
            {
                expiresIn: "1h",
            }
        );

        // check if user has a lease
        const leaseCheckSql = `SELECT EXISTS(SELECT 1 FROM lease WHERE tenant_user_id = ${user.id}) AS hasLease;`;
        const leaseCheckResult = await sequelize.query(leaseCheckSql, {
            type: Sequelize.QueryTypes.SELECT,
        });
        const hasLease = leaseCheckResult[0].hasLease;

        // set HTTP-only cookie
        res.cookie("jwt", token, { httpOnly: true, maxAge: 3600000 }); // 1 hour

        // send response
        res.sendSuccess(
            {
                userId: user.id,
                username: user.username,
                role: user.role,
                profilePictureUrl: user.profile_picture_url,
                hasLease: hasLease,
            },
            "User Logged in successfully"
        );
    } catch (error) {
        res.sendError("Login failed: " + error.message, 500);
    }
};

// user logout
exports.logout = (req, res) => {
    res.clearCookie("jwt");
    res.sendSuccess(null, "User logged out successfully");
};
