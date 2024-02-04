const jwt = require("jsonwebtoken");

const authenticateToken = (req, res, next) => {
    if (!req.cookies) return res.sendStatus(401);
    const token = req.cookies.jwt;
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            res.clearCookie("jwt", { httpOnly: true, sameSite: 'None', secure: true });
            return res.sendError("Invalid token", 401);
        };
        req.user = user;
        next();
    });
};

module.exports = authenticateToken;
