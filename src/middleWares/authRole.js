const jwt = require("jsonwebtoken");

const authRole = (requiredRole) => {
    return (req, res, next) => {
        if (!req.cookies)
            return res
                .status(401)
                .sendError("Access denied. No cookies provided.", 401);

        const token = req.cookies.jwt;

        if (!token) {
            return res
                .status(401)
                .sendError("Access denied. No token provided.", 401);
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;

            if (decoded.role !== requiredRole) {
                return res
                    .status(403)
                    .sendError("Access denied. Insufficient role.", 403);
            }

            next();
        } catch (ex) {
            res.status(400).sendError("Invalid token.", 400);
        }
    };
};

module.exports = authRole;
