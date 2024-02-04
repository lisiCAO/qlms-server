// success response middleware
function sendSuccessResponse(req, res, next) {
    res.sendSuccess = (data, message) => {
        res.json({
            success: true,
            data: data,
            message: message,
        });
    };
    next();
}

// error response middleware
function sendErrorResponse(req, res, next) {
    res.sendError = (message, statusCode) => {
        res.status(statusCode).json({
            success: false,
            data: null,
            message: message,
        });
    };
    next();
}

module.exports = {
    sendSuccessResponse,
    sendErrorResponse,
};
