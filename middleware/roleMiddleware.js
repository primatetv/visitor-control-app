// Middleware to check user role
function checkRole(role) {
    return function(req, res, next) {
        if (req.isAuthenticated() && req.user.role === role) {
            return next();
        }
        // If the role doesn't match, send an unauthorized error
        return res.status(403).render('403');
    };
}

module.exports = {
    checkRole
};