const { verifyToken } = require('../utils/jwt.js');

// 인증 미들웨어
function auth(req, res, next) {
    const token = req.cookies.AccessToken;
    if (!token) {
        return next();
    }

    verifyToken(token, (error, decoded) => {
        if (error) {
            console.log(error);
            return next();
        }
        req.user = decoded;
        next();
    });
}

// 인증 확인 미들웨어
function isAuthenticated(req, res, next) {
    if (!req.user) {
        return res.redirect('/login');
    }
    next();
}

// 관리자 확인 미들웨어
function isAdmin(req, res, next) {
    if (req.user.level !== 'adminlevel') {
        return res.redirect('/');
    }
    next();
}

module.exports = {
    auth,
    isAuthenticated,
    isAdmin
};
