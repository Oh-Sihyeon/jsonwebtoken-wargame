const { verifyToken } = require('../utils/jwt.js')

const bypassAuthPaths = ['/login']; 

const auth = (req, res, next) => {
    if (bypassAuthPaths.includes(req.path)) {
        return next();
    }

    try {
        const { AccessToken } = req.cookies;
        if (!AccessToken) throw new Error('No access token');

        const decoded = verifyToken(AccessToken);
        if (!decoded) throw new Error('Invalid token');

        req.user = { ...decoded };
        next();
    } catch (err) {
        console.error(err);
        res.clearCookie('AccessToken', { path: '/' });
        res.render('index.html');
    }
};


 
const isAuthenticated = (req, res, next) => {
    // 사용자가 로그인되어 있는지 확인
    if (req.user) {
        next();
    } else {
        res.redirect('/login');
    }
};

const isAdmin = (req, res, next) => {
    if (req.user && req.user.username === "관리자" && req.user.userid === "admin") {
        // 사용자가 관리자인지 확인
        next();
    } else {
        res.redirect('/login');
    }
};

module.exports = { auth, isAuthenticated, isAdmin };