const express = require('express');
const nunjucks = require('nunjucks');
const cookieParser = require('cookie-parser');
const { users, admins } = require('./models/account.js');
const { createToken, verifyToken } = require('./utils/jwt.js');
const { auth, isAuthenticated, isAdmin } = require('./middlewares/auth.js');

const app = express()

// 뷰 엔진 설정
app.set('view engine', 'html');
nunjucks.configure('./views', {
    express: app,
    watch: true
});

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(auth);

// 홈페이지
app.get('/', (req, res) => {
    const { user } = req;
    res.render('index.html', { user });
});
// 로그인 페이지
app.get('/login', (req, res) => {
    res.render('login.html');
});
// 사용자 프로필 페이지
app.get('/userprofile', isAuthenticated, (req, res) => {
    const { user } = req;
    res.render('userprofile.html', { user });
});
// 관리자 프로필 페이지
app.get('/adminprofile', isAuthenticated, isAdmin, (req, res) => {
    res.render('adminprofile.html');
});

// 로그인 처리
app.post('/login', (req, res) => {
    const { userid, userpw } = req.body;

    // 사용자 검증
    let authenticatedUser = users.find(user => user.userid === userid && user.userpw === userpw);
    if (!authenticatedUser) {
        // 관리자 검증
        authenticatedUser = admins.find(admin => admin.userid === userid && admin.userpw === userpw);
    }

    try {
        if (!authenticatedUser) throw new Error('일치하는 아이디가 존재하지 않음');

        // payload 설정
        const payload = {
            userid: authenticatedUser.userid,
            username: authenticatedUser.username,
            level: users.includes(authenticatedUser) ? "userlevel" : "adminlevel" // 사용자인 경우 level 1, 관리자인 경우 level 2로 가정
        };

        // JWT 생성
        createToken(payload, '5m', (error, token) => {
            if (error) {
                console.log(error);
                return res.send('로그인 실패');
            }

            // 생성한 토큰을 쿠키로 만들어서 브라우저에게 전달
            res.cookie('AccessToken', token, {
                path: '/',
                HttpOnly: true
            });
            res.redirect('/');
        });

    } catch (err) {
        console.log(err);
        res.send('로그인 실패');
    }
});

// 로그 아웃 = 쿠키 삭제
app.get('/logout', (req, res) => {
    res.clearCookie('AccessToken', { path: '/' });
    res.redirect('/');
});

// 서버 리스닝
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
