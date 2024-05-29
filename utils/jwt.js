const crypto = require('crypto')
const fs = require('fs');
const path = require('path');

// 키 파일 경로
const keyFilePath = path.join(__dirname, '../models/keyfile.txt');

// 키 파일 내용을 읽어오는 함수
function getKey() {
    return fs.readFileSync(keyFilePath, 'utf8').trim();
}
 
function createToken(state, expiresIn = '5m') { // 기본값을 '5m'로
    const header = {
        typ: 'JWT',
        alg: 'HS256',
        kid: 'keyfile.txt'
    };

    // 만료 시간 설정
    const exp = Math.floor(Date.now() / 1000) + parseExpiresIn(expiresIn); // 만료 시간 설정 추가
    
    const payload = {
        ...state,
        exp
    };

    const encodingHeader = encoding(header);
    const encodingPayload = encoding(payload);
    const signature = createSignature(encodingHeader, encodingPayload);

    return `${encodingHeader}.${encodingPayload}.${signature}`;
}

// 만료 시간 문자열을 초 단위로 변환하는 함수
function parseExpiresIn(expiresIn) {
    const time = parseInt(expiresIn.slice(0, -1), 10);
    const unit = expiresIn.slice(-1);
    switch (unit) {
        case 's':
            return time;
        case 'm':
            return time * 60;
        case 'h':
            return time * 3600;
        case 'd':
            return time * 86400;
        default:
            throw new Error('Invalid expiresIn format');
    }
}
 
// base64 인코딩 함수
function encoding(value) {
    return Buffer.from(JSON.stringify(value))
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_') 
        .replace(/[=]/g, ''); 
}
 
// signature 생성 함수
function createSignature(header, payload) {
    const encoding = `${header}.${payload}`;
    const key = getKey();
    const signature = crypto.createHmac('sha256', key)
        .update(encoding)
        .digest('base64')
        .replace(/\+/g, '-') // '+'를 '-'로 변경
        .replace(/\//g, '_') // '/'를 '_'로 변경
        .replace(/[=]/g, ''); // '=' 제거
    
    return signature;
}

// JWT 검증 함수
function verifyToken(token) {
    const [header, payload, signature] = token.split('.');
    const verifiedSignature = createSignature(header, payload);
    if (signature !== verifiedSignature) {
        throw new Error('Invalid signature');
    }

    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString('utf-8'));
    if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
        throw new Error('Token expired');
    }

    return decodedPayload;
}
 
module.exports = {
    createToken,
    createSignature,
    verifyToken
}