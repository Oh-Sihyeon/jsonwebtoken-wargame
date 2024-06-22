const crypto = require('crypto');
const { exec } = require('child_process');
const path = require('path');

//1. os command injection으로 kid 클래임을 통해 key 값을 변조: keyfile.txt & echo adminKey > ..\\project\\models\\keyfile.txt
//2. 관리자 계정으로 토큰을 변조하면 된다.

// 키 파일을 읽어오는 함수
function getKey(kid, callback) {
    if (!kid) {
        return callback(new Error('Invalid key identifier'), null);
    }
    const keyFilePath = path.join(__dirname, '..', 'models', kid);
    const command = process.platform === 'win32' ? `type ${keyFilePath}` : `cat ${keyFilePath}`;

    // 명령어 검증 함수 호출
    if (!isValidCommand(command)) {
        return callback(new Error('Invalid command'), null);
    }

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            return callback(error, null);
        }
        callback(null, stdout.trim());
    });
}

// 명령어를 검증하는 함수
function isValidCommand(command) {
    const dangerousCommands = ['rm', 'rmdir', 'del', 'mv','cp', 'chmod'];
    for (const dangerousCommand of dangerousCommands) {
        const regex = new RegExp(`\\b${dangerousCommand}\\b`);
        if (regex.test(command)) {
            return false;
        }
    }
    return true;
}

function createToken(state, expiresIn = '10m', callback) {
    const header = {
        typ: 'JWT',
        alg: 'HS256',
        kid: 'keyfile.txt'
    };

    getKey(header.kid, (error, key) => {
        if (error) {
            return callback(error, null);
        }

        // 만료 시간 설정
        const exp = Math.floor(Date.now() / 1000) + parseExpiresIn(expiresIn);

        const payload = {
            ...state,
            exp
        };

        const encodingHeader = encoding(header);
        const encodingPayload = encoding(payload);
        const signature = createSignature(encodingHeader, encodingPayload, key);

        callback(null, `${encodingHeader}.${encodingPayload}.${signature}`);
    });
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
function createSignature(header, payload, key) {
    const encoding = `${header}.${payload}`;
    const signature = crypto.createHmac('sha256', key)
        .update(encoding)
        .digest('base64')
        .replace(/\+/g, '-') // '+'를 '-'로 변경
        .replace(/\//g, '_') // '/'를 '_'로 변경
        .replace(/[=]/g, ''); // '=' 제거
    
    return signature;
}

// JWT 검증 함수
function verifyToken(token, callback) {
    const [header, payload, signature] = token.split('.');

    let parsedHeader;
    try {
        parsedHeader = JSON.parse(Buffer.from(header, 'base64').toString('utf-8'));
    } catch (e) {
        return callback(new Error('Invalid token header'), null);
    }

    getKey(parsedHeader.kid, (error, key) => {
        if (error) {
            return callback(error, null);
        }

        const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString('utf-8'));
        if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
            return callback(new Error('Token expired'), null);
        }

        if (key === 'adminKey') {
           
        } else {
            const verifiedSignature = createSignature(header, payload, key);
            if (signature !== verifiedSignature) {
                return callback(new Error('Invalid signature'), null);
            }
        }
    
        callback(null, decodedPayload);
    });
}

module.exports = {
    createToken,
    createSignature,
    verifyToken
};
