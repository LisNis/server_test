const http = require('http');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const url = require('url');

const server = http.createServer((req, res) => {

    if (req.method === 'GET' && req.url.startsWith('/check-username')) {
        const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
        const username = parsedUrl.searchParams.get('username');
    
        if (!username) {
            res.writeHead(400);
            res.end('Error: Username is required for username availability check');
            return;
        }
    
        // Check if the username already exists in the database
        const databasePath = path.join(__dirname, '../PublicResources/data', 'users.json');
        fs.readFile(databasePath, 'utf8', (err, data) => {
            if (err && err.code !== 'ENOENT') {
                res.writeHead(500);
                res.end('Error: Could not read user database');
                return;
            }
    
            let users;
            try {
                users = data ? JSON.parse(data) : [];
            } catch (parseError) {
                res.writeHead(500);
                res.end('Error: Could not parse user database');
                return;
            }
    
            const existingUser = users.find(user => user.username === username);
            const response = {
                available: !existingUser
            };
    
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(response));
        });
    }
    else if (req.method === 'POST' && req.url === '/login') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString(); // Buffer to string
        });
        req.on('end', () => {
            const loginData = JSON.parse(body);
            const username = loginData.username;
            const password = loginData.password;

            fs.readFile(path.join(__dirname, '../PublicResources/data', 'users.json'), 'utf8', (err, data) => {
                if (err) {
                    res.writeHead(500);
                    res.end('Error: Could not read user data');
                    return;
                }
                
                try {
                    const users = JSON.parse(data);
                    const user = users.find(user => user.username === username);
                    if (user) {
                        // Compare the hashed password
                        bcrypt.compare(password, user.password, (err, result) => {
                            if (result) {
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ message: 'Login successful' }));
                            } else {
                                res.writeHead(401);
                                res.end('Invalid password');
                            }
                        });
                    } else {
                        res.writeHead(404);
                        res.end('User not found');
                    }
                } catch (parseError) {
                    res.writeHead(500);
                    res.end('Error: Could not parse user data');
                }
            });
        });
    } else {
        let filePath = req.url === '/' ? '/html/login.html' : req.url;

        if (filePath === '/post') {
            filePath = '/html/post.html';
        } else if (filePath === '/groups') {
            filePath = '/html/groups.html';
        }

        filePath = path.join(__dirname, '../PublicResources', filePath);

        fs.readFile(filePath, (error, data) => {
            if (error) {
                if (error.code === 'ENOENT') {
                    res.writeHead(404);
                    res.end('Error: File not found');
                } else {
                    res.writeHead(500);
                    res.end('Error: Internal Server Error');
                }
            } else {
                let contentType = 'text/plain';
                const ext = path.extname(filePath);
                if (ext === '.html') {
                    contentType = 'text/html';
                } else if (ext === '.css') {
                    contentType = 'text/css';
                } else if (ext === '.js') {
                    contentType = 'text/javascript';
                }

                res.writeHead(200, { 'Content-Type': contentType });
                res.end(data);
            }
        });
    }   

});

const PORT = process.env.PORT || 3242;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});