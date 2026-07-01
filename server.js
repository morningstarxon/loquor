const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const PORT = process.env.PORT || 8080;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY env vars.');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
    auth: { persistSession: false }
});

const PUBLIC_ROOM = 'public';
const PUBLIC_HISTORY_LIMIT = 10;
const DM_HISTORY_LIMIT = 13;
const SESSION_TTL_DAYS = 30;
const MAX_AVATAR_BYTES = 500 * 1024; // 500KB
const MAX_MESSAGE_LEN = 500;
const USERNAME_MIN = 2;
const USERNAME_MAX = 30;
const PASSWORD_MIN = 8;

// --- Password / token hashing (built-in crypto, no extra deps) ---
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(':');
    if (!salt || !hash) return false;
    const check = crypto.scryptSync(password, salt, 64).toString('hex');
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(check, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function dmRoomId(userIdA, userIdB) {
    return 'dm:' + [userIdA, userIdB].sort().join(':');
}

function isValidUsername(name) {
    return typeof name === 'string' &&
        name.length >= USERNAME_MIN &&
        name.length <= USERNAME_MAX &&
        /^[a-zA-Z0-9_. -]+$/.test(name);
}

// --- JSON body helper ---
function readJsonBody(req, maxBytes) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        req.on('data', (chunk) => {
            size += chunk.length;
            if (size > maxBytes) {
                reject(new Error('Payload too large'));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            try {
                const raw = Buffer.concat(chunks).toString('utf8');
                resolve(raw ? JSON.parse(raw) : {});
            } catch (e) {
                reject(new Error('Invalid JSON'));
            }
        });
        req.on('error', reject);
    });
}

function sendJson(res, statusCode, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
    });
    res.end(body);
}

// --- Session validation shared by HTTP + WS ---
async function getUserByToken(token) {
    if (!token) return null;
    const tokenHash = hashToken(token);
    const { data: session, error } = await supabase
        .from('sessions')
        .select('id, user_id, expires_at')
        .eq('token_hash', tokenHash)
        .maybeSingle();

    if (error || !session) return null;
    if (new Date(session.expires_at) < new Date()) return null;

    const { data: user, error: userErr } = await supabase
        .from('users')
        .select('id, username, avatar_url')
        .eq('id', session.user_id)
        .maybeSingle();

    if (userErr || !user) return null;

    // Best-effort last_seen bump, don't block on it
    supabase.from('sessions').update({ last_seen_at: new Date().toISOString() })
        .eq('id', session.id).then(() => {}, () => {});

    return user;
}

// ================================================================
// HTTP Server: static files + REST auth/avatar endpoints
// ================================================================
const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;

    try {
        // --- POST /api/signup ---
        if (pathname === '/api/signup' && req.method === 'POST') {
            const body = await readJsonBody(req, 10 * 1024);
            const username = (body.username || '').trim();
            const password = body.password || '';

            if (!isValidUsername(username)) {
                return sendJson(res, 400, { error: 'Username must be 2-30 characters (letters, numbers, spaces, _ . -).' });
            }
            if (typeof password !== 'string' || password.length < PASSWORD_MIN) {
                return sendJson(res, 400, { error: `Password must be at least ${PASSWORD_MIN} characters.` });
            }

            const usernameLower = username.toLowerCase();
            const { data: existing } = await supabase
                .from('users').select('id').eq('username_lower', usernameLower).maybeSingle();
            if (existing) {
                return sendJson(res, 409, { error: 'That username is taken.' });
            }

            const passwordHash = hashPassword(password);
            const { data: newUser, error: insertErr } = await supabase
                .from('users')
                .insert({ username, username_lower: usernameLower, password_hash: passwordHash })
                .select('id, username, avatar_url')
                .single();

            if (insertErr || !newUser) {
                console.error('Signup insert error:', insertErr);
                return sendJson(res, 500, { error: 'Could not create account.' });
            }

            const session = await createSession(newUser.id);
            return sendJson(res, 200, { user: newUser, token: session.token });
        }

        // --- POST /api/login ---
        if (pathname === '/api/login' && req.method === 'POST') {
            const body = await readJsonBody(req, 10 * 1024);
            const username = (body.username || '').trim();
            const password = body.password || '';

            const { data: user } = await supabase
                .from('users')
                .select('id, username, avatar_url, password_hash')
                .eq('username_lower', username.toLowerCase())
                .maybeSingle();

            if (!user || !verifyPassword(password, user.password_hash)) {
                return sendJson(res, 401, { error: 'Invalid username or password.' });
            }

            const session = await createSession(user.id);
            return sendJson(res, 200, {
                user: { id: user.id, username: user.username, avatar_url: user.avatar_url },
                token: session.token
            });
        }

        // --- POST /api/session (auto-login via stored token) ---
        if (pathname === '/api/session' && req.method === 'POST') {
            const body = await readJsonBody(req, 2 * 1024);
            const user = await getUserByToken(body.token);
            if (!user) return sendJson(res, 401, { error: 'Session expired.' });
            return sendJson(res, 200, { user });
        }

        // --- POST /api/logout ---
        if (pathname === '/api/logout' && req.method === 'POST') {
            const body = await readJsonBody(req, 2 * 1024);
            if (body.token) {
                await supabase.from('sessions').delete().eq('token_hash', hashToken(body.token));
            }
            return sendJson(res, 200, { ok: true });
        }

        // --- POST /api/avatar ---
        if (pathname === '/api/avatar' && req.method === 'POST') {
            const body = await readJsonBody(req, Math.ceil(MAX_AVATAR_BYTES * 1.4) + 4096);
            const user = await getUserByToken(body.token);
            if (!user) return sendJson(res, 401, { error: 'Not logged in.' });

            const dataUrl = body.image || '';
            const match = /^data:(image\/(png|jpeg|jpg|webp|gif));base64,(.+)$/.exec(dataUrl);
            if (!match) {
                return sendJson(res, 400, { error: 'Image must be PNG, JPEG, WEBP, or GIF.' });
            }
            const mime = match[1];
            const ext = match[2] === 'jpeg' ? 'jpg' : match[2];
            const base64Data = match[3];
            const buffer = Buffer.from(base64Data, 'base64');

            if (buffer.length > MAX_AVATAR_BYTES) {
                return sendJson(res, 400, { error: 'Avatar must be under 500KB.' });
            }

            const filePath = `${user.id}/avatar.${ext}`;
            const { error: uploadErr } = await supabase.storage
                .from('avatars')
                .upload(filePath, buffer, { contentType: mime, upsert: true });

            if (uploadErr) {
                console.error('Avatar upload error:', uploadErr);
                return sendJson(res, 500, { error: 'Upload failed.' });
            }

            const { data: pub } = supabase.storage.from('avatars').getPublicUrl(filePath);
            const avatarUrl = pub.publicUrl + '?t=' + Date.now(); // cache-bust

            await supabase.from('users').update({ avatar_url: avatarUrl }).eq('id', user.id);
            broadcastToAll({ type: 'avatar_update', userId: user.id, avatarUrl });

            return sendJson(res, 200, { avatar_url: avatarUrl });
        }

        // --- Static files ---
        if (pathname === '/' || pathname === '') {
            return serveFile(res, path.join(__dirname, 'index.html'), 'text/html');
        }

        const safePath = path.normalize(pathname).replace(/^(\.\.[/\\])+/, '');
        const filePath = path.join(__dirname, safePath);
        if (filePath.startsWith(__dirname) && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
            const ext = path.extname(filePath);
            const contentType = {
                '.html': 'text/html', '.css': 'text/css',
                '.js': 'application/javascript', '.json': 'application/json'
            }[ext] || 'text/plain';
            return serveFile(res, filePath, contentType);
        }

        res.writeHead(404);
        res.end('Not found');
    } catch (e) {
        console.error('HTTP handler error:', e);
        sendJson(res, 500, { error: 'Server error.' });
    }
});

function serveFile(res, filePath, contentType) {
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(500);
            res.end('Error loading file');
            return;
        }
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(data);
    });
}

async function createSession(userId) {
    const token = generateToken();
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();

    await supabase.from('sessions').insert({ user_id: userId, token_hash: tokenHash, expires_at: expiresAt });
    return { token };
}

// ================================================================
// WebSocket Server
// ================================================================
const wss = new WebSocket.Server({ server, path: '/ws' });

// userId -> Set of ws connections (a user might have multiple tabs)
const userConnections = new Map();
// track which rooms each ws is "subscribed" to for presence purposes
const publicRoomConnections = new Set();

wss.on('connection', async (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');

    const user = await getUserByToken(token);
    if (!user) {
        ws.close(4001, 'Unauthorized');
        return;
    }

    ws.user = user;
    ws.isAlive = true;

    if (!userConnections.has(user.id)) userConnections.set(user.id, new Set());
    userConnections.get(user.id).add(ws);
    publicRoomConnections.add(ws);

    // Send public room history
    const publicHistory = await fetchHistory(PUBLIC_ROOM, PUBLIC_HISTORY_LIMIT);
    ws.send(JSON.stringify({ type: 'history', room: PUBLIC_ROOM, messages: publicHistory }));

    broadcastSystem(PUBLIC_ROOM, `${user.username} joined the room`);
    broadcastOnlineCount();

    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', async (raw) => {
        let data;
        try {
            data = JSON.parse(raw);
        } catch (e) {
            return;
        }

        try {
            if (data.type === 'message' && typeof data.text === 'string') {
                const text = data.text.trim().substring(0, MAX_MESSAGE_LEN);
                if (!text) return;

                if (data.room === PUBLIC_ROOM) {
                    await handlePublicMessage(ws.user, text);
                } else if (data.room && data.room.startsWith('dm:')) {
                    await handleDmMessage(ws.user, data.room, text);
                }
            } else if (data.type === 'open_dm' && typeof data.username === 'string') {
                await handleOpenDm(ws, data.username);
            } else if (data.type === 'typing' && data.room) {
                relayTyping(ws.user, data.room);
            }
        } catch (e) {
            console.error('WS message handling error:', e);
        }
    });

    ws.on('close', () => {
        publicRoomConnections.delete(ws);
        const conns = userConnections.get(user.id);
        if (conns) {
            conns.delete(ws);
            if (conns.size === 0) {
                userConnections.delete(user.id);
                broadcastSystem(PUBLIC_ROOM, `${user.username} left the room`);
            }
        }
        broadcastOnlineCount();
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
    });
});

// Heartbeat to drop dead connections (helps low-power/flaky mobile clients
// reconnect cleanly instead of hanging on a zombie socket)
const heartbeatInterval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        try { ws.ping(); } catch (e) {}
    });
}, 30000);

wss.on('close', () => clearInterval(heartbeatInterval));

// --- Message handling ---
async function handlePublicMessage(user, text) {
    const msg = {
        room: PUBLIC_ROOM,
        sender_id: user.id,
        sender_username: user.username,
        text
    };
    const { data: saved, error } = await supabase.from('messages').insert(msg).select().single();
    if (error) { console.error('Insert public message error:', error); return; }

    trimHistory(PUBLIC_ROOM, PUBLIC_HISTORY_LIMIT);

    broadcastToSet(publicRoomConnections, {
        type: 'message',
        room: PUBLIC_ROOM,
        username: saved.sender_username,
        userId: saved.sender_id,
        avatarUrl: user.avatar_url || null,
        text: saved.text,
        timestamp: new Date(saved.created_at).getTime()
    });
}

async function handleDmMessage(user, room, text) {
    // room must be dm:<idA>:<idB> and user must be one of the two ids
    const parts = room.split(':');
    if (parts.length !== 3 || ![parts[1], parts[2]].includes(user.id)) return;
    const otherId = parts[1] === user.id ? parts[2] : parts[1];

    const msg = {
        room,
        sender_id: user.id,
        sender_username: user.username,
        text
    };
    const { data: saved, error } = await supabase.from('messages').insert(msg).select().single();
    if (error) { console.error('Insert DM error:', error); return; }

    trimHistory(room, DM_HISTORY_LIMIT);

    const payload = {
        type: 'message',
        room,
        username: saved.sender_username,
        userId: saved.sender_id,
        avatarUrl: user.avatar_url || null,
        text: saved.text,
        timestamp: new Date(saved.created_at).getTime()
    };

    sendToUser(user.id, payload);
    sendToUser(otherId, payload);
}

async function handleOpenDm(ws, targetUsername) {
    const { data: target } = await supabase
        .from('users').select('id, username, avatar_url')
        .eq('username_lower', targetUsername.trim().toLowerCase())
        .maybeSingle();

    if (!target) {
        ws.send(JSON.stringify({ type: 'error', message: 'User not found.' }));
        return;
    }
    if (target.id === ws.user.id) {
        ws.send(JSON.stringify({ type: 'error', message: "You can't DM yourself." }));
        return;
    }

    const room = dmRoomId(ws.user.id, target.id);
    const history = await fetchHistory(room, DM_HISTORY_LIMIT);
    ws.send(JSON.stringify({
        type: 'dm_opened',
        room,
        with: { id: target.id, username: target.username, avatar_url: target.avatar_url },
        messages: history
    }));
}

function relayTyping(user, room) {
    const payload = { type: 'typing', room, username: user.username };
    if (room === PUBLIC_ROOM) {
        broadcastToSet(publicRoomConnections, payload, user.id);
    } else if (room.startsWith('dm:')) {
        const parts = room.split(':');
        if (![parts[1], parts[2]].includes(user.id)) return;
        const otherId = parts[1] === user.id ? parts[2] : parts[1];
        sendToUser(otherId, payload);
    }
}

async function fetchHistory(room, limit) {
    const { data, error } = await supabase
        .from('messages')
        .select('sender_id, sender_username, text, created_at')
        .eq('room', room)
        .order('created_at', { ascending: false })
        .limit(limit);

    if (error || !data) return [];

    // Attach avatar urls in one batch query
    const senderIds = [...new Set(data.map(m => m.sender_id))];
    const { data: users } = await supabase.from('users').select('id, avatar_url').in('id', senderIds);
    const avatarMap = new Map((users || []).map(u => [u.id, u.avatar_url]));

    return data.reverse().map(m => ({
        username: m.sender_username,
        userId: m.sender_id,
        avatarUrl: avatarMap.get(m.sender_id) || null,
        text: m.text,
        timestamp: new Date(m.created_at).getTime()
    }));
}

// Best-effort trim so the table doesn't grow unbounded; not called on
// every single message path synchronously blocking the send, fire-and-forget
async function trimHistory(room, limit) {
    const { data } = await supabase
        .from('messages')
        .select('id')
        .eq('room', room)
        .order('created_at', { ascending: false })
        .range(limit, limit + 200); // anything beyond the keep-limit

    if (data && data.length > 0) {
        const ids = data.map(r => r.id);
        await supabase.from('messages').delete().in('id', ids);
    }
}

// --- Broadcast helpers ---
function broadcastToSet(set, payload, excludeUserId) {
    const data = JSON.stringify(payload);
    set.forEach((client) => {
        if (excludeUserId && client.user && client.user.id === excludeUserId) return;
        if (client.readyState === WebSocket.OPEN) {
            try { client.send(data); } catch (e) {}
        }
    });
}

function broadcastToAll(payload) {
    const data = JSON.stringify(payload);
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            try { client.send(data); } catch (e) {}
        }
    });
}

function sendToUser(userId, payload) {
    const conns = userConnections.get(userId);
    if (!conns) return;
    const data = JSON.stringify(payload);
    conns.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            try { client.send(data); } catch (e) {}
        }
    });
}

function broadcastSystem(room, text) {
    broadcastToSet(publicRoomConnections, { type: 'system', room, text });
}

function broadcastOnlineCount() {
    broadcastToAll({ type: 'online_count', count: userConnections.size });
}

// --- Start Server ---
server.listen(PORT, () => {
    console.log(`Loquor running on http://localhost:${PORT}`);
    console.log(`WebSocket server ready at /ws`);
});
