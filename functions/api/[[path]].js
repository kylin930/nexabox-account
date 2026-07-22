// functions/api/[[path]].js

const generateToken = () => crypto.randomUUID();

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  if (path === '/login' && method === 'GET') {
    const query = url.search;
    const redirectUrl = `/Login.html${query}`;
    return Response.redirect(redirectUrl, 302);
  }
  if (method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const response = await routeRequest(path, method, request, env);
    const newResponse = new Response(response.body, response);
    Object.entries(corsHeaders).forEach(([k, v]) => newResponse.headers.set(k, v));
    return newResponse;
  } catch (err) {
    console.error(err);
    const errorResponse = new Response(JSON.stringify({ error: err.message }), { 
      status: err.status || 500,
      headers: { 'Content-Type': 'application/json' }
    });
    Object.entries(corsHeaders).forEach(([k, v]) => errorResponse.headers.set(k, v));
    return errorResponse;
  }
}

async function routeRequest(path, method, request, env) {
  // Public routes
  if (path === '/api/login' && method === 'POST') {
    return handleLogin(request, env);
  }

  // Auth check for all other routes
  const tokenHeader = request.headers.get('Authorization');
  const token = tokenHeader?.startsWith('Bearer ') ? tokenHeader.substring(7) : null;
  if (!token) return new Response('Unauthorized', { status: 401 });

  const sessionData = await env.STUDIO_KV.get(`session:${token}`, 'json');
  if (!sessionData) return new Response('Session Expired', { status: 401 });
  const currentUser = sessionData.username;

  // Protected routes
  switch (path) {
    case '/api/me':
      if (method === 'GET') {
        const user = await env.STUDIO_KV.get(`user:${currentUser}`, 'json');
        return Response.json({ username: currentUser, ...user });
      }
      break;

    case '/api/change-password':
      if (method === 'POST') {
        const { newPassword } = await request.json();
        const user = await env.STUDIO_KV.get(`user:${currentUser}`, 'json');
        user.password = newPassword;
        user.isInitialPassword = false;
        await env.STUDIO_KV.put(`user:${currentUser}`, JSON.stringify(user));
        return Response.json({ success: true });
      }
      break;

    case '/api/update-avatar':
      if (method === 'POST') {
        const { avatar } = await request.json();
        const user = await env.STUDIO_KV.get(`user:${currentUser}`, 'json');
        user.avatar = avatar || '';
        await env.STUDIO_KV.put(`user:${currentUser}`, JSON.stringify(user));
        return Response.json({ success: true, avatar: user.avatar });
      }
      break;

    case '/api/messages':
      if (method === 'POST') {
        const { toUser, content } = await request.json();
        const message = { from: currentUser, content, time: Date.now() };
        const userBox = await env.STUDIO_KV.get(`msg:${toUser}`, 'json') || [];
        userBox.push(message);
        await env.STUDIO_KV.put(`msg:${toUser}`, JSON.stringify(userBox));
        return Response.json({ success: true });
      }
      if (method === 'GET') {
        const messages = await env.STUDIO_KV.get(`msg:${currentUser}`, 'json') || [];
        return Response.json(messages);
      }
      break;

    case '/api/verify':
      if (method === 'POST') {
        const { token: tokenToVerify, app } = await request.json();
        if (!tokenToVerify) return new Response('Missing Token', { status: 400 });
        
        const session = await env.STUDIO_KV.get(`session:${tokenToVerify}`, 'json');
        if (!session) return Response.json({ valid: false });
        
        const user = await env.STUDIO_KV.get(`user:${session.username}`, 'json');
        const perms = user ? user.permissions : [];
        const hasAll = perms.includes('all');
        
        const responseData = {
          valid: true,
          username: session.username,
          permissions: perms,
          has_all: hasAll
        };

        if (app) {
          responseData.authorized = hasAll || perms.includes(app);
        }

        return Response.json(responseData);
      }
      break;
    case '/api/user-config':
      if (method === 'GET') {
        const config = await env.STUDIO_KV.get(`user:config:${currentUser}`, 'json') || {};
        return Response.json(config);
      }
      if (method === 'POST') {
        const newConfig = await request.json();
        await env.STUDIO_KV.put(`user:config:${currentUser}`, JSON.stringify(newConfig));
        return Response.json({ success: true });
      }
      if (method === 'DELETE') {
        await env.STUDIO_KV.delete(`user:config:${currentUser}`);
        return Response.json({ success: true });
      }
      break;
  }

  // Admin routes
  if (path.startsWith('/api/admin')) {
    if (currentUser !== env.ADMIN_USER) {
      return new Response('Forbidden', { status: 403 });
    }

    if (path === '/api/admin/users' && method === 'POST') {
      const { username, initialPassword } = await request.json();
      const newUser = {
        password: initialPassword,
        isInitialPassword: true,
        permissions: [],
        lastLogin: null,
        avatar: ""
      };
      await env.STUDIO_KV.put(`user:${username}`, JSON.stringify(newUser));
      return Response.json({ success: true });
    }

    if (path === '/api/admin/users' && method === 'DELETE') {
      const { username } = await request.json();
      await env.STUDIO_KV.delete(`user:${username}`);
      return Response.json({ success: true });
    }

    if (path === '/api/admin/users/permissions' && method === 'PUT') {
      const { username, permissions } = await request.json();
      const user = await env.STUDIO_KV.get(`user:${username}`, 'json');
      if(!user) return new Response('User Not Found', { status: 404 });
      user.permissions = permissions;
      await env.STUDIO_KV.put(`user:${username}`, JSON.stringify(user));
      return Response.json({ success: true });
    }

    if (path === '/api/admin/users/grant-all' && method === 'POST') {
      const { permission } = await request.json();
      if (!permission) return new Response('Missing Permission Name', { status: 400 });
      
      const permsToAdd = permission.split(',').map(p => p.trim()).filter(p => p !== '');
      if (permsToAdd.length === 0) return new Response('Invalid Permission Name', { status: 400 });

      const list = await env.STUDIO_KV.list({ prefix: 'user:' });
      let count = 0;
      for (const item of list.keys) {
        const user = await env.STUDIO_KV.get(item.name, 'json');
        if (user) {
          let modified = false;
          permsToAdd.forEach(p => {
            if (!user.permissions.includes(p)) {
              user.permissions.push(p);
              modified = true;
            }
          });
          if (modified) {
            await env.STUDIO_KV.put(item.name, JSON.stringify(user));
            count++;
          }
        }
      }
      return Response.json({ success: true, count });
    }
  }

  return new Response('Not Found', { status: 404 });
}

async function handleLogin(request, env) {
  const { username, password, app } = await request.json();
  let isValid = false;
  let isInitial = false;
  let permissions = [];

  if (username === env.ADMIN_USER && password === env.ADMIN_PASS) {
    isValid = true;
    permissions = ['admin', 'all'];
  } else {
    const user = await env.STUDIO_KV.get(`user:${username}`, 'json');
    if (user && user.password === password) {
      isValid = true;
      isInitial = user.isInitialPassword;
      permissions = user.permissions || [];
      user.lastLogin = Date.now();
      await env.STUDIO_KV.put(`user:${username}`, JSON.stringify(user));
    }
  }

  if (isValid) {
    const token = generateToken();
    await env.STUDIO_KV.put(`session:${token}`, JSON.stringify({ username }), { expirationTtl: 86400 });
    return Response.json({ success: true, token, isInitial, permissions, username });
  } else {
    return new Response('Invalid credentials', { status: 401 });
  }
}
