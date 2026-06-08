// functions/api/[[path]].js

// 辅助函数：生成随机 Token
const generateToken = () => crypto.randomUUID();

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS 跨域处理
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };

  // 处理 预检请求 (Preflight)
  if (method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    let response;
    if (path === '/api/login' && method === 'POST') {
      response = await handleLogin(request, env);
    } else {
      // 以下接口需要验证 Token
      const tokenHeader = request.headers.get('Authorization');
      const token = tokenHeader?.startsWith('Bearer ') ? tokenHeader.substring(7) : null;
      
      // 注意：/api/verify 接口比较特殊，它本身就是用来验证 token 的，
      // 但根据文档，它也需要携带 Authorization 头
      if (!token) {
        response = new Response('未授权', { status: 401 });
      } else {
        // 获取当前会话用户信息
        const sessionData = await env.STUDIO_KV.get(`session:${token}`, 'json');
        if (!sessionData) {
          response = new Response('登录已过期', { status: 401 });
        } else {
          const currentUser = sessionData.username;

          if (path === '/api/me' && method === 'GET') {
            const user = await env.STUDIO_KV.get(`user:${currentUser}`, 'json');
            response = Response.json({ username: currentUser, ...user });
          } else if (path === '/api/change-password' && method === 'POST') {
            const { newPassword } = await request.json();
            const user = await env.STUDIO_KV.get(`user:${currentUser}`, 'json');
            user.password = newPassword;
            user.isInitialPassword = false;
            await env.STUDIO_KV.put(`user:${currentUser}`, JSON.stringify(user));
            response = Response.json({ success: true });
          } else if (path === '/api/update-avatar' && method === 'POST') {
            const { avatar } = await request.json();
            const user = await env.STUDIO_KV.get(`user:${currentUser}`, 'json');
            if (!user) {
              response = new Response('用户不存在', { status: 404 });
            } else {
              user.avatar = avatar || '';
              await env.STUDIO_KV.put(`user:${currentUser}`, JSON.stringify(user));
              response = Response.json({ success: true, avatar: user.avatar });
            }
          } else if (path === '/api/messages' && method === 'POST') {
            const { toUser, content } = await request.json();
            const message = { from: currentUser, content, time: Date.now() };
            const userBox = await env.STUDIO_KV.get(`msg:${toUser}`, 'json') || [];
            userBox.push(message);
            await env.STUDIO_KV.put(`msg:${toUser}`, JSON.stringify(userBox));
            response = Response.json({ success: true });
          } else if (path === '/api/messages' && method === 'GET') {
            const messages = await env.STUDIO_KV.get(`msg:${currentUser}`, 'json') || [];
            response = Response.json(messages);
          } else if (path === '/api/verify' && method === 'POST') {
            const { token: tokenToVerify } = await request.json();
            if (!tokenToVerify) {
              response = new Response('缺少 Token', { status: 400 });
            } else {
              const sessionDataVerify = await env.STUDIO_KV.get(`session:${tokenToVerify}`, 'json');
              if (!sessionDataVerify) {
                response = Response.json({ valid: false });
              } else {
                const user = await env.STUDIO_KV.get(`user:${sessionDataVerify.username}`, 'json');
                response = Response.json({
                  valid: true,
                  username: sessionDataVerify.username,
                  permissions: user ? user.permissions : []
                });
              }
            }
          } else if (path.startsWith('/api/admin')) {
            if (currentUser !== env.ADMIN_USER) {
              response = new Response('无管理员权限', { status: 403 });
            } else if (path === '/api/admin/users' && method === 'POST') {
              const { username, initialPassword } = await request.json();
              const newUser = {
                password: initialPassword,
                isInitialPassword: true,
                permissions: [],
                lastLogin: null,
                avatar: ""
              };
              await env.STUDIO_KV.put(`user:${username}`, JSON.stringify(newUser));
              response = Response.json({ success: true });
            } else if (path === '/api/admin/users' && method === 'DELETE') {
              const { username } = await request.json();
              await env.STUDIO_KV.delete(`user:${username}`);
              response = Response.json({ success: true });
            } else if (path === '/api/admin/users/permissions' && method === 'PUT') {
              const { username, permissions } = await request.json();
              const user = await env.STUDIO_KV.get(`user:${username}`, 'json');
              if(!user) {
                response = new Response('用户不存在', { status: 404 });
              } else {
                user.permissions = permissions;
                await env.STUDIO_KV.put(`user:${username}`, JSON.stringify(user));
                response = Response.json({ success: true });
              }
            }
          }
        }
      }
    }

    if (!response) {
      response = new Response('Not Found', { status: 404 });
    }

    // 给所有响应添加 CORS 头
    const newResponse = new Response(response.body, response);
    Object.entries(corsHeaders).forEach(([k, v]) => newResponse.headers.set(k, v));
    return newResponse;

  } catch (err) {
    const errorResponse = new Response(err.message, { status: 500 });
    Object.entries(corsHeaders).forEach(([k, v]) => errorResponse.headers.set(k, v));
    return errorResponse;
  }
}

// 登录处理函数
async function handleLogin(request, env) {
  const { username, password } = await request.json();
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
    return new Response('账号或密码错误', { status: 401 });
  }
}
