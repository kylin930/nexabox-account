// functions/api/[[path]].js

// 辅助函数：生成随机 Token
const generateToken = () => crypto.randomUUID();

export async function onRequest(context) {
  const { request, env, params } = context;
  const url = new URL(request.url);
  const path = url.pathname; // 例如 /api/login
  const method = request.method;

  // 简单的路由分发
  try {
    if (path === '/api/login' && method === 'POST') {
      return await handleLogin(request, env);
    }
    
    // 以下接口需要验证 Token
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    if (!token) return new Response('未授权', { status: 401 });
    
    // 获取当前会话用户信息
    const sessionData = await env.STUDIO_KV.get(`session:${token}`, 'json');
    if (!sessionData) return new Response('登录已过期', { status: 401 });
    const currentUser = sessionData.username;

    if (path === '/api/me' && method === 'GET') {
      const user = await env.STUDIO_KV.get(`user:${currentUser}`, 'json');
      return Response.json({ username: currentUser, ...user });
    }

    if (path === '/api/change-password' && method === 'POST') {
      const { newPassword } = await request.json();
      const user = await env.STUDIO_KV.get(`user:${currentUser}`, 'json');
      user.password = newPassword; // 实际生产中建议在此处加盐哈希
      user.isInitialPassword = false;
      await env.STUDIO_KV.put(`user:${currentUser}`, JSON.stringify(user));
      return Response.json({ success: true });
    }

    // --- 内部消息功能 ---
    if (path === '/api/messages' && method === 'POST') {
      const { toUser, content } = await request.json();
      const msgId = crypto.randomUUID();
      const message = { from: currentUser, content, time: Date.now() };
      // 简单起见，把消息存为一个列表
      const userBox = await env.STUDIO_KV.get(`msg:${toUser}`, 'json') || [];
      userBox.push(message);
      await env.STUDIO_KV.put(`msg:${toUser}`, JSON.stringify(userBox));
      return Response.json({ success: true });
    }

    if (path === '/api/messages' && method === 'GET') {
      const messages = await env.STUDIO_KV.get(`msg:${currentUser}`, 'json') || [];
      return Response.json(messages);
    }

    // --- 管理员专属功能 ---
    if (path.startsWith('/api/admin')) {
      if (currentUser !== env.ADMIN_USER) return new Response('无管理员权限', { status: 403 });

      if (path === '/api/admin/users' && method === 'POST') {
        // 创建新用户
        const { username, initialPassword } = await request.json();
        const newUser = {
          password: initialPassword,
          isInitialPassword: true, // 标记为初始密码，需强制修改
          permissions: [], // 默认无任何应用权限
          lastLogin: null
        };
        await env.STUDIO_KV.put(`user:${username}`, JSON.stringify(newUser));
        return Response.json({ success: true });
      }

      if (path === '/api/admin/users/permissions' && method === 'PUT') {
        // 修改用户权限
        const { username, permissions } = await request.json();
        const user = await env.STUDIO_KV.get(`user:${username}`, 'json');
        if(!user) return new Response('用户不存在', { status: 404 });
        user.permissions = permissions;
        await env.STUDIO_KV.put(`user:${username}`, JSON.stringify(user));
        return Response.json({ success: true });
      }
    }

    return new Response('Not Found', { status: 404 });
  } catch (err) {
    return new Response(err.message, { status: 500 });
  }
}

// 登录处理函数
async function handleLogin(request, env) {
  const { username, password } = await request.json();
  let isValid = false;
  let isInitial = false;
  let permissions = [];

  // 检查是否是管理员登录
  if (username === env.ADMIN_USER && password === env.ADMIN_PASS) {
    isValid = true;
    permissions = ['admin', 'all']; // 管理员拥有最高权限
  } else {
    // 检查普通用户
    const user = await env.STUDIO_KV.get(`user:${username}`, 'json');
    if (user && user.password === password) {
      isValid = true;
      isInitial = user.isInitialPassword;
      permissions = user.permissions || [];
      
      // 更新最后登录时间
      user.lastLogin = Date.now();
      await env.STUDIO_KV.put(`user:${username}`, JSON.stringify(user));
    }
  }

  if (isValid) {
    const token = generateToken();
    // Token 过期时间设置为 24 小时 (以秒为单位)
    await env.STUDIO_KV.put(`session:${token}`, JSON.stringify({ username }), { expirationTtl: 86400 });
    return Response.json({ success: true, token, isInitial, permissions, username });
  } else {
    return new Response('账号或密码错误', { status: 401 });
  }
}
