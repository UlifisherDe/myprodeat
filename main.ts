import { Application, Router } from "oak";
import { crypto, kv } from "deno";
import { hashSync, compareSync } from "bcrypt";
import { create, verify } from "djwt";
import { renderFile } from "eta";

// 类型定义
interface User {
  username: string;
  password: string;
  createdAt: Date;
}

// 环境配置
const env = Deno.env.toObject();
const CONFIG = {
  PORT: Number(env.PORT) || 8000,
  JWT_SECRET: env.JWT_SECRET || "super_secret_key_123!",
};

// 打开 Deno KV 数据库
const denoKv = await kv.openKv();

// Web应用初始化
const app = new Application();
const router = new Router();

// 中间件
app.use(async (ctx, next) => {
  ctx.response.headers.set("X-Content-Type-Options", "nosniff");
  ctx.response.headers.set("X-Frame-Options", "DENY");
  await next();
});

// 路由配置
router
  .get("/", async (ctx) => {
    // 获取前10个用户
    const users = [];
    for await (const entry of denoKv.list<User>({ prefix: ["users"] })) {
      users.push(entry.value);
    }

    ctx.response.body = await renderFile("views/index.eta", {
      users: users.sort((a, b) => 
        b.createdAt.getTime() - a.createdAt.getTime()
      ).slice(0, 10),
      timestamp: new Date().toLocaleString()
    });
  })
  .post("/api/register", async (ctx) => {
    const body = await ctx.request.body().value;
    const { username, password } = body;

    // 输入验证
    if (!username || !password) {
      ctx.throw(400, "用户名和密码不能为空");
    }
    if (password.length < 6) {
      ctx.throw(400, "密码至少需要6位");
    }

    // 检查用户是否存在
    const userKey = ["users", username];
    const existingUser = await denoKv.get<User>(userKey);
    if (existingUser.value) {
      ctx.throw(409, "用户已存在");
    }

    // 创建用户
    const user: User = {
      username,
      password: hashSync(password),
      createdAt: new Date()
    };

    // 原子操作写入用户数据
    const commitResult = await denoKv.atomic()
      .check({ key: userKey, versionstamp: null })
      .set(userKey, user)
      .commit();

    if (!commitResult.ok) {
      ctx.throw(500, "用户注册失败");
    }

    // 生成 JWT
    const token = await createJwt(username);
    ctx.response.body = { 
      success: true,
      token,
      user: { username }
    };
  })
  .get("/health", (ctx) => {
    ctx.response.body = {
      status: "healthy",
      timestamp: Date.now()
    };
  });

// JWT 工具函数
async function createJwt(username: string): Promise<string> {
  return await create(
    { alg: "HS256", typ: "JWT" },
    { 
      sub: username,
      iat: Date.now(),
      exp: Date.now() + 3_600_000 // 1小时有效期
    },
    CONFIG.JWT_SECRET
  );
}

// 启动服务
console.log(`🚀 服务已启动: http://localhost:${CONFIG.PORT}`);
await app.use(router.routes()).listen({ port: CONFIG.PORT });
