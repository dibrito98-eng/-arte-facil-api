require("dotenv").config();

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET) console.warn("JWT_SECRET não configurado.");
if (!DATABASE_URL) console.warn("DATABASE_URL não configurado.");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: 5,
});

app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(express.json({ limit: "10mb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

function signToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Não autenticado." });
    }

    const token = header.slice(7);
    const payload = jwt.verify(token, JWT_SECRET);

    const result = await pool.query(
      "SELECT id, name, email, role, status, avatar_url, created_at FROM users WHERE id = $1 LIMIT 1",
      [payload.sub]
    );

    if (!result.rows[0] || result.rows[0].status !== "ACTIVE") {
      return res.status(401).json({ error: "Usuário inválido ou bloqueado." });
    }

    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido ou expirado." });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "ADMIN") {
    return res.status(403).json({ error: "Acesso administrativo necessário." });
  }
  next();
}

app.get("/", (req, res) => {
  res.json({
    name: "Arte Fácil API",
    version: "1.0.0",
    status: "online",
    health: "/health",
  });
});

app.get("/health", async (req, res) => {

  try {

    await pool.query("SELECT 1");

    res.json({ ok: true, database: "connected" });

  } catch (err) {

    console.error("ERRO DATABASE:", err.message);

    res.status(503).json({

      ok: false,

      database: "error",

      message: err.message,

    });

  }

});

app.post("/auth/register", authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Nome, e-mail e senha são obrigatórios." });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "A senha deve ter pelo menos 8 caracteres." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const exists = await pool.query(
      "SELECT id FROM users WHERE email = $1 LIMIT 1",
      [normalizedEmail]
    );
    if (exists.rows.length) {
      return res.status(409).json({ error: "Este e-mail já está cadastrado." });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, status)
       VALUES ($1, $2, $3, 'FREE', 'ACTIVE')
       RETURNING id, name, email, role, status, avatar_url, created_at`,
      [String(name).trim(), normalizedEmail, passwordHash]
    );

    const user = result.rows[0];
    const token = signToken(user);

    res.status(201).json({ user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao criar conta." });
  }
});

app.post("/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "E-mail e senha são obrigatórios." });
    }

    const result = await pool.query(
      `SELECT id, name, email, password_hash, role, status, avatar_url, created_at
       FROM users WHERE email = $1 LIMIT 1`,
      [String(email).trim().toLowerCase()]
    );

    const user = result.rows[0];
    if (!user || user.status !== "ACTIVE") {
      return res.status(401).json({ error: "E-mail ou senha inválidos." });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: "E-mail ou senha inválidos." });
    }

    await pool.query("UPDATE users SET last_login_at = NOW() WHERE id = $1", [user.id]);

    delete user.password_hash;
    const token = signToken(user);

    res.json({ user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao entrar." });
  }
});

app.get("/auth/me", auth, (req, res) => {
  res.json({ user: req.user });
});

app.post("/auth/logout", auth, (req, res) => {
  res.json({ ok: true });
});

app.get("/categories", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, slug, description, icon_url, sort_order, active
       FROM categories WHERE active = TRUE ORDER BY sort_order, name`
    );
    res.json({ categories: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Erro ao carregar categorias." });
  }
});

app.get("/templates", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.id, t.name, t.slug, t.description, t.category_id,
              t.access_level, t.status, t.thumbnail_url, t.width, t.height,
              c.name AS category_name
       FROM templates t
       LEFT JOIN categories c ON c.id = t.category_id
       WHERE t.status = 'PUBLISHED'
       ORDER BY t.created_at DESC`
    );
    res.json({ templates: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Erro ao carregar templates." });
  }
});

app.get("/templates/:id", async (req, res) => {
  try {
    const template = await pool.query(
      `SELECT t.*, c.name AS category_name
       FROM templates t
       LEFT JOIN categories c ON c.id = t.category_id
       WHERE t.id = $1 LIMIT 1`,
      [req.params.id]
    );

    if (!template.rows[0]) return res.status(404).json({ error: "Template não encontrado." });

    const elements = await pool.query(
      `SELECT * FROM template_elements
       WHERE template_id = $1
       ORDER BY z_index ASC`,
      [req.params.id]
    );

    res.json({ template: template.rows[0], elements: elements.rows });
  } catch (err) {
    res.status(500).json({ error: "Erro ao carregar template." });
  }
});

app.get("/projects", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, template_id, width, height, status,
              thumbnail_url, created_at, updated_at
       FROM projects
       WHERE user_id = $1
       ORDER BY updated_at DESC`,
      [req.user.id]
    );
    res.json({ projects: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Erro ao carregar projetos." });
  }
});

app.post("/projects", auth, async (req, res) => {
  try {
    const { name, template_id, width, height, canvas_data, thumbnail_url, status } = req.body || {};

    const result = await pool.query(
      `INSERT INTO projects
       (user_id, name, template_id, width, height, canvas_data, thumbnail_url, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        req.user.id,
        name || "Meu projeto",
        template_id || null,
        width || 1080,
        height || 1350,
        canvas_data || {},
        thumbnail_url || null,
        status || "DRAFT",
      ]
    );

    res.status(201).json({ project: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao criar projeto." });
  }
});

app.get("/projects/:id", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM projects WHERE id = $1 AND user_id = $2 LIMIT 1",
      [req.params.id, req.user.id]
    );

    if (!result.rows[0]) return res.status(404).json({ error: "Projeto não encontrado." });
    res.json({ project: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Erro ao carregar projeto." });
  }
});

app.put("/projects/:id", auth, async (req, res) => {
  try {
    const { name, canvas_data, thumbnail_url, status } = req.body || {};

    const result = await pool.query(
      `UPDATE projects
       SET name = COALESCE($1, name),
           canvas_data = COALESCE($2, canvas_data),
           thumbnail_url = COALESCE($3, thumbnail_url),
           status = COALESCE($4, status),
           updated_at = NOW()
       WHERE id = $5 AND user_id = $6
       RETURNING *`,
      [name ?? null, canvas_data ?? null, thumbnail_url ?? null, status ?? null, req.params.id, req.user.id]
    );

    if (!result.rows[0]) return res.status(404).json({ error: "Projeto não encontrado." });
    res.json({ project: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao salvar projeto." });
  }
});

app.delete("/projects/:id", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM projects WHERE id = $1 AND user_id = $2 RETURNING id",
      [req.params.id, req.user.id]
    );

    if (!result.rows[0]) return res.status(404).json({ error: "Projeto não encontrado." });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Erro ao excluir projeto." });
  }
});

app.get("/favorites", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT f.id, f.template_id, f.created_at,
              t.name, t.slug, t.thumbnail_url, t.access_level
       FROM favorites f
       JOIN templates t ON t.id = f.template_id
       WHERE f.user_id = $1
       ORDER BY f.created_at DESC`,
      [req.user.id]
    );
    res.json({ favorites: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Erro ao carregar favoritos." });
  }
});

app.post("/favorites/:templateId", auth, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO favorites (user_id, template_id)
       VALUES ($1, $2)
       ON CONFLICT (user_id, template_id) DO NOTHING`,
      [req.user.id, req.params.templateId]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Erro ao adicionar favorito." });
  }
});

app.delete("/favorites/:templateId", auth, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM favorites WHERE user_id = $1 AND template_id = $2",
      [req.user.id, req.params.templateId]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Erro ao remover favorito." });
  }
});

app.get("/admin/dashboard", auth, adminOnly, async (req, res) => {
  try {
    const [users, templates, projects] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS total FROM users"),
      pool.query("SELECT COUNT(*)::int AS total FROM templates"),
      pool.query("SELECT COUNT(*)::int AS total FROM projects"),
    ]);

    res.json({
      users: users.rows[0].total,
      templates: templates.rows[0].total,
      projects: projects.rows[0].total,
    });
  } catch (err) {
    res.status(500).json({ error: "Erro no painel administrativo." });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: "Rota não encontrada." });
});

app.listen(PORT, () => {
  console.log(`Arte Fácil API rodando na porta ${PORT}`);
});
