import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();
const app = express();
app.use(cors({
  origin: "https://gilded-jelly-096e79.netlify.app",
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"]
}));
app.options("*", cors()); // 👈 aggiunto per preflight
app.use(bodyParser.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET || "supersegreto123";

// Middleware auth
function auth(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Token mancante" });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: "Token non valido" });
    }
}

// Registrazione utente
app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    try {
        await pool.query(
            "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
            [username, hash]
        );
        res.json({ message: "Utente creato" });
    } catch (err) {
        res.status(400).json({ error: "Username già esistente" });
    }
});

// Login
app.post("/login", async (req, res) => {
    console.log(">>> Richiesta LOGIN ricevuta", req.body); // 👈 debug
    const { username, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Credenziali errate" });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Credenziali errate" });
    const token = jwt.sign({
        id: user.id,
        username: user.username,
        is_admin: user.is_admin
    }, JWT_SECRET);
    res.json({ token });
});

// Inserisci pronostico
app.post("/matches/:id/predictions", auth, async (req, res) => {
    const { id } = req.params;
    const { home_score, away_score, scorer } = req.body;

    const match = await pool.query("SELECT * FROM matches WHERE id=$1", [id]);
    if (!match.rows.length) return res.status(404).json({ error: "Partita non trovata" });
    if (match.rows[0].finished) return res.status(400).json({ error: "Partita già terminata" });

    const existing = await pool.query(
        "SELECT * FROM predictions WHERE match_id=$1 AND user_id=$2",
        [id, req.user.id]
    );
    if (existing.rows.length > 0) {
        return res.status(400).json({ error: "Pronostico già inserito" });
    }

    await pool.query(
        "INSERT INTO predictions (match_id, user_id, home_score, away_score, scorer) VALUES ($1,$2,$3,$4,$5)",
        [id, req.user.id, home_score, away_score, scorer]
    );
    res.json({ message: "Pronostico salvato" });
});

// Inserimento risultato ufficiale (solo admin)
app.post("/matches/:id/result", auth, async (req, res) => {
    if (!req.user.is_admin) return res.status(403).json({ error: "Non autorizzato" });
    const { id } = req.params;
    const { home_score, away_score } = req.body;

    await pool.query(
        "UPDATE matches SET home_score=$1, away_score=$2, finished=true WHERE id=$3",
        [home_score, away_score, id]
    );

    const preds = await pool.query("SELECT * FROM predictions WHERE match_id=$1", [id]);
    for (let pred of preds.rows) {
        let points = 0;
        if (pred.home_score === home_score && pred.away_score === away_score) {
            points = 5;
        }
        await pool.query("UPDATE predictions SET points=$1 WHERE id=$2", [points, pred.id]);
    }

    res.json({ message: "Risultato ufficiale inserito, punteggi aggiornati" });
});

// Classifica
app.get("/leaderboard", auth, async (req, res) => {
    const board = await pool.query(`
        SELECT u.username, COALESCE(SUM(p.points),0) as total_points
        FROM users u
        LEFT JOIN predictions p ON u.id = p.user_id
        GROUP BY u.username
        ORDER BY total_points DESC
    `);
    res.json(board.rows);
});

// Mostra pronostici (tutti visibili se partita finita)
app.get("/matches/:id/predictions", auth, async (req, res) => {
    const match = await pool.query("SELECT * FROM matches WHERE id=$1", [req.params.id]);
    if (!match.rows.length) return res.status(404).json({ error: "Partita non trovata" });

    const finished = match.rows[0].finished;
    if (finished) {
        const preds = await pool.query(`
            SELECT u.username, p.home_score, p.away_score, p.scorer, p.points
            FROM predictions p
            JOIN users u ON p.user_id = u.id
            WHERE p.match_id=$1
        `, [req.params.id]);
        res.json(preds.rows);
    } else {
        const pred = await pool.query(`
            SELECT home_score, away_score, scorer
            FROM predictions
            WHERE match_id=$1 AND user_id=$2
        `, [req.params.id, req.user.id]);
        res.json(pred.rows);
    }
});

app.listen(3000, () => console.log("Server avviato"));

// Crea una nuova partita (solo admin)
app.post("/matches", auth, async (req, res) => {
    if (!req.user.is_admin) {
        return res.status(403).json({ error: "Non autorizzato" });
    }
    const { date, home_team, away_team } = req.body;

    try {
        const result = await pool.query(
            "INSERT INTO matches (date, home_team, away_team) VALUES ($1, $2, $3) RETURNING *",
            [date, home_team, away_team]
        );
        res.json({ message: "Partita creata", match: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Errore creazione partita" });
    }
});
