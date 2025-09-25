import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import dotenv from "dotenv";
import cors from "cors";
import { verifyAdmin } from "./middleware/auth.js"; // <-- aggiungi questo

const app = express();
app.use(express.json());

dotenv.config();
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
export function auth(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader)
    return res.status(401).json({ error: "Token mancante" });

  const token = authHeader.split(" ")[1];
  if (!token)
    return res.status(401).json({ error: "Token non valido" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "fallback_secret");
    req.user = decoded; // 👈 qui salvo il payload
    next();
  } catch (err) {
    console.error("JWT error:", err);
    return res.status(403).json({ error: "Token non valido o scaduto" });
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
  const { username, password } = req.body;

  // recupera utente da DB
  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1",
    [username]
  );
  const user = result.rows[0];

  if (!user) {
    return res.status(400).json({ error: "Utente non trovato" });
  }

  // verifica password...
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: "Password errata" });
  }

  // qui setta anche il campo is_admin (esempio: true per un username o colonna DB)
  const token = jwt.sign(
    {
      id: user.id,
      username: user.username,
      is_admin: user.is_admin === true  // importante specificare
    },
    process.env.JWT_SECRET || "fallback_secret", // 👈 fallback se env mancante
    { expiresIn: "365d" }
  );

  res.json({ token });
});

// Inserisci pronostico
app.post("/matches/:id/predictions", auth, async (req, res) => {
  const { id } = req.params;
  const { home_score, away_score, scorer_id } = req.body;
  const userId = req.user.id;

  // controlla che scorer esista
  const scorerCheck = await pool.query("SELECT * FROM scorers WHERE id=$1", [scorer_id]);
  if (!scorerCheck.rows.length) {
    return res.status(400).json({ error: "Marcatore non valido" });
  }

  await pool.query(`
    INSERT INTO predictions (match_id, user_id, home_score, away_score, scorer_id)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (match_id, user_id)
    DO UPDATE SET home_score=EXCLUDED.home_score,
                  away_score=EXCLUDED.away_score,
                  scorer_id=EXCLUDED.scorer_id
  `, [id, userId, home_score, away_score, scorer_id]);

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

// GET /leaderboard
app.get('/leaderboard', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id as user_id,
        u.username,
        SUM(DISTINCT
          CASE 
            WHEN p.home_score = m.home_score AND p.away_score = m.away_score AND m.finished
              THEN 5 ELSE 0 
          END
        ) 
        + 
        SUM(
          CASE 
            WHEN ms.scorer_id = p.scorer_id AND m.finished
              THEN s.points ELSE 0
          END
        ) as points
      FROM users u
      LEFT JOIN predictions p ON u.id = p.user_id
      LEFT JOIN matches m ON m.id = p.match_id
      LEFT JOIN match_scorers ms ON ms.match_id = m.id
      LEFT JOIN scorers s ON s.id = p.scorer_id
      GROUP BY u.id, u.username
      ORDER BY points DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Errore calcolo classifica' });
  }
});

// Mostra pronostici (tutti visibili se partita finita)
app.get("/matches/:id/predictions", auth, async (req, res) => {
    const match = await pool.query("SELECT * FROM matches WHERE id=$1", [req.params.id]);
    if (!match.rows.length) return res.status(404).json({ error: "Partita non trovata" });

    const finished = match.rows[0].finished;
    if (finished) {
        const preds = await pool.query(`
            SELECT u.username, p.home_score, p.away_score, s.name as scorer, p.points
            FROM predictions p
            JOIN users u ON p.user_id = u.id
            JOIN scorers s ON p.scorer_id = s.id
            WHERE p.match_id=$1
        `, [req.params.id]);
        res.json(preds.rows);
    } else {
        const pred = await pool.query(`
            SELECT p.home_score, p.away_score, s.name as scorer
            FROM predictions p
            JOIN scorers s ON p.scorer_id = s.id
            WHERE p.match_id=$1 AND p.user_id=$2
        `, [req.params.id, req.user.id]);
        res.json(pred.rows);
    }
});

app.listen(3000, () => console.log("Server avviato"));

// POST /admin/matches
app.post('/admin/matches', verifyAdmin, async (req, res) => {
  const { home_team, away_team, date } = req.body;

  try {
    const result = await pool.query(
      `INSERT INTO matches (home_team, away_team, date) 
       VALUES ($1, $2, $3) RETURNING *`,
      [home_team, away_team, date]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Errore inserimento match' });
  }
});

// PUT /admin/matches/:id/result
app.put('/admin/matches/:id/result', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { home_score, away_score } = req.body;

  try {
    const result = await pool.query(
      `UPDATE matches 
       SET home_score = $1, away_score = $2, finished = true 
       WHERE id = $3 RETURNING *`,
      [home_score, away_score, id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Errore aggiornamento risultato' });
  }
});

// GET /matches → restituisce tutte le partite
app.get("/matches", async (req, res) => {
  try {
    const result = await pool.query(`SELECT m.*, COALESCE(string_agg(s.name, ', ' ORDER BY s.name), '') as scorers_names
    FROM matches m
      LEFT JOIN match_scorers ms ON ms.match_id = m.id
      LEFT JOIN scorers s ON s.id = ms.scorer_id
    GROUP BY m.id
    ORDER BY m.date ASC`);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Errore nel recupero partite" });
  }
});

// GET /matches/upcoming → restituisce tutte le partite future non concluse
app.get("/matches/upcoming", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM matches WHERE finished = false AND date > NOW() ORDER BY date ASC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Errore nel recupero partite future" });
  }
});

// GET /predictions/:match_id
app.get("/predictions/:match_id", auth, async (req, res) => {
  const userId = req.user.id; // se usi autenticazione JWT con req.user
  const { match_id } = req.params;

  try {
    // recupera la partita
    const matchRes = await pool.query("SELECT * FROM matches WHERE id = $1", [match_id]);
    const match = matchRes.rows[0];
    if (!match) return res.status(404).json({ error: "Partita non trovata" });

    // recupera i pronostici
    const predictionsRes = await pool.query(
      `SELECT u.username, p.*, s.name as scorer
            FROM predictions p
            JOIN users u ON p.user_id = u.id
            JOIN scorers s ON p.scorer_id = s.id
       WHERE p.match_id = $1`,
      [match_id]
    );
    const predictions = predictionsRes.rows;

    if (!match.finished) {
      // partita NON finita → restituisco SOLO il pronostico dell’utente corrente
      const myPrediction = predictions.find(p => p.user_id === userId);
      return res.json({ match, predictions: myPrediction ? [myPrediction] : [] });
    } else {
      // partita finita → restituisco TUTTI i pronostici
      return res.json({ match, predictions });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Errore recupero pronostici" });
  }
});

// Lista dei marcatori disponibili
app.get("/scorers", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, points FROM scorers ORDER BY name ASC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Errore caricamento scorers:", err);
    res.status(500).json({ error: "Errore nel recupero marcatori" });
  }
});


// POST /admin/matches/:id/scorers
app.post("/admin/matches/:id/scorers", verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { scorers } = req.body; // array di scorer_id

  try {
    // pulisci eventuali vecchi marcatori → reinserisci
    await pool.query("DELETE FROM match_scorers WHERE match_id=$1", [id]);

    for (const scorer_id of scorers) {
      await pool.query(
        "INSERT INTO match_scorers (match_id, scorer_id) VALUES ($1, $2)",
        [id, scorer_id]
      );
    }

    res.json({ message: "Marcatori aggiornati" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Errore assegnazione marcatori" });
  }
});
