// middleware/auth.js
import jwt from "jsonwebtoken";

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

// Middleware: verifica autenticazione e ruolo admin
export function verifyAdmin(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ error: "Token mancante" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Token non valido" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded.is_admin) {
      return res.status(403).json({ error: "Accesso negato: non sei admin" });
    }

    // Se ok → passo al controller
    req.user = decoded;
    next();
  } catch (err) {
    console.error(err);
    return res.status(403).json({ error: "Token non valido o scaduto" });
  }
}
