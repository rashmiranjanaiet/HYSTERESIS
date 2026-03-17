const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { URL } = require("node:url");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const { MongoClient, ObjectId } = require("mongodb");

dotenv.config();

const ROOT_DIR = __dirname;
const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.HOST || "0.0.0.0";
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || "hysteresis_auth";
const JWT_SECRET = process.env.JWT_SECRET || "change-me";

const mongoClient = MONGODB_URI ? new MongoClient(MONGODB_URI) : null;
let usersCollection;

const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".webp": "image/webp",
};

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

function resolvePath(urlPath) {
  const pathname = decodeURIComponent(urlPath.split("?")[0]);
  const requestPath = pathname === "/" ? "/index.html" : pathname;
  const fullPath = path.normalize(path.join(ROOT_DIR, requestPath));

  if (!fullPath.startsWith(ROOT_DIR)) {
    return null;
  }

  return fullPath;
}

function sendFile(res, filePath) {
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not Found");
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType =
      MIME_TYPES[ext] || "application/octet-stream; charset=utf-8";
    res.writeHead(200, { "Content-Type": contentType });
    res.end(content);
  });
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let rawBody = "";
    req.on("data", (chunk) => {
      rawBody += chunk;
      if (rawBody.length > 1_000_000) {
        reject(new Error("Payload too large"));
      }
    });
    req.on("end", () => {
      if (!rawBody) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(rawBody));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function buildToken(user) {
  return jwt.sign(
    {
      sub: String(user._id),
      email: user.email,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function sanitizeUser(user) {
  return {
    id: String(user._id),
    name: user.name || "",
    email: user.email,
    createdAt: user.createdAt,
  };
}

async function authenticateRequest(req) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return null;
  }

  const token = authHeader.slice("Bearer ".length);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await usersCollection.findOne({
      _id: new ObjectId(String(payload.sub)),
    });
    return user || null;
  } catch {
    return null;
  }
}

async function handleAuthApi(req, res, pathname) {
  if (!usersCollection) {
    sendJson(res, 500, { error: "Database not connected" });
    return true;
  }

  if (pathname === "/api/health" && req.method === "GET") {
    sendJson(res, 200, { ok: true });
    return true;
  }

  if (pathname === "/api/auth/register" && req.method === "POST") {
    const body = await readJsonBody(req);
    const name = String(body.name || "").trim();
    const email = String(body.email || "")
      .trim()
      .toLowerCase();
    const password = String(body.password || "");

    if (!email || !password) {
      sendJson(res, 400, { error: "Email and password are required" });
      return true;
    }

    if (password.length < 6) {
      sendJson(res, 400, { error: "Password must be at least 6 characters" });
      return true;
    }

    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      sendJson(res, 409, { error: "User already exists" });
      return true;
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const userDoc = {
      name,
      email,
      passwordHash,
      createdAt: new Date(),
    };
    const insertResult = await usersCollection.insertOne(userDoc);
    const user = { ...userDoc, _id: insertResult.insertedId };
    const token = buildToken(user);
    sendJson(res, 201, { token, user: sanitizeUser(user) });
    return true;
  }

  if (pathname === "/api/auth/login" && req.method === "POST") {
    const body = await readJsonBody(req);
    const email = String(body.email || "")
      .trim()
      .toLowerCase();
    const password = String(body.password || "");

    if (!email || !password) {
      sendJson(res, 400, { error: "Email and password are required" });
      return true;
    }

    const user = await usersCollection.findOne({ email });
    if (!user) {
      sendJson(res, 401, { error: "Invalid email or password" });
      return true;
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatches) {
      sendJson(res, 401, { error: "Invalid email or password" });
      return true;
    }

    const token = buildToken(user);
    sendJson(res, 200, { token, user: sanitizeUser(user) });
    return true;
  }

  if (pathname === "/api/auth/me" && req.method === "GET") {
    const user = await authenticateRequest(req);
    if (!user) {
      sendJson(res, 401, { error: "Unauthorized" });
      return true;
    }

    sendJson(res, 200, { user: sanitizeUser(user) });
    return true;
  }

  if (pathname.startsWith("/api/")) {
    sendJson(res, 404, { error: "API route not found" });
    return true;
  }

  return false;
}

const server = http.createServer(async (req, res) => {
  try {
    const requestUrl = new URL(
      req.url || "/",
      `http://${req.headers.host || "localhost"}`
    );
    const pathname = requestUrl.pathname;

    const apiHandled = await handleAuthApi(req, res, pathname);
    if (apiHandled) {
      return;
    }

    const fullPath = resolvePath(pathname);
    if (!fullPath) {
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Bad Request");
      return;
    }

    fs.stat(fullPath, (err, stats) => {
      if (!err && stats.isFile()) {
        sendFile(res, fullPath);
        return;
      }

      const hasExtension = path.extname(fullPath) !== "";
      if (!hasExtension) {
        sendFile(res, path.join(ROOT_DIR, "index.html"));
        return;
      }

      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not Found");
    });
  } catch (error) {
    if (error && error.message === "Payload too large") {
      sendJson(res, 413, { error: "Payload too large" });
      return;
    }
    if (error && error.message === "Invalid JSON body") {
      sendJson(res, 400, { error: "Invalid JSON body" });
      return;
    }
    if (error && error.code === 11000) {
      sendJson(res, 409, { error: "User already exists" });
      return;
    }
    console.error(error);
    sendJson(res, 500, { error: "Internal server error" });
  }
});

server.on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error(
      `Port ${PORT} is already in use. Stop the old server or run: set PORT=4174 && npm start`
    );
    process.exit(1);
  }

  console.error(error);
  process.exit(1);
});

async function startServer() {
  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI is missing. Set it in .env");
  }

  await mongoClient.connect();
  const db = mongoClient.db(MONGODB_DB);
  usersCollection = db.collection("users");
  await usersCollection.createIndex({ email: 1 }, { unique: true });

  server.listen(PORT, HOST, () => {
    console.log(`Hysteresis clone running at http://localhost:${PORT}`);
  });
}

startServer().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
