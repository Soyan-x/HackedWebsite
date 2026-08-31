require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const { Resend } = require("resend");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const path = require("path");

const app = express();


// =========================
// TRUST PROXY - RENDER
// =========================

app.set("trust proxy", 1);


// =========================
// DATABASE
// =========================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === "production"
        ? { rejectUnauthorized: false }
        : false
});


// =========================
// MIDDLEWARE
// =========================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// =========================
// SESSION
// =========================

app.use(
    session({
        store: new pgSession({
            pool: pool,
            tableName: "user_sessions",
            createTableIfMissing: true
        }),

        secret: process.env.SESSION_SECRET,

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 1000 * 60 * 60 * 24
        }
    })
);


// =========================
// STATIC FILES
// =========================

app.use(express.static(path.join(__dirname, "public")));


// =========================
// RESEND
// =========================

const resend = new Resend(process.env.RESEND_API_KEY);


// =========================
// GENERATE VERIFICATION CODE
// =========================

function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}


// =========================
// SIGNUP
// =========================

app.post("/api/signup", async (req, res) => {

    try {

        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "All fields are required"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: "Password must be at least 6 characters"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const existingUser = await pool.query(
            "SELECT id, email_verified FROM users WHERE email = $1",
            [normalizedEmail]
        );

        if (existingUser.rows.length > 0) {

            if (existingUser.rows[0].email_verified) {
                return res.status(400).json({
                    message: "Email already registered"
                });
            }

            return res.status(400).json({
                message: "Email already waiting for verification"
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const verificationCode = generateCode();

        await pool.query(
            `INSERT INTO users
            (name, email, password_hash, verification_code, verification_expires)
            VALUES ($1, $2, $3, $4, NOW() + INTERVAL '10 minutes')`,
            [
                name.trim(),
                normalizedEmail,
                passwordHash,
                verificationCode
            ]
        );


        // =========================
        // SEND VERIFICATION EMAIL
        // =========================

        const { data, error } = await resend.emails.send({
            from: process.env.EMAIL_FROM || "onboarding@resend.dev",
            to: [normalizedEmail],
            subject: "Your Verification Code",
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>Email Verification</h2>

                    <p>Hello ${name.trim()},</p>

                    <p>Your verification code is:</p>

                    <h1 style="letter-spacing: 5px;">
                        ${verificationCode}
                    </h1>

                    <p>
                        This code will expire in 10 minutes.
                    </p>

                    <p>
                        If you did not create this account,
                        you can ignore this email.
                    </p>
                </div>
            `
        });


        if (error) {

            console.error("Resend error:", error);

            // Email পাঠানো না গেলে temporary user record delete
            await pool.query(
                "DELETE FROM users WHERE email = $1 AND email_verified = FALSE",
                [normalizedEmail]
            );

            return res.status(500).json({
                message: "Could not send verification email"
            });
        }


        console.log("Verification email sent:", data);


        res.json({
            success: true,
            message: "Verification code sent to your email"
        });


    } catch (error) {

        console.error("Signup error:", error);

        res.status(500).json({
            message: "Server error"
        });
    }
});


// =========================
// VERIFY EMAIL
// =========================

app.post("/api/verify", async (req, res) => {

    try {

        const { email, code } = req.body;

        if (!email || !code) {
            return res.status(400).json({
                message: "Email and verification code are required"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const result = await pool.query(
            `SELECT *
             FROM users
             WHERE email = $1
             AND verification_code = $2
             AND verification_expires > NOW()`,
            [
                normalizedEmail,
                code
            ]
        );


        if (result.rows.length === 0) {

            return res.status(400).json({
                message: "Invalid or expired verification code"
            });
        }


        await pool.query(
            `UPDATE users
             SET email_verified = TRUE,
                 verification_code = NULL,
                 verification_expires = NULL
             WHERE email = $1`,
            [normalizedEmail]
        );


        res.json({
            success: true,
            message: "Email verified successfully"
        });


    } catch (error) {

        console.error("Verification error:", error);

        res.status(500).json({
            message: "Server error"
        });
    }
});


// =========================
// LOGIN
// =========================

app.post("/api/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        if (!email || !password) {

            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const result = await pool.query(
            "SELECT * FROM users WHERE email = $1",
            [normalizedEmail]
        );


        if (result.rows.length === 0) {

            return res.status(401).json({
                message: "Invalid email or password"
            });
        }


        const user = result.rows[0];


        if (!user.email_verified) {

            return res.status(403).json({
                message: "Please verify your email first"
            });
        }


        const passwordMatch = await bcrypt.compare(
            password,
            user.password_hash
        );


        if (!passwordMatch) {

            return res.status(401).json({
                message: "Invalid email or password"
            });
        }


        // =========================
        // CREATE LOGIN SESSION
        // =========================

        req.session.userId = user.id;


        // IMPORTANT:
        // Explicitly save session before sending response

        req.session.save((error) => {

            if (error) {

                console.error("Session save error:", error);

                return res.status(500).json({
                    message: "Could not create login session"
                });
            }


            res.json({
                success: true,
                message: "Login successful"
            });

        });


    } catch (error) {

        console.error("Login error:", error);

        res.status(500).json({
            message: "Server error"
        });
    }
});


// =========================
// SESSION CHECK
// =========================

app.get("/api/session", async (req, res) => {

    try {

        if (!req.session.userId) {

            return res.status(401).json({
                success: false,
                loggedIn: false
            });
        }


        const result = await pool.query(
            `SELECT id, name, email
             FROM users
             WHERE id = $1`,
            [req.session.userId]
        );


        if (result.rows.length === 0) {

            return res.status(401).json({
                success: false,
                loggedIn: false
            });
        }


        res.json({
            success: true,
            loggedIn: true,
            user: result.rows[0]
        });


    } catch (error) {

        console.error("Session check error:", error);

        res.status(500).json({
            success: false,
            loggedIn: false,
            message: "Server error"
        });
    }
});


// =========================
// CURRENT USER
// =========================

app.get("/api/me", async (req, res) => {

    try {

        if (!req.session.userId) {

            return res.status(401).json({
                message: "Not logged in"
            });
        }


        const result = await pool.query(
            `SELECT id, name, email
             FROM users
             WHERE id = $1`,
            [req.session.userId]
        );


        if (result.rows.length === 0) {

            return res.status(401).json({
                message: "User not found"
            });
        }


        res.json({
            success: true,
            user: result.rows[0]
        });


    } catch (error) {

        console.error("Current user error:", error);

        res.status(500).json({
            message: "Server error"
        });
    }
});


// =========================
// LOGOUT
// =========================

app.post("/api/logout", (req, res) => {

    req.session.destroy((error) => {

        if (error) {

            console.error("Logout error:", error);

            return res.status(500).json({
                message: "Logout failed"
            });
        }


        res.clearCookie("connect.sid");

        res.json({
            success: true,
            message: "Logged out"
        });

    });
});


// =========================
// DATABASE TEST
// =========================

pool.connect()
    .then((client) => {

        console.log("Database connected");

        client.release();

    })
    .catch((error) => {

        console.error("Database connection failed:", error);

    });


// =========================
// START SERVER
// =========================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {

    console.log(
        `Server running on http://localhost:${PORT}`
    );

});
