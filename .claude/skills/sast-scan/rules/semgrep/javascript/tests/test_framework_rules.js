// ruleid: js.security.express-debug-mode
app.set("show stack error", true)

// ok: js.security.express-debug-mode
app.set("env", process.env.NODE_ENV)

// ruleid: js.security.express-cors-wildcard
app.use(cors({ origin: "*" }))

// ok: js.security.express-cors-wildcard
app.use(cors({ origin: ["https://app.example.com"] }))

// ruleid: js.security.express-helmet-missing
const insecureApp = express()

// ok: js.security.express-helmet-missing
const secureApp = express()
secureApp.use(helmet())

// ruleid: js.security.cookie-secure-false
res.cookie("sid", token, { secure: false })

// ok: js.security.cookie-secure-false
res.cookie("sid", token, { secure: true })

// ruleid: js.security.cookie-httponly-false
res.cookie("sid", token, { httpOnly: false })

// ok: js.security.cookie-httponly-false
res.cookie("sid", token, { httpOnly: true })

// ruleid: js.security.jwt-none-algorithm
jwt.verify(token, secret, { algorithms: ["none"] })

// ok: js.security.jwt-none-algorithm
jwt.verify(token, secret, { algorithms: ["HS256"] })
