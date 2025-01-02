const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session')
const customer_routes = require('./router/auth_users.js').authenticated;
const genl_routes = require('./router/general.js').general;

const app = express();

app.use(express.json());

app.use("/customer",session({secret:"fingerprint_customer",resave: true, saveUninitialized: true}))

app.use("/customer/auth/*", function auth(req,res,next){
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: "Authorization token is required" });
    }

    const token = authHeader.split(' ')[1]; // "Bearer <token>"

    if (!token) {
        return res.status(401).json({ message: "Token missing" });
    }

    jwt.verify(token, 'secretKey', (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Invalid or expired token" });
        }

        req.user = decoded; // You can access `req.user.username` later
        next(); // Pass control to the next middleware or route handler
    });
});
 
const PORT = 5000;

app.use("/customer", customer_routes);
app.use("/", genl_routes);

app.listen(PORT,()=>console.log("Server is running"));