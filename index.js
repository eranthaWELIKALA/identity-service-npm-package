// identity-service/index.js
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const mongoose = require("mongoose");
const { Sequelize, DataTypes } = require("sequelize");
require("dotenv").config();

const SECRET_KEY = process.env.WELIKALA_IDS_JWT_SECRET || "your-secret-key";
const DB_TYPE = process.env.WELIKALA_IDS_DB_TYPE || "mongodb";
const LOGIN_METHOD = process.env.WELIKALA_IDS_LOGIN_METHOD || "password";
const OTP_LENGTH = parseInt(process.env.WELIKALA_IDS_OTP_LENGTH, 10) || 6;

let db;

if (DB_TYPE === "mongodb") {
    const DB_CONFIG = {
        uri: process.env.WELIKALA_IDS_DB_URI,
        user: process.env.WELIKALA_IDS_DB_USER || "",
        pass: process.env.WELIKALA_IDS_DB_PASS || "",
        dbName: process.env.WELIKALA_IDS_DB_NAME || "",
        authSource: process.env.WELIKALA_IDS_DB_AUTH_SOURCE || "admin",
        useNewUrlParser: true,
        useUnifiedTopology: true,
    };

    mongoose
        .connect(DB_CONFIG.uri, {
            user: DB_CONFIG.user,
            pass: DB_CONFIG.pass,
            dbName: DB_CONFIG.dbName,
            authSource: DB_CONFIG.authSource,
            useNewUrlParser: DB_CONFIG.useNewUrlParser,
            useUnifiedTopology: DB_CONFIG.useUnifiedTopology,
        })
        .then(() => console.log("WELIKALA_IDS: MongoDB connected successfully"))
        .catch((err) => console.error("WELIKALA_IDS: MongoDB connection error:", err));

    const userSchema = new mongoose.Schema({
        username: { type: String, unique: true, required: true },
        password: { type: String, required: true },
        role: { type: String, default: "user" },
    });

    const otpSchema = new mongoose.Schema({
        username: { type: String, required: true },
        otp: { type: String, required: true },
        createdAt: { type: Date, default: Date.now, expires: 300 },
    });

    db = {
        User: mongoose.model("User", userSchema),
        OTP: mongoose.model("OTP", otpSchema),
    };
} else {
    const sequelize = new Sequelize(process.env.WELIKALA_IDS_DB_URI, {
        dialect: DB_TYPE,
        logging: false,
    });

    const User = sequelize.define("User", {
        id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
        username: { type: DataTypes.STRING, unique: true, allowNull: false },
        password: { type: DataTypes.STRING, allowNull: false },
        role: { type: DataTypes.STRING, defaultValue: "user" },
    });

    const OTP = sequelize.define(
        "OTP",
        {
            id: {
                type: DataTypes.INTEGER,
                primaryKey: true,
                autoIncrement: true,
            },
            username: { type: DataTypes.STRING, allowNull: false },
            otp: { type: DataTypes.STRING, allowNull: false },
            createdAt: { type: DataTypes.DATE, defaultValue: Sequelize.NOW },
        },
        { timestamps: false }
    );

    sequelize
        .sync()
        .then(() => console.log("WELIKALA_IDS: SQL Database synced"))
        .catch((err) => console.error("WELIKALA_IDS: SQL sync error:", err));

    db = { User, OTP };
}

const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};

const verifyPassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

const generateToken = (username, role = "user") => {
    return jwt.sign({ username, role }, SECRET_KEY, { expiresIn: "1h" });
};

const verifyToken = (token) => {
    try {
        return jwt.verify(token, SECRET_KEY);
    } catch (err) {
        return null;
    }
};

const generateOtp = () => {
    return crypto
        .randomInt(10 ** (OTP_LENGTH - 1), 10 ** OTP_LENGTH)
        .toString();
};

const register = async (username, password, role = "user") => {
    const existingUser =
        DB_TYPE === "mongodb"
            ? await db.User.findOne({ username })
            : await db.User.findOne({ where: { username } });

    if (existingUser) throw new Error("User already exists");
    const hashedPassword = await hashPassword(password);
    await db.User.create({ username, password: hashedPassword, role });
    return { message: "WELIKALA_IDS: User registered successfully" };
};

const authenticate = async (username, password, otp = null) => {
    const user =
        DB_TYPE === "mongodb"
            ? await db.User.findOne({ where: { username } })
            : await db.User.findOne({ username });
    if (!user) throw new Error("WELIKALA_IDS: User not found");

    if (LOGIN_METHOD === "password" || LOGIN_METHOD === "password_otp") {
        if (!(await verifyPassword(password, user.password)))
            throw new Error("WELIKALA_IDS: Invalid password");
    }

    if (LOGIN_METHOD === "otp" || LOGIN_METHOD === "password_otp") {
        const storedOtp =
            DB_TYPE === "mongodb"
                ? await db.OTP.findOne({ username, otp })
                : await db.OTP.findOne({ where: { username, otp } });
        if (!storedOtp) throw new Error("WELIKALA_IDS: Invalid OTP");

        DB_TYPE === "mongodb"
            ? await db.OTP.deleteOne({ username })
            : await db.OTP.destroy({ where: { username } });
    }

    return { token: generateToken(username, user.role) };
};

const requestOtp = async (username) => {
    const user =
        DB_TYPE === "mongodb"
            ? await db.User.findOne({ username })
            : await db.User.findOne({ where: { username } });
    if (!user) throw new Error("WELIKALA_IDS: User not found");
    const otp = generateOtp();
    DB_TYPE === "mongodb"
        ? await db.OTP.updateOne(
              { username },
              { $set: { otp, createdAt: new Date() } },
              { upsert: true }
          )
        : await db.OTP.upsert(
              { username, otp, createdAt: new Date() },
              { where: { username } }
          );

    console.log(`WELIKALA_IDS: OTP for ${username}: ${otp}`);
    return { message: "WELIKALA_IDS: OTP sent successfully" };
};

module.exports = { register, authenticate, requestOtp, verifyToken };
