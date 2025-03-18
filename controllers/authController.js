// controllers/authController.js
const db = require("../db");
const bcrypt = require("bcrypt");

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const [user] = await db.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (!user.length) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    const isValidPassword = await bcrypt.compare(password, user[0].password);
    if (!isValidPassword) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid password" });
    }
    res
      .status(200)
      .json({ success: true, message: "Login successful", user: user[0] });
  } catch (error) {
    console.error("❌ Error in login:", error);
    res
      .status(500)
      .json({ success: false, message: "Server error", error: error.message });
  }
};

exports.register = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      "INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
      [email, hashedPassword, name]
    );
    res
      .status(201)
      .json({
        success: true,
        message: "User registered",
        userId: result.insertId,
      });
  } catch (error) {
    console.error("❌ Error in registration:", error);
    res
      .status(500)
      .json({ success: false, message: "Server error", error: error.message });
  }
};
