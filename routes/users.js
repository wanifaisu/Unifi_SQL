// routes/users.js
const express = require("express");
const db = require("../db"); // Import database connection
const router = express.Router();

// Get all users
router.get("/", async (req, res) => {
  try {
    const [users] = await db.query("SELECT * FROM users");
    res.status(200).json({ success: true, users });
  } catch (error) {
    console.error("❌ Error fetching users:", error);
    res
      .status(500)
      .json({ success: false, message: "Server error", error: error.message });
  }
});

// Get a single user by ID
router.get("/:id", async (req, res) => {
  try {
    const [user] = await db.query("SELECT * FROM users WHERE id = ?", [
      req.params.id,
    ]);
    if (!user.length) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    res.status(200).json({ success: true, user: user[0] });
  } catch (error) {
    console.error("❌ Error fetching user:", error);
    res
      .status(500)
      .json({ success: false, message: "Server error", error: error.message });
  }
});

module.exports = router;
