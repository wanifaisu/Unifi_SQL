const express = require("express");
const jwt = require("jsonwebtoken");
const db = require("../db"); // Import MySQL connection
const bcrypt = require("bcrypt"); // For comparing hashed SSN
const dotenv = require("dotenv");
const moment = require("moment");

dotenv.config();
const router = express.Router();

// Login endpoint
router.post("/", async (req, res) => {
  const { lastName, dob, fourDigitSSN } = req.body;
  console.log(req.body, " req.body");

  try {
    if (!lastName || !dob || !fourDigitSSN) {
      return res
        .status(400)
        .json({ message: "All fields are required", status: false });
    }

    const inputMonthYear = moment(dob, "YYYY-MM-DD").format("MM-YYYY");

    // Fetch contacts with the given last name
    const [contacts] = await db.query(
      "SELECT * FROM contacts WHERE lastName = ?",
      [lastName]
    );

    if (!contacts.length) {
      return res
        .status(400)
        .json({ message: "Invalid credentials", status: false });
    }

    // Find a contact with matching date of birth (month and year)
    const contact = contacts.find((c) => {
      if (!c.dateOfBirth) return false;
      const contactMonthYear = moment(c.dateOfBirth).format("MM-YYYY");
      return contactMonthYear === inputMonthYear;
    });

    if (!contact) {
      return res
        .status(400)
        .json({ message: "Invalid credentials", status: false });
    }

    if (!contact.hashedFour) {
      return res.status(400).json({ message: "SSN not found", status: false });
    }

    // Compare the last 4 digits of SSN
    const isMatch = await bcrypt.compare(fourDigitSSN, contact.hashedFour);
    if (!isMatch) {
      return res
        .status(400)
        .json({ message: "Invalid credentials", status: false });
    }

    // Generate JWT token including contactId and email
    const token = jwt.sign(
      { contactId: contact.id, email: contact.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Login successful",
      token,
      contact_id: contact.contact_id,
      status: true,
    });
  } catch (error) {
    console.error("Error during login:", error.message);
    res.status(500).json({ message: "Server error", status: false });
  }
});

module.exports = router;
