// routes/webhookRoutes.js
const express = require("express");
const db = require("../db"); // Import MySQL connection
const bcrypt = require("bcrypt"); // For hashing SSNs
const router = express.Router();

// Webhook endpoint for GHL
router.post("/", async (req, res) => {
  try {
    const contacts = Array.isArray(req.body) ? req.body : [req.body];

    for (let data of contacts) {
      const rawSSN = data["Social security Number"];
      let hashedSSN = "";
      let ssnLastFourHash = "";

      if (rawSSN) {
        const salt = await bcrypt.genSalt(10);
        hashedSSN = await bcrypt.hash(rawSSN.toString(), salt);
        const lastFourSSN = rawSSN.toString().slice(-4);
        ssnLastFourHash = await bcrypt.hash(lastFourSSN, salt);
      }

      const contactData = {
        contact_id: data.contact_id || "",
        locationId: data.locationId || "",
        contactName: data.full_name || "",
        firstName: data.first_name || "",
        lastName: data.last_name || "",
        companyName: data.companyName || "",
        email: data.email,
        phone: data.phone || "",
        dnd: data.dnd || false,
        type: data.type || "",
        source: data.source || "",
        assignedTo: data.assignedTo || "",
        city: data.city || "",
        state: data.state || "",
        postalCode: data.postalCode || "",
        address1: data.address1 || "",
        dateAdded: data.date_created || new Date(),
        dateUpdated: new Date(),
        dateOfBirth: data.date_of_birth || null,
        tags: JSON.stringify(data.tags || []), // Store tags as JSON
        country: data.country || "",
        website: data.website || "",
        timezone: data.timezone || "",
        ssn: hashedSSN || "",
        hashedFour: ssnLastFourHash || "",
        customField: JSON.stringify(data.customField || {}), // Store customField as JSON
      };

      try {
        // Check if the contact already exists
        const [existingContact] = await db.query(
          "SELECT * FROM contacts WHERE email = ?",
          [data.email]
        );

        if (existingContact.length > 0) {
          // Update existing contact
          await db.query(
            `UPDATE contacts SET
                            contact_id = ?, locationId = ?, contactName = ?, firstName = ?, lastName = ?,
                            companyName = ?, phone = ?, dnd = ?, type = ?, source = ?, assignedTo = ?,
                            city = ?, state = ?, postalCode = ?, address1 = ?, dateAdded = ?, dateUpdated = ?,
                            dateOfBirth = ?, tags = ?, country = ?, website = ?, timezone = ?, ssn = ?,
                            hashedFour = ?, customField = ?
                        WHERE email = ?`,
            [
              contactData.contact_id,
              contactData.locationId,
              contactData.contactName,
              contactData.firstName,
              contactData.lastName,
              contactData.companyName,
              contactData.phone,
              contactData.dnd,
              contactData.type,
              contactData.source,
              contactData.assignedTo,
              contactData.city,
              contactData.state,
              contactData.postalCode,
              contactData.address1,
              contactData.dateAdded,
              contactData.dateUpdated,
              contactData.dateOfBirth,
              contactData.tags,
              contactData.country,
              contactData.website,
              contactData.timezone,
              contactData.ssn,
              contactData.hashedFour,
              contactData.customField,
              data.email, // WHERE condition
            ]
          );
          console.log(`✅ Updated contact: ${data.email}`);
        } else {
          // Insert new contact
          await db.query(
            `INSERT INTO contacts (
                            contact_id, locationId, contactName, firstName, lastName,
                            companyName, email, phone, dnd, type, source, assignedTo,
                            city, state, postalCode, address1, dateAdded, dateUpdated,
                            dateOfBirth, tags, country, website, timezone, ssn,
                            hashedFour, customField
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              contactData.contact_id,
              contactData.locationId,
              contactData.contactName,
              contactData.firstName,
              contactData.lastName,
              contactData.companyName,
              contactData.email,
              contactData.phone,
              contactData.dnd,
              contactData.type,
              contactData.source,
              contactData.assignedTo,
              contactData.city,
              contactData.state,
              contactData.postalCode,
              contactData.address1,
              contactData.dateAdded,
              contactData.dateUpdated,
              contactData.dateOfBirth,
              contactData.tags,
              contactData.country,
              contactData.website,
              contactData.timezone,
              contactData.ssn,
              contactData.hashedFour,
              contactData.customField,
            ]
          );
          console.log(`✅ New contact added: ${data.email}`);
        }
      } catch (error) {
        console.error("❌ Error processing webhook:", error);
      }
    }

    res
      .status(200)
      .json({ success: true, message: "Webhook processed successfully" });
  } catch (error) {
    console.error("❌ Error processing webhook:", error);
    return res
      .status(500)
      .json({ success: false, message: "Server error", error: error.message });
  }
});

module.exports = router;
