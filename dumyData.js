const db = require("./db"); // Import MySQL connection
const bcrypt = require("bcrypt"); // For hashing SSN

async function insertDummyData() {
  try {
    // Hash the last 4 digits of the SSN
    const saltRounds = 10;
    const hashedFour = await bcrypt.hash("7890", saltRounds); // Replace '7890' with the actual last 4 digits

    const dummyData = {
      contact_id: "12345",
      locationId: "loc-001",
      contactName: "John Doe",
      firstName: "John",
      lastName: "wani", // Last name to be used in the login API
      companyName: "Doe Inc.",
      email: "asdfr.doe@example.com",
      phone: "1234567890",
      dnd: false,
      type: "Lead",
      source: "Website",
      assignedTo: "Sales",
      city: "New York",
      state: "NY",
      postalCode: "10001",
      address1: "123 Main St",
      dateAdded: new Date(),
      dateUpdated: new Date(),
      dateOfBirth: "2021-01-01", // Use a valid date in YYYY-MM-DD format
      tags: JSON.stringify(["New Lead", "Website"]),
      country: "USA",
      website: "https://example.com",
      timezone: "America/New_York",
      ssn: "1234567890",
      hashedFour: hashedFour, // Use the hashed value
      customField: JSON.stringify({ key: "value" }),
    };

    // Insert dummy data
    const [result] = await db.query(
      `INSERT INTO contacts (
                contact_id, locationId, contactName, firstName, lastName, companyName,
                email, phone, dnd, type, source, assignedTo, city, state, postalCode,
                address1, dateAdded, dateUpdated, dateOfBirth, tags, country, website,
                timezone, ssn, hashedFour, customField
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        dummyData.contact_id,
        dummyData.locationId,
        dummyData.contactName,
        dummyData.firstName,
        dummyData.lastName,
        dummyData.companyName,
        dummyData.email,
        dummyData.phone,
        dummyData.dnd,
        dummyData.type,
        dummyData.source,
        dummyData.assignedTo,
        dummyData.city,
        dummyData.state,
        dummyData.postalCode,
        dummyData.address1,
        dummyData.dateAdded,
        dummyData.dateUpdated,
        dummyData.dateOfBirth,
        dummyData.tags,
        dummyData.country,
        dummyData.website,
        dummyData.timezone,
        dummyData.ssn,
        dummyData.hashedFour,
        dummyData.customField,
      ]
    );

    console.log("✅ Dummy data inserted:", result);
  } catch (error) {
    console.error("❌ Error inserting dummy data:", error);
  }
}

// Call the function to insert dummy data
insertDummyData();
