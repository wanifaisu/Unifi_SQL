const mysql = require("mysql2");

const pool = mysql.createPool({
  host: "mysql1001.site4now.net",
  user: "ab6902_unifi",
  password: "Faisal@155223",
  database: "db_ab6902_unifi",
});
pool.getConnection((err, connection) => {
  if (err) {
    console.error("❌ Error connecting to MySQL:", err);
  } else {
    console.log("✅ Connected to MySQL database");
    connection.release(); // Release the connection back to the pool
  }
});
module.exports = pool.promise();
