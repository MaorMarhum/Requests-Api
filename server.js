const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();

const connection = mysql.createConnection(process.env.DATABASE_URL);
app.use(cookieParser());
app.use(bodyParser.json());
const corsOptions = {
  origin: "https://maor-requests.netlify.app",
  credentials: true,
};

app.use(cors(corsOptions));

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// users

app.post("/users/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.execute(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );
    res.status(201).json({ message: "User created successfully!" });
  } catch (err) {
    console.log(err);
    res.status(500).send("Server Error");
  }
});

// app.post("/users/login", async (req, res) => {
//   try {
//     const { email, password } = req.body;

//     connection.query(
//       "SELECT * FROM users WHERE email = ?",
//       [email],
//       async function (err, rows, fields) {
//         console.log(rows.values);

//         if (rows.length === 0) {
//           return res.status(401).json({ message: "User not found!" });
//         }

//         const user = rows[0];

//         const isPasswordValid = await bcrypt.compare(password, user.password);

//         if (!isPasswordValid) {
//           return res.status(401).json({ message: "Incorrect password!" });
//         }

//         const token = jwt.sign({ id: user.id }, "secret", { expiresIn: "1h" });

//         res.cookie("jwt", token, { httpOnly: true });
//         res.header(
//           "Access-Control-Allow-Origin",
//           "https://maor-requests.netlify.app"
//         );
//         res.header("Access-Control-Allow-Credentials", true);
//         return res.status(200).send({ name: user.name, jwt: token });
//       }
//     );
//   } catch (err) {
//     console.log(err);
//     return res.status(500).json({ message: "Server error" });
//   }
// });

app.post("/users/login", cors(corsOptions), async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists in database
    const checkUser = await connection
      .promise()
      .query(`SELECT * FROM users WHERE email = ?`, [email]);
    if (checkUser[0].length === 0) {
      return res.status(401).send("Invalid email or password");
    }

    // Compare password hashes
    const isPasswordValid = await bcrypt.compare(
      password,
      checkUser[0][0].password
    );
    if (!isPasswordValid) {
      return res.status(401).send("Invalid email or password");
    }

    // Generate JWT token
    const token = jwt.sign({ email }, "secret", { expiresIn: "1h" });

    // Set token in cookie
    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 3600000,
      sameSite: "none",
      secure: true,
    }); // maxAge is in millisecond

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal server error");
  }
});

app.get("/users/user", cors(corsOptions), async (req, res) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      throw new Error("Unauthenticated!");
    }

    const decodedToken = jwt.verify(token, "secret");

    connection.query(
      "SELECT * FROM users WHERE id = ?",
      [decodedToken.id],
      function (err, rows, fields) {
        if (rows.length === 0) {
          throw new Error("User not found");
        }

        const user = rows[0];

        res.status(200).json({ user });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: err.message });
  }
});

app.post("/users/logout", (req, res) => {
  res.clearCookie("jwt");
  res.status(200).send("Logged out successfully!");
});

// requests

app.post("/requests/create", async (req, res) => {
  const { title, description, name, user_id } = req.body;

  try {
    connection.query(
      "INSERT INTO requests (title, description, name, user_id) VALUES (?, ?, ?, ?)",
      [title, description, name, user_id]
    );
    res.status(201).json({ message: "saved" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "internal server error" });
  }
});

app.put("/requests/update/:id", async (req, res) => {
  const id = req.params.id;
  const title = req.body.title;
  const description = req.body.description;

  if (!title || !description) {
    return res
      .status(400)
      .json({ error: "Title and description are required" });
  }

  try {
    connection.execute(
      "SELECT * FROM requests WHERE id = ?",
      [id],
      function (err, rows, fields) {
        if (rows.length === 0) {
          return res.status(404).json({ error: "Request not found" });
        }
        connection.execute(
          "UPDATE requests SET title = ?, description = ? WHERE id = ?",
          [title, description, id]
        );
      }
    );

    res.status(200).json({ message: "Request updated" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/requests/update-status/:id", async (req, res) => {
  const id = req.params.id;
  const status = req.body.status;

  if (!status) {
    return res.status(400).json({ error: "Status is required" });
  }

  try {
    await connection.execute(
      "SELECT * FROM requests WHERE id = ?",
      [id],
      function (err, rows, fields) {
        if (rows.length === 0) {
          return res.status(404).json({ error: "Request not found" });
        }
        connection.execute("UPDATE requests SET status = ? WHERE id = ?", [
          status,
          id,
        ]);
        res.status(200).json({ message: "Request status updated" });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/requests/delete/:id", async (req, res) => {
  const id = req.params.id;

  try {
    connection.execute(
      "SELECT * FROM requests WHERE id = ?",
      [id],
      function (err, rows, fields) {
        if (rows.length === 0) {
          return res.status(404).json({ error: "Request not found" });
        }
        connection.execute("DELETE FROM requests WHERE id = ?", [id]);
        res.status(200).json({ message: "Request deleted" });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/requests/all", async (req, res) => {
  try {
    connection.execute("SELECT * FROM requests", function (err, rows, fields) {
      res.status(200).json({ requests: rows });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/requests/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    await connection.execute(
      "SELECT * FROM requests WHERE user_id = ?",
      [userId],
      function (err, rows, fields) {
        res.status(200).json({ requests: rows });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// emails

app.post("/send-email", (req, res) => {
  const { recipientEmail, subject, message } = req.body;

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "maormarhum9400@gmail.com",
      pass: "dfisdhcokskdwdzr",
    },
  });

  const mailOptions = {
    from: "maor.requests@gmail.com",
    to: recipientEmail,
    subject: subject,
    text: message,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      res.status(500).send("Error: Failed to send email");
    } else {
      res.send("Email sent successfully");
    }
  });
});

app.post("/send-update", async (req, res) => {
  const { id } = req.body;
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "maormarhum9400@gmail.com",
      pass: "dfisdhcokskdwdzr",
    },
  });

  try {
    connection.execute(
      "SELECT user_id FROM requests WHERE id = ?",
      [id],
      function (err, rows, fields) {
        const user_id = rows[0].user_id;
        connection.execute(
          "SELECT email FROM users WHERE id = ?",
          [user_id],
          function (err, rows, fields) {
            const recipientEmail = rows[0].email;
            connection.execute(
              "SELECT title FROM requests WHERE id = ?",
              [id],
              function (err, rows, fields) {
                if (rows.length === 0) {
                  return res.status(404).json({ error: "user not found" });
                }
                const title = rows[0].title;
                const mailOptions = {
                  from: "maormarhum9400@gmail.com",
                  to: recipientEmail,
                  subject: "עדכון סטטוס בקשה",
                  text: `יש לך עדכון לגבי הבקשה ששלחת למאור בנושא ${title}`,
                };

                transporter.sendMail(mailOptions, (error) => {
                  if (error) {
                    console.log(error);
                    res.status(500).send("Error: Failed to send email");
                  } else {
                    res.send("Email sent successfully");
                  }
                });
              }
            );
          }
        );
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(3001, () => console.log("Example app is listening on port 3000."));
