const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require('cors');
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const nodemailer = require('nodemailer');

const app = express();

const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "Mm123456",
  database: "requests",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.json())
app.use(cors({
  origin: 'http://localhost:3001',
  credentials: true
}));

// users

app.post("/users/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const [rows, fields] = await pool.execute(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );
    res.status(201).json({ message: "User created successfully!" });
  } catch (err) {
    console.log(err);
    res.status(500).send("Server Error");
  }
});

app.post("/users/login", async (req, res) => {
  try {
    const email = req.body.email;
    const password = req.body.password;

    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (rows.length === 0) {
      return res.status(401).json({ message: "User not found!" });
    }

    const user = rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Incorrect password!" });
    }

    const token = jwt.sign({ id: user.id }, "secret", { expiresIn: "1h" });

    res.cookie("jwt", token, { httpOnly: true });
    res.json({ name: user.name, jwt: token });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/users/user", async (req, res) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      throw new Error("Unauthenticated!");
    }

    const decodedToken = jwt.verify(token, "secret");

    const [rows] = await pool.query("SELECT * FROM users WHERE id = ?", [
      decodedToken.id,
    ]);

    if (rows.length === 0) {
      throw new Error("User not found");
    }

    const user = rows[0];

    res.status(200).json({ user });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: err.message });
  }
});

app.post('/users/logout', (req, res) => {
  res.clearCookie('jwt');
  res.status(200).send('Logged out successfully!');
});

// requests

app.post("/requests/create", async (req, res) => {
  const { title, description, name, user_id } = req.body;

  try {
    const connection = await pool.getConnection();

    const [userRows] = await connection.query(
      "SELECT * FROM users WHERE id = ?",
      [user_id]
    );
    const user = userRows[0];

    const [result] = await connection.query(
      "INSERT INTO requests (title, description, name, user_id) VALUES (?, ?, ?, ?)",
      [title, description, name, user_id]
    );

    connection.release();

    res.status(201).json({ message: "saved" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "internal server error" });
  }
});

app.put('/requests/update/:id', async (req, res) => {
  const id = req.params.id;
  const title = req.body.title;
  const description = req.body.description;
  
  if (!title || !description) {
    return res.status(400).json({ error: "Title and description are required" });
  }
  
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    
    const [result] = await connection.execute('SELECT * FROM requests WHERE id = ?', [id]);
    
    if (result.length === 0) {
      return res.status(404).json({ error: "Request not found" });
    }
    
    await connection.execute('UPDATE requests SET title = ?, description = ? WHERE id = ?', [title, description, id]);
    
    await connection.commit();
    
    res.status(200).json({ message: "Request updated" });
  } catch (error) {
    await connection.rollback();
    
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    connection.release();
  }
});

app.put('/requests/update-status/:id', async (req, res) => {
  const id = req.params.id;
  const status = req.body.status;

  if (!status) {
    return res.status(400).json({ error: "Status is required" });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [result] = await connection.execute('SELECT * FROM requests WHERE id = ?', [id]);

    if (result.length === 0) {
      return res.status(404).json({ error: "Request not found" });
    }

    await connection.execute('UPDATE requests SET status = ? WHERE id = ?', [status, id]);

    await connection.commit();

    res.status(200).json({ message: "Request status updated" });
  } catch (error) {
    await connection.rollback();

    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    connection.release();
  }
});

app.delete('/requests/delete/:id', async (req, res) => {
  const id = req.params.id;

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [result] = await connection.execute('SELECT * FROM requests WHERE id = ?', [id]);

    if (result.length === 0) {
      return res.status(404).json({ error: "Request not found" });
    }

    await connection.execute('DELETE FROM requests WHERE id = ?', [id]);

    await connection.commit();

    res.status(200).json({ message: "Request deleted" });
  } catch (error) {
    await connection.rollback();

    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    connection.release();
  }
});

app.get('/requests/all', async (req, res) => {
  const connection = await pool.getConnection();

  try {
    const [results] = await connection.execute('SELECT * FROM requests');

    res.status(200).json({ requests: results });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    connection.release();
  }
});

app.get('/requests/:id', async (req, res) => {
  const userId = req.params.id;

  const connection = await pool.getConnection();

  try {
    const [results] = await connection.execute('SELECT * FROM requests WHERE user_id = ?', [userId]);

    res.status(200).json({ requests: results });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    connection.release();
  }
});

// emails

app.post('/send-email', (req, res) => {
  const { recipientEmail, subject, message } = req.body;

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'maormarhum9400@gmail.com',
      pass: 'dfisdhcokskdwdzr'
    }
  });

  const mailOptions = {
    from: 'maor.requests@gmail.com',
    to: recipientEmail,
    subject: subject,
    text: message
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      res.status(500).send('Error: Failed to send email');
    } else {
      res.send('Email sent successfully');
    }
  });
});

app.post('/send-update', async (req, res) => {
  const { id } = req.body;

  const connection = await pool.getConnection();

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'maormarhum9400@gmail.com',
      pass: 'dfisdhcokskdwdzr'
    }
  });

  try {
    await connection.beginTransaction();

    const [result_user_id] = await connection.execute('SELECT user_id FROM requests WHERE id = ?', [id]);
    const user_id = result_user_id[0].user_id
    const [result] = await connection.execute('SELECT email FROM users WHERE id = ?', [user_id]);
    const recipientEmail = result[0].email
    const [result_title] = await connection.execute('SELECT title FROM requests WHERE id = ?', [id]);
    const title = result_title[0].title

    if (result.length === 0) {
      return res.status(404).json({ error: "user not found" });
    }

    const mailOptions = {
      from: 'maormarhum9400@gmail.com',
      to: recipientEmail,
      subject: 'עדכון סטטוס בקשה',
      text: `יש לך עדכון לגבי הבקשה ששלחת למאור בנושא ${title}`
    };
  
    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.log(error);
        res.status(500).send('Error: Failed to send email');
      } else {
        res.send('Email sent successfully');
      }
    });

    await connection.commit();
  } catch (error) {
    await connection.rollback();

    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    connection.release();
  }
});

app.listen(3000, () => console.log("Example app is listening on port 3000."));
