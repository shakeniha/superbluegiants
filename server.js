const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || "06df829c80fa7a07d6b4e219a0ea683dacb6cf6f652db490417893179adf5525";

// Подключение к MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Определение схем
const userSchema = new mongoose.Schema({
  username: String,
  hashedPassword: String,
  role: { type: String, default: "user" },
  confirmed: { type: Boolean, default: false },
  confirmationToken: String,
});
const User = mongoose.model("User", userSchema);

const whaleSchema = new mongoose.Schema({
  name: String,
  dietType: String,
  size: Number,
  habitat: String,
  populationCount: Number,
});
const Whale = mongoose.model("Whale", whaleSchema);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
// Статика (HTML, CSS, форма и пр.) в папке public
app.use(express.static(path.join(__dirname, "public")));

// Настройка multer для загрузки файлов (сохраняются в public/uploads)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "public", "uploads"));
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// Настройка nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Вспомогательные функции
const generateToken = () => crypto.randomBytes(32).toString("hex");

const generateJWT = (username, role) => {
  return jwt.sign({ username, role }, jwtSecret, { expiresIn: "24h" });
};

const validateJWT = (token) => {
  try {
    return jwt.verify(token, jwtSecret);
  } catch (err) {
    return null;
  }
};

// Middleware для аутентификации
const authMiddleware = (req, res, next) => {
  const token = req.cookies?.Authorization;
  const decoded = validateJWT(token);
  if (!decoded) return res.status(401).send("Unauthorized");
  req.user = decoded;
  next();
};

// Регистрация пользователя
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 8 || password.length < 8) {
    return res.status(406).send("Username and password must be at least 8 characters");
  }
  // Валидация email через регулярное выражение
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(username)) {
    return res.status(400).send("Invalid email address");
  }
  const existingUser = await User.findOne({ username });
  if (existingUser) return res.status(409).send("User already exists");

  const hashedPassword = await bcrypt.hash(password, 10);
  const confirmationToken = generateToken();

  const newUser = new User({ username, hashedPassword, confirmationToken });
  await newUser.save();

  // Отправка письма для подтверждения регистрации
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: username,
    subject: "Confirm your registration",
    text: `Click the link to confirm your registration: ${process.env.BASE_URL}/api/confirm?token=${confirmationToken}`,
  };
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) console.error("Error sending email:", error);
  });
  res.send("Registration successful! Please check your email to confirm your account.");
});

// Подтверждение email
app.get("/api/confirm", async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send("Invalid token");
  const user = await User.findOneAndUpdate({ confirmationToken: token }, { confirmed: true, confirmationToken: "" });
  if (!user) return res.status(400).send("Invalid or expired token");
  res.send("Email confirmed successfully! You can now log in.");
});

// Логин
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).send("Invalid username or password");
  if (!user.confirmed) return res.status(401).send("Email not confirmed. Please check your email.");
  const passwordMatch = await bcrypt.compare(password, user.hashedPassword);
  if (!passwordMatch) return res.status(401).send("Invalid username or password");
  const token = generateJWT(user.username, user.role);
  res.cookie("Authorization", token, { httpOnly: true, maxAge: 24 * 3600 * 1000 });
  res.send("Login successful!");
});

// Логаут
app.post("/api/logout", (req, res) => {
  res.clearCookie("Authorization");
  res.send("Logout successful!");
});

// Защищённый эндпоинт
app.get("/api/protected", authMiddleware, (req, res) => {
  res.send(`Welcome, ${req.user.username}! Your role is: ${req.user.role}.`);
});

// CRUD и дополнительные операции для whale

// Создание записи о китах
app.post("/api/whales/create", authMiddleware, async (req, res) => {
  const { name, dietType, size, habitat, populationCount } = req.body;
  if (!name || !dietType || !habitat || size <= 0 || populationCount < 0) {
    return res.status(400).send("All fields are required and must have valid values");
  }
  const whale = new Whale({ name, dietType, size, habitat, populationCount });
  await whale.save();
  res.status(201).json({ message: "Whale created successfully" });
});

// Получение списка китов
app.get("/api/whales/list", async (req, res) => {
  const whales = await Whale.find();
  res.json(whales);
});

// Удаление записи о ките (id передается как query параметр)
app.delete("/api/whales/delete", authMiddleware, async (req, res) => {
  const { id } = req.query;
  if (!id) return res.status(400).send("ID is required");
  try {
    await Whale.findByIdAndDelete(id);
    res.json({ message: "Whale deleted successfully" });
  } catch (err) {
    res.status(500).send("Failed to delete whale");
  }
});

// Обновление записи о ките (id передается как query параметр)
app.put("/api/whales/update", authMiddleware, async (req, res) => {
  const { id } = req.query;
  if (!id) return res.status(400).send("ID is required");
  try {
    await Whale.findByIdAndUpdate(id, req.body);
    res.json({ message: "Whale updated successfully" });
  } catch (err) {
    res.status(500).send("Failed to update whale");
  }
});

// Фильтрация китов
app.get("/api/whales/filter", async (req, res) => {
  const { dietType, size, habitat, population } = req.query;
  let filter = {};
  if (dietType && dietType !== "doesn't matter") filter.dietType = dietType;
  if (size && size !== "doesn't matter") {
    switch (size) {
      case "large":
        filter.size = { $gte: 20 };
        break;
      case "middle":
        filter.size = { $gte: 10, $lt: 20 };
        break;
      case "small":
        filter.size = { $lt: 10 };
        break;
    }
  }
  if (habitat && habitat !== "doesn't matter") filter.habitat = habitat;
  if (population && population !== "doesn't matter") {
    switch (population) {
      case "not sufficiently studied":
        filter.populationCount = { $lt: 100 };
        break;
      case "rare":
        filter.populationCount = { $gte: 10000, $lt: 50000 };
        break;
      case "moderate":
        filter.populationCount = { $gte: 50000, $lt: 100000 };
        break;
      case "abundant":
        filter.populationCount = { $gte: 100000 };
        break;
    }
  }
  const whales = await Whale.find(filter);
  res.json(whales);
});

// Сортировка китов
app.get("/api/whales/sort", async (req, res) => {
  const { sortBy, order } = req.query;
  const sortOrder = order === "desc" ? -1 : 1;
  const allowedSortFields = { name: true, size: true, populationCount: true };
  if (!allowedSortFields[sortBy]) return res.status(400).send("Invalid sort field");
  const whales = await Whale.find().sort({ [sortBy]: sortOrder });
  res.json(whales);
});

// Пагинация китов
app.get("/api/whales/paginate", async (req, res) => {
  let { sortBy, order, page, limit } = req.query;
  page = parseInt(page) || 1;
  limit = parseInt(limit) || 10;
  const skip = (page - 1) * limit;
  const sortOrder = order === "desc" ? -1 : 1;
  let sort = {};
  if (sortBy) sort[sortBy] = sortOrder;
  const whales = await Whale.find().sort(sort).skip(skip).limit(limit);
  res.json(whales);
});

// Эндпоинт для формы с загрузкой файла и отправкой письма
app.get("/form", (req, res) => {
  // Отдаем HTML-форму (например, public/form.html)
  res.sendFile(path.join(__dirname, "public", "form.html"));
});

app.post("/form", upload.single("image"), async (req, res) => {
  const { subject, message, email } = req.body;
  let finalMessage = message;
  if (req.file) {
    // Формируем URL для доступа к загруженному файлу
    const imageUrl = `/uploads/${req.file.filename}`;
    finalMessage += `<br><img src='${imageUrl}' alt='Uploaded Image'>`;
  }
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email || process.env.EMAIL_USER,
    subject,
    html: finalMessage,
  };
  try {
    await transporter.sendMail(mailOptions);
    res.send("Email sent successfully!");
  } catch (err) {
    res.status(500).send("Failed to send email: " + err.message);
  }
});

// Запуск сервера
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
