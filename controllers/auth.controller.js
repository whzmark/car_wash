import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
  try {
    const { username, password } = req.body;

    const existing = await User.findOne({ username });
    if (existing)
      return res.status(400).json({ message: "A user with this username already exists. Please choose a different username." });

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({ username, password: hashed });
    res.status(201).json({ message: "Registration successful! You can now log in.", userId: user._id });
  } catch (err) {
    res.status(500).json({ message: "An unexpected error occurred during registration. Please try again later.", error: err.message });
  }
};

export const login = async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: "No account found with that username. Please check your username or register." });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Incorrect password. Please try again." });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res
      .cookie("token", token, { httpOnly: true, sameSite: "lax" })
      .json({ message: "Login successful!", userId: user._id });
  } catch (err) {
    res.status(500).json({ message: "An unexpected error occurred during login. Please try again later.", error: err.message });
  }
};

export const logout = (req, res) => {
  res.clearCookie("token").json({ message: "Logged out" });
};

export const getMe = (req, res) => {
  res.json(req.user);
};
