import express from "express";
import {
  changePassword,
  deleteUser,
  updateUser
} from "../controllers/user.controllers.js";
import { verifyToken } from "../middlewares/verifyToken.js";

const router = express.Router();

router.post("/change-password/:id", verifyToken, changePassword);
router.post("/update/:id", verifyToken, updateUser);
router.delete("/delete/:id", verifyToken, deleteUser);

export { router };
