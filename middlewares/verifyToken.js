import jwt from "jsonwebtoken";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";

export const verifyToken = async (req, res, next) => {
  const token = req.cookies?.access_token;

  if (!token) return next(new ApiError(401, "Access denied. No token provided."));

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded._id).select("_id role");

    if (!user) {
      return next(new ApiError(404, "User not found."));
    }

    req.user = user;
    next();
  } catch (error) {
    return next(new ApiError(403, "Token is not valid."));
  }
};
