import jwt from "jsonwebtoken";
import { ApiError } from "../utils/ApiError.js";

export const verifyToken = (req, res, next) => {
  const token = req.cookies.access_token;

  if (!token) return next();
  // if (!token) return next(new ApiResponse(401, null, "Unauthorized - no token provided !!"));

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return next(new ApiError(403, "Token is not valid."));

    // decoded user by jwt
    req.user = user;
  });
  next();
};
