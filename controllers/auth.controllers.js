import { User } from "../models/user.model.js";
import bcryptjs from "bcryptjs";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import { ONE_DAY, ONE_HOUR, TEN_MINUTES } from "../utils/helper.js";

export const signup = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = bcryptjs.hashSync(password, 10);
  const otp = Math.floor(100_000 + Math.random() * 900_000).toString();

  const isExist = await User.findOne({ email });

  if (isExist)
    return res.status(409).json(new ApiError(409, "user already registered with this email"))

  const newUser = await User.create({
    name,
    email,
    password: hashedPassword,
    verificationToken: otp,
    verificationTokenExpiresAt: Date.now() + TEN_MINUTES, // 10 minutes expiry
  });

  if (!newUser)
    return res.status(400).json(new ApiError(400, "something went wrong while registering user"));

  // await sendVerificationEmail(email, otp);

  return res
    .status(201)
    .json(
      new ApiResponse(
        200,
        "User created successfully.",
        "User Registered Successfully",
      ),
    );
});

export const signin = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user) return res.status(404).json(new ApiError(404, "user not found with this email"));

  const validPassword = bcryptjs.compareSync(password, user.password);

  if (!validPassword) return res.status(401).json(new ApiError(401, "wrong credentials"));

  const token = jwt.sign(
    {
      _id: user._id,
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_SECRET_EXPIRY },
  );

  const { password: hashedPassword, ...rest } = user._doc;

  const expiryDate = new Date(Date.now() + ONE_DAY); // 1 day

  res
    .cookie("access_token", token, {
      httpOnly: true,
      secure: true,
      expires: expiryDate,
    })
    .status(200)
    .json(new ApiResponse(200, rest, "Successful Login"));
});

export const google = asyncHandler(async (req, res) => {
  const { name, email, photo } = req.body;

  const validUser = await User.findOne({ email });
  if (validUser) {
    const token = jwt.sign(
      {
        id: validUser._id,
        email: validUser.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_SECRET_EXPIRY },
    );

    const { password, ...rest } = validUser._doc;

    const expiryDate = new Date(Date.now() + 3_600_000); // 1 hour
    res
      .cookie("access_token", token, {
        httpOnly: true,
        expiresIn: process.env.JWT_SECRET_EXPIRY,
      })
      .status(200)
      .json(new ApiResponse(200, rest, "Successful Login"));
  } else {
    const generatedPassword = Math.random().toString(36).slice(-8);
    const hashedPassword = bcryptjs.hashSync(generatedPassword, 10);
    const newUser = new User({
      username: name.split(" ").join("-").toLowerCase(),
      email,
      password: hashedPassword,
      profilePicture: photo,
    });

    if (!newUser)
      throw new ApiError(400, "Something went wrong While registering User.");
    await newUser.save();

    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);
    const expiryDate = new Date(Date.now() + 3600000); // 1 hour

    return res
      .cookie("access_token", token, {
        httpOnly: true,
        expiresIn: process.env.JWT_SECRET_EXPIRY,
      })
      .status(201)
      .json(new ApiResponse(200, newUser, "User Registered Successfully"));
  }
});

export const signout = asyncHandler(async (req, res) => {
  res.clearCookie("access_token").status(200).json("Sign out Success");
});

export const verifyEmail = asyncHandler(async (req, res) => {
  const { otp } = req.body;

  const user = await User.findOne({
    verificationToken: otp,
    verificationTokenExpiresAt: { $gt: Date.now() },
  }).select("-createdAt -updatedAt -__v");

  if (!user) throw new ApiError(404, "User not Found.");

  user.isVerified = true;
  user.verificationToken = undefined;
  user.verificationTokenExpiresAt = undefined;
  await user.save();

  const token = jwt.sign(
    {
      _id: user._id,
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_SECRET_EXPIRY },
  );
  const expiryDate = new Date(Date.now() + ONE_DAY); // 1 day

  // await sendWelcomeEmail(user.email, user.name);

  res
    .cookie("access_token", token, {
      httpOnly: true,
      secure: true,
      expires: expiryDate,
    })
    .status(200)
    .json(new ApiResponse(200, user, "verified successfully"));
});

export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });

    if (!user) throw new ApiError(404, "User not found");

    let crypto = await import("node:crypto");
    const token = crypto
      .createHmac("sha256", process.env.JWT_SECRET)
      .digest("hex");

    user.resetPasswordToken = token;
    user.resetPasswordExpiresAt = Date.now() + ONE_HOUR; // 1 hour
    await user.save();

    // await sendPasswordResetEmail(
    //   email,
    //   `${process.env.CLIENT_URL}/reset-password/${token}`,
    // );

    res
      .status(200)
      .json(
        new ApiResponse(200, null, "Password reset link sent to your email"),
      );
  } catch (error) {
    console.error("error: ", error.message);
  }
});

export const resetPassword = asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { new_password } = req.body;

  const user = await User.findOne({
    resetPasswordToken: token,
    resetPasswordExpiresAt: { $gt: Date.now() },
  });

  if (!user) throw new ApiError(404, "user not found");

  const hashedPassword = bcryptjs.hashSync(new_password, 10);

  user.password = hashedPassword;
  await user.save();

  // await sendResetSuccessEmail(user.email);

  res
    .status(200)
    .json(new ApiResponse(200, null, "password reset is successful"));
});

export const verifyAuth = asyncHandler(async (req, res) => {
  const token = req.cookies?.access_token;

  if (!token) {
    return res.status(200).json(new ApiResponse(200, null, "token not found"));
  }

  const decoded = jwt.verify(req.cookies?.access_token, process.env.JWT_SECRET);
  const user = await User.findById(decoded._id).select("-password");

  if (!user) {
    return res.status(400).json({ success: false, message: "User not found" });
  }

  res.status(200).json(new ApiResponse(200, user, "User found."));
});
