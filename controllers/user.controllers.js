import { asyncHandler } from "../utils/asyncHandler.js";
import bcryptjs from "bcryptjs";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";

// change password
export const changePassword = asyncHandler(async (req, res) => {
  if (req.user.id !== req.params.id) {
    return res
      .status(401)
      .json(new ApiError(401, "You can only update your account !!"));
  }

  const { id } = req.params;
  const { new_password } = req.body;

  const user = await User.findById(id);

  if (!user) return res.status(404).json(new ApiError(404, "user not found"));

  const hashedPassword = bcryptjs.hashSync(new_password, 10);

  user.password = hashedPassword;
  await user.save();

  res
    .status(200)
    .json(new ApiResponse(200, user, "password changed successfully"));
});

// update user
export const updateUser = asyncHandler(async (req, res) => {
  if (req.user.id !== req.params.id) {
    return res
      .status(401)
      .json(new ApiError(401, "You can only update your account !!"));
  }

  const { name, role, tfa } = req.body;

  const updatedUser = await User.findByIdAndUpdate(
    req.params.id,
    {
      $set: {
        name: name,
        role: role,
      },
    },
    { new: true },
  ).select("-password")

  // const { password: hashedPassword, ...rest } = updatedUser._doc;

  res
    .status(201)
    .json(new ApiResponse(200, updatedUser, "User updated Successfully."));
});

// delete user
export const deleteUser = asyncHandler(async (req, res) => {
  if (req.user.id !== req.params.id) {
    return res
      .status(401)
      .json(new ApiError("You can only delete your account"));
  }

  await User.findByIdAndDelete(req.params.id);
  res.status(200).json(new ApiResponse(200, null, "User has been deleted..."));
});
