import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required."]
    },
    email: {
      type: String,
      required: [true, "Email is required."],
      unique: true,
      index: true
    },
    password: {
      type: String,
      required: [true, "Password is required"]
    },
    profilePicture: {
      type: String,
      default:
        "https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_960_720.png"
    },
    isVerified: {
      type: Boolean,
      default: false
    },
    role: {
      type: String,
      enum: ["USER", "ADMIN"],
      default: "USER"
    },
    resetPasswordToken: String,
    resetPasswordExpiresAt: Date,
    verificationToken: String,
    verificationTokenExpiresAt: Date
  },
  { timestamps: true }
);

// compound index - index on multiple fields
userSchema.index({ verificationToken: 1, verificationTokenExpiresAt: 1 });

export const User = mongoose.model("User", userSchema);
