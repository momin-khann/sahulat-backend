import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MOONGO_DB_CONNECTION);

    console.log("====================================================");
    console.log(
      `Database connected to ${conn.connection.name} on ${conn.connection.host}`
    );
  } catch (error) {
    console.log(error.message);
    process.exit(1);
  }
};

export default connectDB;
