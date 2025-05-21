import mongoose from 'mongoose';
import config from "../config/config";

export const connectDB = async (): Promise<void> => {
  try {
    const conn = await mongoose.connect(config.dbUrl!);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error connecting to MongoDB: ${error}`);
    process.exit(1);
  }
};
