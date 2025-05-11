// src/config/db.ts
import mongoose from 'mongoose';

const connectMongo = async (): Promise<void> => {
  const uri = process.env.MONGO_URI!;
  try {
    await mongoose.connect(uri);
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  }
};

export default connectMongo;
