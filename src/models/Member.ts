// src/models/Member.ts
import mongoose, { Schema, Document } from 'mongoose';

export interface IMember extends Document {
  membershipId: string;
  name: string;
  email: string;
  type: 'volunteer' | 'standard' | 'executive';
  status: 'pending' | 'active' | 'expired';
  memberSince: Date;
  start: Date;
  expiration: Date;
  autoRenew: boolean;
  source?: string;
  related?: string[];
}

const MemberSchema = new Schema<IMember>(
  {
    membershipId: { type: String, unique: true, required: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    type: { type: String, enum: ['volunteer', 'standard', 'executive'], required: true },
    status: { type: String, enum: ['pending', 'active', 'expired'], default: 'pending' },
    memberSince: { type: Date, default: () => new Date() },
    start: { type: Date, required: true },
    expiration: { type: Date, required: true },
    autoRenew: { type: Boolean, default: false },
    source: String,
    related: [String],
  },
  { timestamps: true }
);

// You’ll need a plugin or a pre-save hook to auto-increment “membershipId”
// (left out here for brevity)

export default mongoose.model<IMember>('Member', MemberSchema);
