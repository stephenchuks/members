// src/models/Counter.ts
import { Schema, model, Document } from 'mongoose';

export interface ICounter extends Document {
  name: string;
  seq: number;
}

const CounterSchema = new Schema<ICounter>({
  name: { type: String, required: true, unique: true },
  seq:  { type: Number, required: true, default: 0 },
});

export default model<ICounter>('Counter', CounterSchema);
