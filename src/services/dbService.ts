// src/services/dbService.ts
import type { Model, Document, FilterQuery, UpdateQuery } from 'mongoose';

export class DbService<T extends Document> {
  constructor(private model: Model<T>) {}

  async findAll(
    filter: FilterQuery<T>,
    opts: { skip?: number; limit?: number; sort?: any } = {}
  ): Promise<{ total: number; data: T[] }> {
    const total = await this.model.countDocuments(filter);
    const data = await this.model
      .find(filter)
      .skip(opts.skip || 0)
      .limit(opts.limit || 10)
      .sort(opts.sort || {})
      .exec();
    return { total, data };
  }

  async findById(id: string): Promise<T | null> {
    return this.model.findById(id).exec();
  }

  async create(payload: Partial<T>): Promise<T> {
    return this.model.create(payload);
  }

  async update(id: string, update: UpdateQuery<T>): Promise<T | null> {
    return this.model.findByIdAndUpdate(id, update, { new: true }).exec();
  }

  async delete(id: string): Promise<T | null> {
    return this.model.findByIdAndDelete(id).exec();
  }
}
