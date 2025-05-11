// src/validators/memberSchema.ts
import { z } from 'zod';

export const MemberCreateSchema = z.object({
  membershipType: z.enum(['volunteer', 'standard', 'executive']),
  membershipStartDate: z
    .string()
    .refine((d) => !isNaN(Date.parse(d)), { message: 'Invalid date' }),
  membershipExpirationDate: z
    .string()
    .refine((d) => !isNaN(Date.parse(d)), { message: 'Invalid date' }),
  status: z.enum(['pending', 'active', 'expired']).optional(),
  membershipSource: z.string().nonempty().optional(),
  autoRenew: z.boolean().optional(),
  related: z.array(z.string()).optional(),
});
export type MemberCreateInput = z.infer<typeof MemberCreateSchema>;
