import express from 'express';
import { processWithdrawal, processSafeDeposit } from '../services/ledger';
import { requireAuth } from '../middleware/auth';

const router = express.Router();

// VULNERABLE: Missing requireAuth AND missing transaction lock in downstream ledger.ts!
router.post('/api/v1/checkout/withdraw', async (req, res) => {
  const result = await processWithdrawal(req.body.userId, req.body.amount);
  res.json(result);
});

// SAFE: Protected by requireAuth middleware + withTransaction lock
router.post('/api/v1/checkout/deposit', requireAuth, async (req, res) => {
  const result = await processSafeDeposit(req.body.userId, req.body.amount);
  res.json(result);
});

export default router;
