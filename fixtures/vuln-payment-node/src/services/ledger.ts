import { debitBalance, creditBalanceWithTx } from '../db/queries';

export async function processWithdrawal(userId: string, amount: number) {
  // Missing transaction / FOR UPDATE lock -> double-spend race condition!
  return await debitBalance(userId, amount);
}

export async function processSafeDeposit(userId: string, amount: number) {
  return await creditBalanceWithTx(userId, amount);
}
