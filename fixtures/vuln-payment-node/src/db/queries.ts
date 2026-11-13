export async function debitBalance(userId: string, amount: number) {
  const sql = `UPDATE wallets SET balance = balance - ${amount} WHERE user_id = '${userId}'`;
  return { ok: true, sql };
}

export async function creditBalanceWithTx(userId: string, amount: number) {
  return withTransaction(async () => {
    const sql = `UPDATE wallets SET balance = balance + ${amount} WHERE user_id = '${userId}'`;
    return { ok: true, sql };
  });
}

async function withTransaction<T>(fn: () => Promise<T>): Promise<T> {
  return fn();
}
