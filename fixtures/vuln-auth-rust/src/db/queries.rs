pub fn update_role_in_db(user_id: &str) {
    let _sql = format!("UPDATE users SET role = 'admin' WHERE id = '{}'", user_id);
}

pub fn execute_locked_transfer(user_id: &str, amount: i64) {
    let _lock = "SELECT balance FROM accounts WHERE id = $1 FOR UPDATE";
    let _sql = format!("UPDATE accounts SET balance = balance - {} WHERE id = '{}'", amount, user_id);
}
