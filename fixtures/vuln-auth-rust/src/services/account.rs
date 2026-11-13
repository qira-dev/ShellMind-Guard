use crate::db::queries::{update_role_in_db, execute_locked_transfer};

pub async fn promote_user_role(user_id: &str) {
    // Missing requireAuth / requireAdmin check!
    update_role_in_db(user_id);
}

pub async fn transfer_funds_safe(user_id: &str, amount: i64) {
    requireAuth(user_id);
    execute_locked_transfer(user_id, amount);
}

fn requireAuth(_u: &str) {}
