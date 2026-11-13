use crate::services::account::{promote_user_role, transfer_funds_safe};

pub fn build_router() {
    let app = Router::new()
        .route("/api/v1/admin/promote", post(promote_user_role))
        .route("/api/v1/account/transfer", post(transfer_funds_safe));
    let _ = app;
}
