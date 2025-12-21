use uuid::Uuid;

pub fn generate_refresh_token() -> String {
    Uuid::new_v4().to_string()
}
