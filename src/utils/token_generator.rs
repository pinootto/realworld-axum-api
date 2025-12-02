use uuid::Uuid;

pub fn generate_verification_token() -> String {
    // Generate a random UUID and convert to string without hyphens
    Uuid::new_v4().simple().to_string()
}
