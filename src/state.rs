use std::sync::Arc;

use crate::{
    repositories::{
        EmailVerificationRepository, EmailVerificationRepositoryTrait, PasswordResetRepository,
        PasswordResetRepositoryTrait, RefreshTokenRepository, RefreshTokenRepositoryTrait,
        UserRepository, UserRepositoryTrait,
    },
    services::EmailService,
};
use axum::extract::FromRef;
use sqlx::PgPool;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub db: PgPool,
    pub user_repository: Arc<dyn UserRepositoryTrait>,
    pub email_verification_repository: Arc<dyn EmailVerificationRepositoryTrait>,
    pub password_reset_repository: Arc<dyn PasswordResetRepositoryTrait>,
    pub refresh_token_repository: Arc<dyn RefreshTokenRepositoryTrait>,
    pub email_service: Arc<EmailService>,
}

impl AppState {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        // Create the database connecion pool
        let db = PgPool::connect(database_url).await?;

        // Run migration automatically
        sqlx::migrate!("./migrations").run(&db).await?;

        // Create the user repository
        let user_repository: Arc<dyn UserRepositoryTrait> =
            Arc::new(UserRepository::new(db.clone()));

        // Create the email verification repository
        let email_verification_repository: Arc<dyn EmailVerificationRepositoryTrait> =
            Arc::new(EmailVerificationRepository::new(db.clone()));

        // Create the password reset repository
        let password_reset_repository: Arc<dyn PasswordResetRepositoryTrait> =
            Arc::new(PasswordResetRepository::new(db.clone()));

        // Create the refresh token repository
        let refresh_token_repository: Arc<dyn RefreshTokenRepositoryTrait> =
            Arc::new(RefreshTokenRepository::new(db.clone()));

        // Create the email service
        let email_service =
            Arc::new(EmailService::new().expect("Failed to initialize email service"));

        Ok(Self {
            db,
            user_repository,
            email_verification_repository,
            password_reset_repository,
            refresh_token_repository,
            email_service,
        })
    }
}
