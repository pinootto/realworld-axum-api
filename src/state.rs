use std::sync::Arc;

use crate::repositories::{UserRepository, UserRepositoryTrait};
use axum::extract::FromRef;
use sqlx::PgPool;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub db: PgPool,
    pub user_repository: Arc<dyn UserRepositoryTrait>,
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

        Ok(Self {
            db,
            user_repository,
        })
    }
}
