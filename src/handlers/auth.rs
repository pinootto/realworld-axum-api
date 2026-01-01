use std::collections::HashMap;

use crate::auth::middleware::RequireAuth;
use crate::auth::password::hash_password;
use crate::auth::tokens::generate_refresh_token;
use crate::auth::{jwt::generate_token, password::verify_password};
use crate::schemas::password_reset_schemas::{
    ForgotPasswordRequest, ForgotPasswordResponse, ResetPasswordRequest, ResetPasswordResponse,
};
use crate::schemas::{
    auth_schemas::*, LogoutRequest, LogoutResponse, RefreshTokenRequest, RefreshTokenResponse,
};
use crate::state::AppState;
use crate::utils::generate_verification_token;
use axum::{extract::State, http::StatusCode, Json};
use chrono::{Duration, Utc};
use validator::Validate;

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    eprintln!("REGISTER HANDLER CALLED");

    // Validate input data
    eprintln!("Validating...");
    payload
        .user
        .validate()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Check if user already exists
    eprintln!("Checking email exists...");
    if state
        .user_repository
        .find_by_email(&payload.user.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }

    eprintln!("Checking username exists...");
    if state
        .user_repository
        .find_by_username(&payload.user.username)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }

    // Hash the password
    eprintln!("Hashing password...");
    let password_hash =
        hash_password(&payload.user.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create user in database
    eprintln!("Creating user...");
    let user = state
        .user_repository
        .create(&payload.user.username, &payload.user.email, &password_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    eprintln!("User created: {}", user.email);

    // Generate verification token
    let verification_token = generate_verification_token();
    let expires_at = Utc::now() + Duration::hours(24);

    eprintln!("Generated token: {}", verification_token);

    // Save token to database
    state
        .email_verification_repository
        .create_token(user.id, &verification_token, expires_at)
        .await
        .map_err(|e| {
            eprintln!("Failed to create token in DB: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    eprintln!("Token saved to database");

    // Send verification email
    eprintln!("Attempting to send email...");
    state
        .email_service
        .send_verification_email(&user.email, &user.username, &verification_token)
        .await
        .map_err(|e| {
            eprintln!("Failed to send verification email: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    eprintln!("Email sent successfully");

    // Generate JWT access token (15 minutes)
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let access_token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate refresh token (UUID, no expiration)
    let refresh_token = generate_refresh_token();

    // Save refresh token to database
    state
        .refresh_token_repository
        .create_token(user.id, &refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build the response with BOTH tokens
    let response = LoginResponse {
        user: UserData::from_user(user),
        access_token,
        refresh_token,
    };

    eprintln!("Registration completed");

    Ok(Json(response))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginUserRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    // Validate input
    payload
        .user
        .validate()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Find user by email
    let user = state
        .user_repository
        .find_by_email(&payload.user.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if email is verified
    // if not verified, return UNAUTHORIZED
    // todo

    // Verify password
    let password_valid = verify_password(&payload.user.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !password_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Generate JWT access token (15 minutes)
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let access_token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate refresh token (UUID, no expiration)
    let refresh_token = generate_refresh_token();

    // Save refresh token to database
    state
        .refresh_token_repository
        .create_token(user.id, &refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build the response with BOTH tokens
    let response = LoginResponse {
        user: UserData::from_user(user),
        access_token,
        refresh_token,
    };

    Ok(Json(response))
}

pub async fn current_user(
    RequireAuth(user): RequireAuth,
) -> Result<Json<UserResponse>, StatusCode> {
    // Build the response (no token needed - they already have one)
    let response = UserResponse {
        user: UserData::from_user(user),
    };

    Ok(Json(response))
}

pub async fn verify_email(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Extract token from query params
    let token = params.get("token").ok_or(StatusCode::BAD_REQUEST)?;

    // Look up the token in database
    let verification_token = state
        .email_verification_repository
        .find_by_token(token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Check if expired
    if verification_token.is_expired() {
        // Clean up expired token
        state
            .email_verification_repository
            .delete_token(token)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(StatusCode::GONE);
    }

    // Mark user as verified
    state
        .email_verification_repository
        .verify_user_email(verification_token.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Delete token (single-use)
    state
        .email_verification_repository
        .delete_token(token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "message": "Email verified successfully!"
    })))
}

pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, StatusCode> {
    // Validate email format
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Look up user by email
    let user = state
        .user_repository
        .find_by_email(&payload.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // SECURITY: Always return success even if email doesn't exists
    // This prevents attackers from discovering which emails are generated
    if user.is_none() {
        return Ok(Json(ForgotPasswordResponse {
            message: "If that email exists, a password reset link has been sent.".to_string(),
        }));
    }

    let user = user.unwrap();

    // Generate reset token
    let reset_token = generate_verification_token();
    let expires_at = Utc::now() + Duration::hours(1);

    // Save token to database
    state
        .password_reset_repository
        .create_token(user.id, &reset_token, expires_at)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Send reset email
    state
        .email_service
        .send_password_reset_email(&user.email, &user.username, &reset_token)
        .await
        .map_err(|e| {
            eprintln!("Failed to send password reset email: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(ForgotPasswordResponse {
        message: "If that email exists, a password reset link has been sent.".to_string(),
    }))
}

pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, StatusCode> {
    // Validate new password
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Look up token
    let reset_token = state
        .password_reset_repository
        .find_by_token(&payload.token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Check expiration
    if reset_token.is_expired() {
        // Clean up expire token
        state
            .password_reset_repository
            .delete_token(&payload.token)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(StatusCode::GONE);
    }

    // Hash new password
    let new_password_hash =
        hash_password(&payload.new_password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update user password
    state
        .user_repository
        .update_password(reset_token.user_id, &new_password_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ResetPasswordResponse {
        message: "Password has been reset successfully. You can now login with your new password."
            .to_string(),
    }))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<RefreshTokenResponse>, StatusCode> {
    // Find the refresh token in database
    let refresh_token = state
        .refresh_token_repository
        .find_by_token(&payload.refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if token has expired
    if refresh_token.is_expired() {
        // Token is expired, delete it and reject
        let _ = state
            .refresh_token_repository
            .delete_token(&payload.refresh_token)
            .await;

        return Err(StatusCode::UNAUTHORIZED);
    }

    // REUSE DETECTION - Check if token was already UserData
    if refresh_token.is_used {
        // SECURITY BREACH DETECTED!
        // Someone is trying to use an old token
        // This means the token was likely stolen

        eprintln!("TOKEN REUSE DETECTED!");
        eprintln!("Token: {}", &payload.refresh_token);
        eprintln!("User ID: {}", refresh_token.user_id);
        eprintln!("Originally used at: {:?}", refresh_token.used_at);

        // Nuclear option: Delete ALL user's refresh tokens
        // Force them to login again
        state
            .refresh_token_repository
            .delete_all_user_tokens(refresh_token.user_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // Get user info for email
        let user = state
            .user_repository
            .find_by_id(refresh_token.user_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

        // Send security alert email
        if let Err(e) = state
            .email_service
            .send_security_alert(&user.email, &user.username)
            .await
        {
            eprintln!("Failed to send security alert email: {}", e);
            // Don't fail the request if email fails
        }

        return Err(StatusCode::UNAUTHORIZED);
    }

    // Mark the old token as used (consumed)
    state
        .refresh_token_repository
        .mark_token_as_used(&payload.refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate NEW refresh token with rotation
    let new_refresh_token = generate_refresh_token();
    state
        .refresh_token_repository
        .create_token(refresh_token.user_id, &new_refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate new access token
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let access_token = generate_token(&refresh_token.user_id, &jwt_secret)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Return BOTH tokens
    Ok(Json(RefreshTokenResponse {
        access_token,
        refresh_token: new_refresh_token,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Json<LogoutResponse>, StatusCode> {
    // Simply delete the refresh token from database
    state
        .refresh_token_repository
        .delete_token(&payload.refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(LogoutResponse {
        message: "Logged out successfully".to_string(),
    }))
}
