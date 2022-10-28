use std::{
    collections::HashMap,
    fmt::Write,
    string::FromUtf8Error,
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac};
use itertools::Itertools;
use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    Request, State,
};
use serde::Deserialize;
use sha2::Sha256;
use urlencoding::decode;

use crate::appcontext::AppContext;

pub struct TelegramAuth(pub HashMap<String, String>);

#[derive(Deserialize)]
pub struct TelegramUser {
    /// A unique identifier for the user or bot.
    pub id: u64,
    /// First name of the user or bot.
    pub first_name: String,
    /// Last name of the user or bot.
    pub last_name: Option<String>,
    /// Username of the user or bot.
    pub username: Option<String>,
    /// [IETF language](https://en.wikipedia.org/wiki/IETF_language_tag) tag of the user's language.
    pub language_code: Option<String>,
    /// True, if this user is a Telegram Premium user
    pub is_premium: Option<bool>,
    /// URL of the user’s profile photo. The photo can be in .jpeg or .svg formats.
    /// Only returned for Web Apps launched from the attachment menu.
    pub photo_url: Option<String>,
}

#[derive(Debug)]
pub enum TelegramAuthError {
    /// Invalid `init_data` key=value format.
    /// For example, may occur on `init_data` like `foo=bar&invalid&bar=baz`
    InitDataFormat,
    /// Empty `init_data` or missing `hash=` field
    InitDataEmpty,
    /// `init_data` decode failture using `urlencoding::decode`
    Utf8Decode(FromUtf8Error),
    /// Calculated hash not equals telegram-provided hash
    HashMismatch,
    /// `auth_date` is too old.
    ///
    /// **Note:** this variant returned only in `TelegramAuth::authorize_with_time()`
    AuthorizationExpired,
}

impl std::fmt::Display for TelegramAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitDataFormat => write!(f, "Invalid `init_data` key=value format"),
            Self::InitDataEmpty => write!(f, "Empty (or invalid) `init_data`"),
            Self::Utf8Decode(e) => e.fmt(f),
            Self::HashMismatch => write!(f, "Hash does not match"),
            Self::AuthorizationExpired => write!(f, "`auth_date=` field in `init_data` too old"),
        }
    }
}
impl std::error::Error for TelegramAuthError {}

impl TelegramAuth {
    /// Maximum time in seconds when the authorization is still valid
    pub const MAX_AUTH_TIME: u64 = 15 * 60;

    /// Always returns Result::Err(TelegramAuthError::HashMismatch) using shitty magic
    // NOTE: seems like it really broken. Fuck telegram.
    pub fn authorize(init_data: &str, bot_token: &str) -> Result<Self, TelegramAuthError> {
        // Stolen from: https://stackoverflow.com/q/72044314 and first answer to it

        // Also, data_field here doesn't contains hash= field
        let (data_fields, telegram_hash) = {
            // Spliting at '&' before decode because after decode some field (ex user.name) may contains it
            let raw_fields = init_data.split('&').map(|f| f.split_once('='));

            let mut hs = Vec::new();
            let mut hash = None;

            // May be it can be more... readable... Anyway, its works (in my dreams)
            for field in raw_fields {
                if let Some((k, v)) = field {
                    let v = match decode(v) {
                        Ok(v) => v.to_string(),
                        Err(e) => return Err(TelegramAuthError::Utf8Decode(e)),
                    };
                    if k == "hash" {
                        hash = Some(v);
                    } else {
                        hs.push((k, v));
                    }
                } else {
                    return Err(TelegramAuthError::InitDataFormat);
                }
            }

            hs.sort_by_key(|f| f.0);

            (hs, hash)
        };

        // If there no hash= field, structure may be invalid (or empty...)
        let telegram_hash = match telegram_hash {
            Some(h) => h,
            None => return Err(TelegramAuthError::InitDataEmpty),
        };

        // Telegram-way data_check_string. See top comment
        let data_check_string = data_fields
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .join("\n");

        let secret_key = {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(b"WebAppData").expect("Init 'WebAppData' mac");
            mac.update(bot_token.as_bytes());

            mac.finalize().into_bytes()
        };

        // Following telegram documentation, we need to check
        // hex(HMAC_SHA256(data_check_string, secret_key)) == telegram_hash
        // but hmac crate contains verify func... Copypasting code from top comment
        let calculated_hash = {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&secret_key[..]).expect("Init `secret_key` mac");
            mac.update(data_check_string.as_bytes());

            mac.finalize().into_bytes()
        };

        // Encode `calculated_hash` bytes to hex string, like `telegram_hash`
        let calculated_hash = {
            let bytes = &calculated_hash[..];
            let mut s = String::with_capacity(bytes.len() * 2);

            for &b in bytes {
                write!(&mut s, "{:02x}", b).unwrap();
            }

            s
        };

        if calculated_hash == telegram_hash {
            Ok(TelegramAuth(
                data_fields
                    .into_iter()
                    .map(|f| (f.0.to_owned(), f.1))
                    .collect(),
            ))
        } else {
            Err(TelegramAuthError::HashMismatch)
        }
    }

    /// Verify `init_data` by `bot_token` and verify `auth_date=` field in `init_data`
    pub fn authorize_with_time(
        init_data: &str,
        bot_token: &str,
        allowed_auth_time: u64,
    ) -> Result<Self, TelegramAuthError> {
        let data_fields = Self::authorize(init_data, bot_token)?;

        if data_fields.validate_by_time(allowed_auth_time) {
            Ok(data_fields)
        } else {
            Err(TelegramAuthError::AuthorizationExpired)
        }
    }

    /// Validate authorization by time
    pub fn validate_by_time(&self, allowed_auth_time: u64) -> bool {
        let auth_time = self
            .0
            .get("auth_date")
            .map(|f| f.parse::<u64>().ok())
            .flatten();
        debug_assert!(auth_time.is_some());

        let auth_time = match auth_time {
            Some(a) => a,
            None => return false,
        };

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Duration since UNIX_EPOCH")
            .as_secs();

        auth_time + allowed_auth_time >= current_time
    }

    /// Get user from data fields
    pub fn get_user(&self) -> Result<TelegramUser, serde_json::Error> {
        let user = self
            .0
            .get("user")
            .expect("`data_fields` doesn't contains `user=` field");

        serde_json::from_str(&user)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for TelegramAuth {
    type Error = TelegramAuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let app_context = match req.guard::<&State<AppContext>>().await {
            Outcome::Success(a) => a,
            Outcome::Failure(_) => panic!("Failed to get guard &State<AppContext>"),
            Outcome::Forward(_) => unreachable!(),
        };

        let init_data = match req.headers().get("X-InitData").next() {
            Some(h) => h,
            None => return Outcome::Forward(()),
        };

        let telegram_auth = TelegramAuth::authorize_with_time(
            init_data,
            &app_context.telegram_token,
            TelegramAuth::MAX_AUTH_TIME,
        );

        match telegram_auth {
            Ok(a) => Outcome::Success(a),
            Err(e) => Outcome::Failure((Status::Forbidden, e)),
        }
    }
}
