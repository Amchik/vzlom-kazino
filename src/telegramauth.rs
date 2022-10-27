use std::{collections::HashMap, string::FromUtf8Error};

use hmac::{Hmac, Mac};
use itertools::Itertools;
use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    Request, State,
};
use sha2::Sha256;
use urlencoding::decode;

use crate::appcontext::AppContext;

pub struct TelegramAuth(pub HashMap<String, String>);

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
}

impl std::fmt::Display for TelegramAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitDataFormat => write!(f, "Invalid `init_data` key=value format"),
            Self::InitDataEmpty => write!(f, "Empty (or invalid) `init_data`"),
            Self::Utf8Decode(e) => e.fmt(f),
            Self::HashMismatch => write!(f, "Hash does not match"),
        }
    }
}
impl std::error::Error for TelegramAuthError {}

impl TelegramAuth {
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

            (
                hs.into_iter()
                    .sorted_by_key(|f| f.0)
                    .map(|(k, v)| (k.to_string(), v))
                    .collect::<HashMap<String, String>>(),
                hash,
            )
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
            let mut mac = Hmac::<Sha256>::new_from_slice(b"WebApp").expect("Init 'WebApp' mac");
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

        if &calculated_hash[..] == telegram_hash.as_bytes() {
            Ok(TelegramAuth(data_fields))
        } else {
            Err(TelegramAuthError::HashMismatch)
        }
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

        let telegram_auth = TelegramAuth::authorize(init_data, &app_context.telegram_token);

        match telegram_auth {
            Ok(a) => Outcome::Success(a),
            Err(e) => Outcome::Failure((Status::Forbidden, e)),
        }
    }
}
