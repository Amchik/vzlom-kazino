use rocket::get;

use crate::{response::APIResponse, telegramauth::TelegramAuth};

#[get("/self")]
pub fn get_user(auth: TelegramAuth) -> APIResponse {
    APIResponse::new(auth.0)
}
