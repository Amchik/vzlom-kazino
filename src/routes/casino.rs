use lazy_static::__Deref;
use migration::sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ActiveValue, DatabaseConnection, EntityTrait,
};
use rocket::{get, State};

use crate::{response::APIResponse, telegramauth::TelegramAuth};

#[get("/self")]
pub async fn get_user(auth: TelegramAuth, db: &State<DatabaseConnection>) -> APIResponse {
    let user = auth.get_user().unwrap();
    let db_user = entity::user::Entity::find_by_id(user.id as i64)
        .one(db.deref())
        .await
        .ok()
        .flatten();

    let db_user = match db_user {
        Some(u) => u.calculate_casino_progress(db.deref()).await,
        None => {
            let mut active = entity::user::ActiveModel::new();
            active.id = ActiveValue::Set(user.id as i64);

            active.insert(db.deref()).await
        }
    };

    APIResponse::new(db_user.unwrap())
}
