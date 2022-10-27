mod appcontext;
mod response;
mod routes;
mod telegramauth;

use appcontext::AppContext;
use rocket::{config::Ident, Config};

use migration::{sea_orm::Database, Migrator, MigratorTrait};
use routes::get_routes;

#[rocket::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::connect("sqlite://vzlom-kazino.db").await?;
    Migrator::up(&db, None).await?;

    // FIXME: config or cli, but not that...
    let ctx = AppContext {
        telegram_token: std::env::var("TELEGRAM_TOKEN")
            .expect("pls set $TELEGRAM_TOKEN env var, TODO: "),
    };

    let _rocket = rocket::build()
        .configure(Config {
            ident: Ident::none(),
            ..Default::default()
        })
        .mount("/", get_routes())
        .manage(db)
        .manage(ctx)
        .launch()
        .await?;

    Ok(())
}
