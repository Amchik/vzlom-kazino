use rocket::{routes, Route};

mod casino;

pub mod catchers;

pub fn get_routes() -> Vec<Route> {
    routes![casino::get_user]
}
