use rocket::{catch, http::Status, Request};

use crate::response::APIResponse;

#[catch(404)]
pub fn no_endpoint_catcher() -> APIResponse {
    APIResponse::error(404, "Endpoint doesn't exists")
}

#[catch(default)]
pub fn default_catcher(status: Status, _: &Request) -> APIResponse {
    APIResponse::error(status.code, status.reason_lossy())
}
