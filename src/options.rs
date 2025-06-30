use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{Header, Method, Status},
};
use std::io::Cursor;

/// A `rocket::fairing::Fairing` which automatically responds to an HTTP OPTIONS request as long as
/// there is a path registered for the requested method. If `/test/route` is registered with both
/// `GET` and `POST`, then this fairing will respond with the header `Allow: GET, POST` indicating
/// that `/test/route` has both `GET` and `POST` routes implemented.
///
///# Example
/// ```rust
/// use rocket_ext::prelude::Options;
///
/// #[rocket::main]
/// async fn main() {
///     let app = rocket::build().attach(Options);
/// }
/// ```
pub struct Options;

#[rocket::async_trait]
impl Fairing for Options {
    fn info(&self) -> Info {
        Info {
            name: "Options Fairing",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, req: &'r rocket::Request<'_>, res: &mut rocket::Response<'r>) {
        if req.method() != Method::Options {
            return;
        }

        let req_path = req.uri().path();

        let allowed_methods = req
            .rocket()
            .routes()
            .filter(|r| r.uri.path() == req_path)
            .map(|r| r.method.as_str())
            .collect::<Vec<&str>>();

        if allowed_methods.is_empty() {
            return;
        }

        res.set_header(Header::new("Allow", allowed_methods.join(", ")));
        res.set_status(Status::Ok);
        res.set_sized_body(0, Cursor::new(""));
    }
}

#[cfg(test)]
mod tests {
    use rocket::{get, http::Status, local::asynchronous::Client, post, routes};

    use crate::options::Options;
    #[post("/test/route")]
    fn some_post_route() {}

    #[get("/test/route")]
    fn some_get_route() {}

    #[tokio::test]
    async fn test_post_route_options() -> anyhow::Result<()> {
        let rocket_app = rocket::build()
            .mount("/", routes![some_post_route])
            .attach(Options)
            .ignite()
            .await?;

        let client = Client::tracked(rocket_app).await?;

        let req = client.options("/test/route").dispatch().await;

        let headers = req.headers().get_one("Allow");

        assert_eq!(headers, Some("POST"));
        assert_eq!(req.status(), Status::Ok);
        assert_eq!(req.into_string().await, Some("".into()));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_and_post_route_options() -> anyhow::Result<()> {
        let rocket_app = rocket::build()
            .mount("/", routes![some_get_route, some_post_route])
            .attach(Options)
            .ignite()
            .await?;

        let client = Client::tracked(rocket_app).await?;

        let res = client.options("/test/route").dispatch().await;

        let expected_methods = ["GET", "POST"];
        let allow_headers = res
            .headers()
            .get_one("Allow")
            .map(|val| val.split(", ").collect::<Vec<_>>())
            .expect("There to be an Allow header");

        assert!(
            expected_methods
                .iter()
                .all(|header| allow_headers.contains(header))
        );
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(res.into_string().await, Some("".into()));

        Ok(())
    }
}
