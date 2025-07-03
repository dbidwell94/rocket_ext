mod origin;

use http::HeaderName;
use itertools::Itertools;
use lasso::{Rodeo, Spur};
use origin::{Origin, OriginParseError};
pub use rocket::http::Method;
use rocket::{
    Data, Route,
    fairing::{Fairing, Info, Kind},
    http::{Header, Status},
    route::Outcome,
};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    time::Duration,
};

const CORS_ORIGIN: HeaderName = http::header::ACCESS_CONTROL_ALLOW_ORIGIN;
const CORS_HEADERS: HeaderName = http::header::ACCESS_CONTROL_ALLOW_HEADERS;
const CORS_METHODS: HeaderName = http::header::ACCESS_CONTROL_ALLOW_METHODS;
const CORS_AGE: HeaderName = http::header::ACCESS_CONTROL_MAX_AGE;
const CORS_CREDENTIALS: HeaderName = http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS;

const OPTIONS_ALLOW_HEADERS: HeaderName = http::header::ALLOW;

const REQUEST_METHOD: HeaderName = http::header::ACCESS_CONTROL_REQUEST_METHOD;
const REQUEST_HEADERS: HeaderName = http::header::ACCESS_CONTROL_REQUEST_HEADERS;
const REQUEST_ORIGIN: HeaderName = http::header::ORIGIN;

type PathMap = HashMap<Spur, HashSet<Method>>;

struct CorsState {
    interner: Rodeo,
    path_map: PathMap,
}

fn normalize_path(route: &Route) -> String {
    // We start with a leading slash for correctness
    let mut normalized = String::from("/");

    let path_str = route.uri.origin.path().as_str();

    // The first segment from splitting "/" is always empty, so we skip it.
    let segments: Vec<&str> = path_str.split('/').skip(1).collect();

    let processed_segments: Vec<&str> = segments
        .iter()
        .map(|segment| {
            // Check if the segment is dynamic
            if segment.starts_with('<') && segment.ends_with('>') {
                // Replace with a universal placeholder
                "<>"
            } else {
                // Keep the static segment as is
                *segment
            }
        })
        .collect();

    normalized.push_str(&processed_segments.join("/"));

    normalized
}

fn default_options_handler<'r>(
    req: &'r rocket::Request,
    _: Data<'r>,
) -> rocket::route::BoxFuture<'r> {
    Box::pin(async move {
        let Some(state) = req.rocket().state::<CorsState>() else {
            return Outcome::from(req, Status::InternalServerError);
        };

        let Some(route) = req.route() else {
            return Outcome::from(req, Status::NotFound);
        };

        let normalized_path = normalize_path(route);

        let methods_supported = state
            .interner
            .get(&normalized_path)
            .and_then(|key| state.path_map.get(&key))
            .is_some_and(|methods| !methods.is_empty());

        if methods_supported {
            Outcome::from(req, Status::NoContent)
        } else {
            Outcome::from(req, Status::MethodNotAllowed)
        }
    })
}

#[derive(thiserror::Error, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum CorsError {
    /// This error is returned when the `allow_credentials` method is called without a valid origin
    /// set. Credentials can only be sent when the `access-control-allow-origin` header is set to a
    /// valid origin.
    #[error(
        "access-control-allow-credentials was attempted to be set to true with a wildcard or empty access-control-allow-origin value"
    )]
    WithCredentialsMissingOrigin,
    #[error(transparent)]
    OriginParse(#[from] OriginParseError),
}

/// A fairing that implements Cross-Origin Resource Sharing (CORS) headers for Rocket applications.
/// This struct cannot be constructed on its own, but rather through the `CorsBuilder`. This is to
/// allow for validation of the CORS configuration before it is applied.
///
/// # Example
///
/// ```rust
/// use rocket_ext::cors::Cors;
///
/// #[rocket::main]
/// async fn main() -> anyhow::Result<()> {
///     let cors = Cors::builder()
///         .with_origin("https://example.com")?
///         .with_header("X-Custom-Header")
///         .with_method(rocket::http::Method::Get)
///         .with_max_age(std::time::Duration::from_secs(3600))
///         .allow_credentials()
///         .build()?;
///
///     let rocket = rocket::build().attach(cors);
///
///     Ok(())
/// }
///
///
/// ```
#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Cors {
    origins: OrWildcard<HashSet<Origin>>,
    headers: OrWildcard<HashSet<String>>,
    methods: HashSet<Method>,
    max_age: Option<Duration>,
    allow_creds: bool,
}

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Cross-Origin-Resource-Sharing",
            kind: Kind::Response | Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: rocket::Rocket<rocket::Build>) -> rocket::fairing::Result {
        let mut rodeo = Rodeo::default();

        // Lookup table to ensure that routes are not added multiple times
        let mut routes_added = HashSet::new();

        // These are the built OPTIONS routes that will be mounted
        let mut options_routes = Vec::new();

        // This is our Spur lookup table for routes and methods
        let mut path_map = PathMap::new();

        for route in rocket.routes() {
            let normalized_str = normalize_path(route);

            let key: Spur = rodeo.get_or_intern(&normalized_str);

            let method = route.method;
            let uri = &route.uri;

            if !routes_added.contains(uri.path()) {
                options_routes.push(Route::new(
                    rocket::http::Method::Options,
                    uri.path(),
                    default_options_handler,
                ));

                routes_added.insert(uri.path());
            }
            path_map.entry(key).or_default().insert(method);
        }

        let cors_state = CorsState {
            interner: rodeo,
            path_map,
        };

        Ok(rocket.mount("/", options_routes).manage(cors_state))
    }

    async fn on_response<'r>(&self, req: &'r rocket::Request<'_>, res: &mut rocket::Response<'r>) {
        // origin check failed, don't process OPTIONS or CORS
        if !self.handle_origin(req, res) {
            return;
        }
        if req.method() == Method::Options {
            self.handle_options(req, res);
        } else {
            self.handle_cors(req, res);
        }
    }
}

impl Cors {
    pub fn builder() -> CorsBuilder {
        CorsBuilder::default()
    }

    fn handle_origin<'r>(
        &self,
        req: &'r rocket::Request<'_>,
        res: &mut rocket::Response<'r>,
    ) -> bool {
        let Some(origin) = req
            .headers()
            .get_one(REQUEST_ORIGIN.as_str())
            .and_then(|s| Origin::try_from(s).ok())
        else {
            // If there is no origin header, we do not set the CORS or OPTIONS headers
            return false;
        };

        match self.origins {
            OrWildcard::Wildcard => {
                res.set_header(Header::new(CORS_ORIGIN.as_str(), "*".to_string()));
            }
            OrWildcard::Explicit(ref origins) => {
                if origins.contains(&origin) {
                    res.set_header(Header::new(CORS_ORIGIN.as_str(), origin.to_string()));
                } else {
                    // If the origin is not allowed, we do not set the header
                    return false;
                }
            }
        }

        true
    }

    fn handle_cors<'r>(&self, req: &'r rocket::Request<'_>, res: &mut rocket::Response<'r>) {
        let Some(remote_origin) = req
            .headers()
            .get_one(REQUEST_ORIGIN.as_str())
            .and_then(|s| Origin::try_from(s).ok())
        else {
            return;
        };

        match self.origins {
            OrWildcard::Wildcard => {
                res.set_header(Header::new(CORS_ORIGIN.as_str(), "*".to_string()));
            }
            OrWildcard::Explicit(ref origins) => {
                if origins.contains(&remote_origin) {
                    res.set_header(Header::new(CORS_ORIGIN.as_str(), remote_origin.to_string()));
                } else {
                    // If the origin is not allowed, we do not set the header
                    return;
                }
            }
        }

        if self.allow_creds {
            res.set_header(Header::new(CORS_CREDENTIALS.as_str(), "true".to_string()));
        }
    }

    fn handle_options<'r>(&self, req: &'r rocket::Request<'_>, res: &mut rocket::Response<'r>) {
        // SETUP
        let Some(cors_state) = req.rocket().state::<CorsState>() else {
            return;
        };
        let Some(path_methods) = req
            .route()
            .map(normalize_path)
            .and_then(|path| cors_state.interner.get(&path))
            .and_then(|key| cors_state.path_map.get(&key))
        else {
            return;
        };
        let requested_method = req
            .headers()
            .get_one(REQUEST_METHOD.as_str())
            .and_then(|s| Method::from_str(s).ok());

        let requested_headers = req.headers().get_one(REQUEST_HEADERS.as_str()).map(|h| {
            h.split(',')
                .map(|s| s.trim())
                .map(|s| s.to_owned())
                .collect::<HashSet<_>>()
        });
        let truely_allowed_methods: HashSet<&Method> =
            path_methods.intersection(&self.methods).collect();

        // CHECKS

        // 1: make sure we have allowed methods
        if truely_allowed_methods.is_empty() {
            return;
        }

        // 2: Make sure the requested method is in the allowed methods.
        if let Some(requested_method) = requested_method
            && !truely_allowed_methods.contains(&requested_method)
        {
            return;
        }

        // 3: Make sure the requested headers are allowed.
        if let Some(ref requested_headers) = requested_headers {
            if let OrWildcard::Explicit(ref headers) = self.headers {
                if !requested_headers.is_subset(headers) {
                    // If the requested headers are not a subset of the allowed headers, we do not
                    // set the header
                    return;
                }
            }
        }

        // BUILD HEADERS

        // Access-Control-Allow-Methods
        let methods_str = truely_allowed_methods.iter().join(", ");
        res.set_header(Header::new(CORS_METHODS.as_str(), methods_str));

        // Access-Control-Allow-Headers
        if let Some(requested_headers) = requested_headers {
            res.set_header(Header::new(
                CORS_HEADERS.as_str(),
                requested_headers.iter().join(", "),
            ));
        }

        // Access-Control-Max-Age
        if let Some(max_age) = self.max_age {
            res.set_header(Header::new(
                CORS_AGE.as_str(),
                max_age.as_secs().to_string(),
            ));
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
enum OrWildcard<T>
where
    T: Default + Eq + PartialEq + Default,
{
    Wildcard,
    Explicit(T),
}

impl<T> Default for OrWildcard<T>
where
    T: Default + Eq + PartialEq + Default,
{
    fn default() -> Self {
        OrWildcard::Explicit(T::default())
    }
}

impl<T> OrWildcard<T>
where
    T: Default + Eq + PartialEq + Default,
{
    fn take_or_default(self) -> T {
        match self {
            OrWildcard::Wildcard => T::default(),
            OrWildcard::Explicit(value) => value,
        }
    }
}

/// A builder for the `Cors` fairing. This allows for a more flexible and dynamic way to configure
/// cors headers without having to create a new `Cors` instance every time a configuration change
/// is needed.
#[derive(Default)]
pub struct CorsBuilder {
    allow_origin: Option<OrWildcard<HashSet<Origin>>>,
    allow_method: Option<HashSet<Method>>,
    allow_header: Option<OrWildcard<HashSet<String>>>,
    access_max_age: Option<Duration>,
    allow_credentials: bool,
}

impl CorsBuilder {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// This will dynamically set the `access-control-allow-origin` header depending on if the
    /// incoming request is coming from a valid origin set by this method. As only 1 origin is
    /// allowed in this header, this must be dynamic to accept more than 1 origin.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_origin("http://test.com")
    ///     .expect("A valid URI")
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_origin(
        mut self,
        url: impl TryInto<Origin, Error = OriginParseError>,
    ) -> Result<Self, CorsError> {
        let mut origins = self
            .allow_origin
            .take()
            .unwrap_or_default()
            .take_or_default();
        origins.insert(url.try_into()?);

        self.allow_origin = Some(OrWildcard::Explicit(origins));

        Ok(self)
    }

    /// This will dynamically set the `access-control-allow-origin` header depending on if the
    /// incoming request is coming from a valid origin set by this method. As only 1 origin is
    /// allowed in this header, this must be dynamic to accept more than 1 origin.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_origins(["http://test.com", "https://othertest.com"])
    ///     .expect("A valid URI")
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_origins<T, I>(mut self, urls: I) -> Result<Self, CorsError>
    where
        I: IntoIterator<Item = T>,
        T: TryInto<Origin, Error = OriginParseError>,
    {
        let mut origins = self
            .allow_origin
            .take()
            .unwrap_or_default()
            .take_or_default();

        for url in urls {
            origins.insert(url.try_into()?);
        }
        self.allow_origin = Some(OrWildcard::Explicit(origins));

        Ok(self)
    }

    /// This will set the `access-control-allow-origin` header to allow any origin. This is
    /// equivalent to setting the header to `*`, which means any origin is allowed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_any_origin()
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_any_origin(mut self) -> Self {
        self.allow_origin = Some(OrWildcard::Wildcard);
        self
    }

    /// This will set the `access-control-allow-methods` header to allow the specified HTTP method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::{Cors, Method};
    /// let cors = Cors::builder()
    ///     .with_method(Method::Get)
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_method(mut self, method: Method) -> Self {
        let mut methods = self.allow_method.take().unwrap_or_default();
        methods.insert(method);
        self.allow_method = Some(methods);

        self
    }

    /// This will set the `access-control-allow-methods` header to allow the specified HTTP method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::{Cors, Method};
    /// let cors = Cors::builder()
    ///     .with_methods(&[Method::Get, Method::Post])
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_methods(mut self, methods_to_insert: &[Method]) -> Self {
        let mut methods = self.allow_method.take().unwrap_or_default();
        methods.extend(methods_to_insert);

        self.allow_method = Some(methods);
        self
    }

    /// This will set the `access-control-allow-headers` header to allow the specified header.
    ///
    /// # Example
    /// ```
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_header("X-Custom-Header")
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_header(mut self, header_name: impl ToString) -> Self {
        let mut headers = self
            .allow_header
            .take()
            .unwrap_or_default()
            .take_or_default();
        headers.insert(header_name.to_string());

        self.allow_header = Some(OrWildcard::Explicit(headers));

        self
    }

    /// This will set the `access-control-allow-headers` header to allow the specified header.
    ///
    /// # Example
    /// ```
    /// use rocket_ext::cors::Cors;
    /// use http::header::{ACCEPT,CONTENT_TYPE};
    /// let cors = Cors::builder()
    ///     .with_headers(&["X-Custom-Header", "X-Other-Header"])
    ///     // you may pass an http::header::HeaderName as well
    ///     .with_headers(&[ACCEPT, CONTENT_TYPE])
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_headers(mut self, headers: &[impl ToString]) -> Self {
        let mut header_set = self
            .allow_header
            .take()
            .unwrap_or_default()
            .take_or_default();

        for header in headers {
            header_set.insert(header.to_string());
        }
        self.allow_header = Some(OrWildcard::Explicit(header_set));

        self
    }

    /// This will set the `access-control-allow-headers` header to allow any header. This is
    /// equivalent to setting the header to `*`, which means any header is allowed. However, in
    /// order to be more explicit, CORS will respond with the headers sent in the request. For
    /// example: if the request contains the headers `X-Custom-Header` and `X-Other-Header`, then
    /// the response will contain the header `Access-Control-Allow-Headers: X-Custom-Header,
    /// X-Other-Header`.
    ///
    /// # Example
    /// ```rust
    /// use rocket_ext::cors::Cors;
    ///
    /// let cors = Cors::builder()
    ///     .with_any_header()
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_any_header(mut self) -> Self {
        self.allow_header = Some(OrWildcard::Wildcard);
        self
    }

    /// This will set the `access-control-max-age` header to specify how long the results of a
    /// preflight request can be cached.
    ///
    /// # Example
    /// ```rust
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_max_age(std::time::Duration::from_secs(3600))
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.access_max_age = Some(age);

        self
    }

    /// This will set the `access-control-allow-credentials` header to allow credentials to be
    /// sent. This is only valid if an `access-control-allow-origin` header is also set.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .allow_credentials()
    ///     .with_origin("https://example.com")
    ///     .expect("A valid URI")
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn allow_credentials(mut self) -> Self {
        self.allow_credentials = true;
        self
    }

    /// This will build the `Cors` configuration. If `allow_credentials` is set to true, then
    /// the `with_origin` must have been called, otherwise an error will be returned.
    ///
    /// See the [official CORS documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS/Errors/CORSNotSupportingCredentials)
    ///
    /// # Example
    /// ```rust
    /// use rocket_ext::cors::{Cors, Method};
    ///
    /// let cors = Cors::builder()
    ///     .allow_credentials()
    ///     .with_origin("https://example.com")
    ///     .expect("A valid URI")
    ///     .with_max_age(std::time::Duration::from_secs(3600))
    ///     .with_header("X-Custom-Header")
    ///     .with_method(Method::Get)
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn build(self) -> Result<Cors, CorsError> {
        if self.allow_credentials && self.allow_origin.is_none() {
            return Err(CorsError::WithCredentialsMissingOrigin);
        }

        Ok(Cors {
            origins: self.allow_origin.unwrap_or_default(),
            headers: self.allow_header.unwrap_or_default(),
            methods: self.allow_method.unwrap_or_default(),
            max_age: self.access_max_age,
            allow_creds: self.allow_credentials,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::cors::origin::*;
    use rocket::{Ignite, Rocket, get, local::asynchronous::Client, post, routes};

    #[get("/some/route")]
    fn get_route() {}

    #[post("/some/route")]
    fn post_route() {}

    #[get("/some/dynamic/<_data>")]
    fn get_dynamic(_data: &str) {}

    #[post("/some/dynamic/<_data>")]
    fn post_dynamic(_data: &str) {}

    async fn rocket_with_cors(cors: Cors, routes: &[Route]) -> anyhow::Result<Rocket<Ignite>> {
        Ok(rocket::build()
            .attach(cors)
            .mount("/", routes)
            .ignite()
            .await?)
    }

    #[test]
    fn test_cors_builder_origin() -> anyhow::Result<()> {
        let cors = Cors::builder().with_origin("https://test.com")?.build()?;

        let origins = cors.origins.take_or_default();

        assert_eq!(origins.len(), 1);
        assert!(origins.contains(&Origin {
            scheme: OriginScheme::Https,
            host: String::from("test.com")
        }));

        Ok(())
    }

    #[test]
    fn test_multiple_origins() -> anyhow::Result<()> {
        let cors = Cors::builder()
            .with_origins(["https://test.com", "https://example.com"])?
            .build()?;

        let origins = cors.origins.take_or_default();

        assert_eq!(origins.len(), 2);
        assert!(origins.contains(&Origin {
            scheme: OriginScheme::Https,
            host: String::from("test.com")
        }));
        assert!(origins.contains(&Origin {
            scheme: OriginScheme::Https,
            host: String::from("example.com")
        }));

        Ok(())
    }

    #[test]
    fn test_build_with_creds_no_origin_fails() -> anyhow::Result<()> {
        let cors = Cors::builder().allow_credentials().build();

        assert_eq!(cors, Err(CorsError::WithCredentialsMissingOrigin));
        Ok(())
    }

    #[test]
    fn test_build_with_creds_and_origin_passes() -> anyhow::Result<()> {
        let cors = Cors::builder()
            .allow_credentials()
            .with_origin("https://test.com")?
            .build();

        assert!(cors.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_options_allow_headers() -> anyhow::Result<()> {
        let rocket =
            rocket_with_cors(Cors::builder().build()?, &routes![get_route, post_route]).await?;

        let client = Client::tracked(rocket).await?;

        let req = client.options("/some/route").dispatch().await;

        let allow_header = req
            .headers()
            .get_one(OPTIONS_ALLOW_HEADERS.as_str())
            .map(|s| {
                s.split(", ")
                    .map(|method| Method::from_str(method).expect("A valid method"))
                    .collect::<HashSet<_>>()
            });

        let mut expected_set = HashSet::new();
        expected_set.insert(Method::Post);
        expected_set.insert(Method::Get);

        assert_eq!(allow_header, Some(expected_set));

        Ok(())
    }

    #[tokio::test]
    async fn test_options_dynamic_allow_headers() -> anyhow::Result<()> {
        let rocket = rocket_with_cors(
            Cors::builder().build()?,
            &routes![get_dynamic, post_dynamic],
        )
        .await?;

        let client = Client::tracked(rocket).await?;

        let res = client.options("/some/dynamic/string").dispatch().await;

        let allow_header = res
            .headers()
            .get_one(OPTIONS_ALLOW_HEADERS.as_str())
            .map(|s| {
                s.split(", ")
                    .map(|s| Method::from_str(s).expect("A valid method"))
                    .collect::<HashSet<_>>()
            });

        let mut expected_header = HashSet::new();
        expected_header.insert(Method::Get);
        expected_header.insert(Method::Post);

        assert_eq!(allow_header, Some(expected_header));

        Ok(())
    }

    #[tokio::test]
    async fn test_build_with_allowed_headers() -> anyhow::Result<()> {
        let cors = Cors::builder()
            .with_methods(&[Method::Get, Method::Post])
            .build()?;

        let rocket = rocket_with_cors(cors, &routes![get_route]).await?;

        let client = Client::tracked(rocket).await?;

        let res = client.get("/some/route").dispatch().await;

        let expected_methods = [Method::Get.to_string(), Method::Post.to_string()];

        let method_header = res
            .headers()
            .get_one(CORS_METHODS.as_str())
            .map(|v| v.split(", ").collect::<Vec<_>>())
            .unwrap_or_default();

        assert!(
            expected_methods
                .iter()
                .all(|expected| method_header.contains(&expected.as_str()))
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_origin_header() -> anyhow::Result<()> {
        const TEST_ORIGIN: &str = "https://test.com";
        let cors = Cors::builder().with_origin(TEST_ORIGIN)?.build()?;

        let rocket = rocket_with_cors(cors, &routes![get_route]).await?;

        let client = Client::tracked(rocket).await?;

        let mut req = client.get("/some/route");
        req.add_header(Header::new("origin", TEST_ORIGIN));
        let res = req.dispatch().await;

        let origin_header = res.headers().get_one(CORS_ORIGIN.as_str());

        assert_eq!(origin_header, Some(TEST_ORIGIN));

        Ok(())
    }

    #[tokio::test]
    async fn test_origin_header_wildcard() -> anyhow::Result<()> {
        const TEST_ORIGIN: &str = "https://test.com";
        let cors = Cors::builder().with_any_origin().build()?;

        let rocket = rocket_with_cors(cors, &routes![get_route]).await?;

        let client = Client::tracked(rocket).await?;

        let mut req = client.get("/some/route");
        req.add_header(Header::new("origin", TEST_ORIGIN));
        let res = req.dispatch().await;

        let origin_header = res.headers().get_one(CORS_ORIGIN.as_str());

        assert_eq!(origin_header, Some(TEST_ORIGIN));

        Ok(())
    }

    #[tokio::test]
    async fn test_origin_with_credentials() -> anyhow::Result<()> {
        const TEST_ORIGIN: &str = "https://test.com";
        let cors = Cors::builder()
            .with_origin(TEST_ORIGIN)?
            .allow_credentials()
            .build()?;

        let rocket = rocket_with_cors(cors, &routes![get_route]).await?;

        let client = Client::tracked(rocket).await?;

        let mut req = client.get("/some/route");
        req.add_header(Header::new("origin", TEST_ORIGIN));
        let res = req.dispatch().await;

        let origin_header = res.headers().get_one(CORS_ORIGIN.as_str());
        let credential_header = res.headers().get_one(CORS_CREDENTIALS.as_str());

        assert_eq!(origin_header, Some(TEST_ORIGIN));
        assert_eq!(credential_header, Some("true"));

        Ok(())
    }

    #[tokio::test]
    async fn test_cors_origin_not_matching() -> anyhow::Result<()> {
        let cors = Cors::builder().with_origin("https://test.com")?.build()?;

        let rocket = rocket_with_cors(cors, &routes![get_route]).await?;

        let client = Client::tracked(rocket).await?;

        let mut req = client.get("/some/route");
        req.add_header(Header::new("origin", "https://notvalid.com"));

        let res = req.dispatch().await;

        let header = res.headers().get_one(CORS_ORIGIN.as_str());

        assert!(header.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_cors_origin_not_matching_scheme() -> anyhow::Result<()> {
        let cors = Cors::builder().with_origin("https://test.com")?.build()?;

        let rocket = rocket_with_cors(cors, &routes![get_route]).await?;

        let client = Client::tracked(rocket).await?;

        let mut req = client.get("/some/route");
        req.add_header(Header::new("origin", "http://test.com"));
        let res = req.dispatch().await;

        let header = res.headers().get_one(CORS_ORIGIN.as_str());

        assert!(header.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_cors_age() -> anyhow::Result<()> {
        let cors = Cors::builder()
            .with_max_age(Duration::from_secs(15))
            .build()?;

        let rocket = rocket_with_cors(cors, &routes![get_route]).await?;

        let client = Client::tracked(rocket).await?;

        let res = client.get("/some/route").dispatch().await;

        let header = res.headers().get_one(CORS_AGE.as_str());

        assert_eq!(header, Some("15"));

        Ok(())
    }

    #[tokio::test]
    async fn test_cors_allowed_headers() -> anyhow::Result<()> {
        let cors = Cors::builder()
            .with_header("accept")
            .with_header("custom")
            .build()?;

        let expected_headers = ["accept", "custom"];

        let rocket = rocket_with_cors(cors, &routes![get_route]).await?;

        let client = Client::tracked(rocket).await?;

        let res = client.get("/some/route").dispatch().await;

        let header = res
            .headers()
            .get_one(CORS_HEADERS.as_str())
            .map(|val| val.split(", ").collect::<Vec<_>>())
            .unwrap_or_default();

        assert!(
            expected_headers
                .iter()
                .all(|expected| header.contains(expected))
        );

        Ok(())
    }
}
