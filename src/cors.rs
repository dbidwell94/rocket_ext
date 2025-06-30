mod origin;

use origin::{Origin, OriginParseError};
pub use rocket::http::Method;
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::Header,
};
use std::{collections::HashSet, time::Duration};

const CORS_ORIGIN: &str = "Access-Control-Allow-Origin";
const CORS_HEADERS: &str = "Access-Control-Allow-Headers";
const CORS_METHODS: &str = "Access-Control-Allow-Methods";
const CORS_AGE: &str = "Access-Control-Max-Age";
const CORS_CREDENTIALS: &str = "Access-Control-Allow-Credentials";

#[derive(thiserror::Error, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum CorsError {
    #[error(
        "access-control-allow-credentials was attempted to be set to true with a wildcard access-control-allow-origin value"
    )]
    WithCredentialsMissingOrigin,
    #[error(transparent)]
    OriginParse(#[from] OriginParseError),
}

/// A fairing that implements Cross-Origin Resource Sharing (CORS) headers for Rocket applications.
/// This struct cannot be constructed on its own, but rather through the `CorsBuilder`. This is to
/// allow for validation of the CORS configuration before it is applied.
///
/// #Example
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
    origins: HashSet<Origin>,
    headers: HashSet<String>,
    methods: HashSet<Method>,
    max_age: Option<Duration>,
    allow_creds: bool,
}

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Cross-Origin-Resource-Sharing Fairing",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, req: &'r rocket::Request<'_>, res: &mut rocket::Response<'r>) {
        let remote_origin = req
            .headers()
            .get_one("origin")
            .and_then(|s| Origin::try_from(s).ok());

        let cors_origin = if self.origins.is_empty() {
            Some(String::from("*"))
        } else {
            remote_origin
                .and_then(|origin| self.origins.get(&origin))
                .map(|origin| origin.to_string())
        };

        let Some(cors_origin) = cors_origin else {
            return;
        };

        res.set_header(Header::new(CORS_ORIGIN, cors_origin));
        if !self.headers.is_empty() {
            let cors_headers = self.headers.iter().cloned().collect::<Vec<_>>().join(", ");
            res.set_header(Header::new(CORS_HEADERS, cors_headers));
        }
        if !self.methods.is_empty() {
            let cors_methods = self
                .methods
                .iter()
                .map(|method| method.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            res.set_header(Header::new(CORS_METHODS, cors_methods));
        }
        if let Some(max_age) = self.max_age {
            res.set_header(Header::new(CORS_AGE, max_age.as_secs().to_string()));
        }
        if self.allow_creds {
            res.set_header(Header::new(CORS_CREDENTIALS, "true"));
        }
    }
}

impl Cors {
    pub fn builder() -> CorsBuilder {
        CorsBuilder::default()
    }
}

#[derive(Default)]
pub struct CorsBuilder {
    allow_origin: Option<HashSet<Origin>>,
    allow_method: Option<HashSet<Method>>,
    allow_header: Option<HashSet<String>>,
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
        let mut origins = self.allow_origin.take().unwrap_or_default();
        origins.insert(url.try_into()?);

        self.allow_origin = Some(origins);

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
        let mut origins = self.allow_origin.take().unwrap_or_default();
        for url in urls {
            origins.insert(url.try_into()?);
        }
        self.allow_origin = Some(origins);

        Ok(self)
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
    /// #Example
    /// ```
    /// use rocket_ext::cors::Cors;
    /// let cors = Cors::builder()
    ///     .with_header("X-Custom-Header")
    ///     .build()
    ///     .expect("A valid CORS configuration");
    /// ```
    pub fn with_header(mut self, header_name: impl Into<String>) -> Self {
        let mut headers = self.allow_header.take().unwrap_or_default();
        headers.insert(header_name.into());
        self.allow_header = Some(headers);

        self
    }

    /// This will set the `access-control-max-age` header to specify how long the results of a
    /// preflight request can be cached.
    ///
    /// #Example
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
    /// #Example
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
    /// #Example
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
    use super::*;
    use crate::cors::origin::*;
    use rocket::{Ignite, Rocket, get, local::asynchronous::Client, routes};

    #[get("/some/route")]
    fn get_route() {}

    async fn rocket_with_cors(cors: Cors) -> anyhow::Result<Rocket<Ignite>> {
        Ok(rocket::build()
            .attach(cors)
            .mount("/", routes![get_route])
            .ignite()
            .await?)
    }

    #[test]
    fn test_cors_builder_origin() -> anyhow::Result<()> {
        let cors = Cors::builder().with_origin("https://test.com")?.build()?;

        assert_eq!(cors.origins.len(), 1);
        assert!(cors.origins.contains(&Origin {
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

        assert_eq!(cors.origins.len(), 2);
        assert!(cors.origins.contains(&Origin {
            scheme: OriginScheme::Https,
            host: String::from("test.com")
        }));
        assert!(cors.origins.contains(&Origin {
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
    async fn test_build_with_allowed_headers() -> anyhow::Result<()> {
        let cors = Cors::builder()
            .with_methods(&[Method::Get, Method::Post])
            .build()?;

        let rocket = rocket_with_cors(cors).await?;

        let client = Client::tracked(rocket).await?;

        let res = client.get("/some/route").dispatch().await;

        let expected_methods = [Method::Get.to_string(), Method::Post.to_string()];

        let method_header = res
            .headers()
            .get_one(CORS_METHODS)
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

        let rocket = rocket_with_cors(cors).await?;

        let client = Client::tracked(rocket).await?;

        let mut req = client.get("/some/route");
        req.add_header(Header::new("origin", TEST_ORIGIN));
        let res = req.dispatch().await;

        let origin_header = res.headers().get_one(CORS_ORIGIN);

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

        let rocket = rocket_with_cors(cors).await?;

        let client = Client::tracked(rocket).await?;

        let mut req = client.get("/some/route");
        req.add_header(Header::new("origin", TEST_ORIGIN));
        let res = req.dispatch().await;

        let origin_header = res.headers().get_one(CORS_ORIGIN);
        let credential_header = res.headers().get_one(CORS_CREDENTIALS);

        assert_eq!(origin_header, Some(TEST_ORIGIN));
        assert_eq!(credential_header, Some("true"));

        Ok(())
    }

    #[tokio::test]
    async fn test_cors_origin_not_matching() -> anyhow::Result<()> {
        let cors = Cors::builder().with_origin("https://test.com")?.build()?;

        let rocket = rocket_with_cors(cors).await?;

        let client = Client::tracked(rocket).await?;

        let mut req = client.get("/some/route");
        req.add_header(Header::new("origin", "https://notvalid.com"));

        let res = req.dispatch().await;

        let header = res.headers().get_one(CORS_ORIGIN);

        assert!(header.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_cors_origin_not_matching_scheme() -> anyhow::Result<()> {
        let cors = Cors::builder().with_origin("https://test.com")?.build()?;

        let rocket = rocket_with_cors(cors).await?;

        let client = Client::tracked(rocket).await?;

        let mut req = client.get("/some/route");
        req.add_header(Header::new("origin", "http://test.com"));
        let res = req.dispatch().await;

        let header = res.headers().get_one(CORS_ORIGIN);

        assert!(header.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_cors_age() -> anyhow::Result<()> {
        let cors = Cors::builder()
            .with_max_age(Duration::from_secs(15))
            .build()?;

        let rocket = rocket_with_cors(cors).await?;

        let client = Client::tracked(rocket).await?;

        let res = client.get("/some/route").dispatch().await;

        let header = res.headers().get_one(CORS_AGE);

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

        let rocket = rocket_with_cors(cors).await?;

        let client = Client::tracked(rocket).await?;

        let res = client.get("/some/route").dispatch().await;

        let header = res
            .headers()
            .get_one(CORS_HEADERS)
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
