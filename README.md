# rocket_ext

<!--toc:start-->

- [rocket_ext](#rocket_ext)
  - [Features](#features)
  - [Usage](#usage)
    - [Docs](#docs)
    - [Quick Start](#quick-start)
  - [API](#api)
    - [Building CORS Fairing](#building-cors-fairing)
    - [Error Handling](#error-handling)
  - [License](#license)
  <!--toc:end-->

A Rust extension crate for [Rocket](https://rocket.rs/) that provides a flexible
and configurable Cross-Origin Resource Sharing (CORS) fairing,
as well as an `Options` fairing for easy pre-flight request handling.

## Features

- Easily configure allowed origins, methods, and headers for CORS.
- Support for credentials and max-age.
- Builder pattern for ergonomic configuration.
- Dynamic origin and header handling.
- Fully async and compatible with Rocket's fairing system.
- Options method support for preflight requests.

## Usage

Add to your `Cargo.toml`:

```toml
rocket-ext = { version = "*" }
```

### Docs

Docs are available at [docs.rs/rocket_ext](https://docs.rs/rocket_ext/latest/rocket_ext).

### Quick Start

```rust
use rocket_ext::{cors::Cors, options::Options};
// Also available under `rocket_ext::prelude::*`

#[rocket::main]
async fn main() -> anyhow::Result<()> {
    let cors = Cors::builder()
        .with_origin("https://example.com")?
        .with_header("X-Custom-Header")
        .with_method(rocket::http::Method::Get)
        .with_max_age(std::time::Duration::from_secs(3600))
        .allow_credentials()
        .build()?;

    let rocket = rocket::build().attach(cors).attach(Options);

    Ok(())
}
```

## API

### Building CORS Fairing

- `Cors::builder()`: Start building a CORS configuration.
- `.with_origin(origin)`: Allow a specific origin.
- `.with_origins([origins])`: Allow multiple origins.
- `.with_method(method)`: Allow a specific HTTP method.
- `.with_methods([methods])`: Allow multiple HTTP methods.
- `.with_header(header)`: Allow a specific header.
- `.with_headers([headers])`: Allow multiple headers.
- `.with_any_header()`: Allow any header.
- `.with_max_age(duration)`: Set the max age for preflight requests.
- `.allow_credentials()`: Allow credentials.

### Error Handling

- If you attempt to allow credentials without specifying an origin,
  a `CorsError::WithCredentialsMissingOrigin` will be returned.
- If you pass in an invalid origin, a `CorsError::InvalidOrigin` will be returned.
  An `Origin` must contain a scheme, host, and optionally a port.
  (e.g. `http://example.com:8080`, `https://example.com`, or `http://localhost:8005`)

## License

MIT OR Apache-2.0
