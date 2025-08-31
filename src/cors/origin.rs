use rocket::http::uri::{Absolute, Uri};

#[derive(thiserror::Error, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum OriginParseError {
    #[error("The provided URI was invalid")]
    InvalidUri,
    #[error("The provided scheme is neither http nor https")]
    InvalidScheme,
}

#[derive(Eq, Hash, PartialEq, Debug)]
pub(crate) enum OriginScheme {
    Http,
    Https,
}

impl std::fmt::Display for OriginScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str_version = match self {
            OriginScheme::Http => "http",
            OriginScheme::Https => "https",
        };

        write!(f, "{str_version}")
    }
}

impl TryFrom<&str> for OriginScheme {
    type Error = OriginParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let lower = value.to_lowercase();
        match lower.as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            _ => Err(OriginParseError::InvalidScheme),
        }
    }
}

#[derive(Eq, Hash, PartialEq, Debug)]
pub struct Origin {
    pub(crate) host: String,
    pub(crate) scheme: OriginScheme,
    pub(crate) port: Option<u16>,
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let port_suffix = self.port.map(|port| format!(":{port}")).unwrap_or_default();
        write!(f, "{}://{}{}", self.scheme, self.host, port_suffix)
    }
}

impl TryFrom<&str> for Origin {
    type Error = OriginParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let uri = Absolute::parse(value).map_err(|_| OriginParseError::InvalidUri)?;
        let scheme = OriginScheme::try_from(uri.scheme())?;

        let Some(authority) = uri.authority() else {
            return Err(OriginParseError::InvalidUri);
        };

        let host = authority.host().to_owned();
        let port = authority.port();

        Ok(Self { scheme, host, port })
    }
}

impl TryFrom<String> for Origin {
    type Error = OriginParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&String> for Origin {
    type Error = OriginParseError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl<'a> TryFrom<Absolute<'a>> for Origin {
    type Error = OriginParseError;

    fn try_from(value: Absolute) -> Result<Self, Self::Error> {
        let scheme = OriginScheme::try_from(value.scheme())?;

        let Some(authority) = value.authority() else {
            return Err(OriginParseError::InvalidUri);
        };

        let host = authority.host().to_owned();
        let port = authority.port().to_owned();

        Ok(Self { scheme, host, port })
    }
}

impl<'a> TryFrom<&Absolute<'a>> for Origin {
    type Error = OriginParseError;

    fn try_from(value: &Absolute<'a>) -> Result<Self, Self::Error> {
        value.clone().try_into()
    }
}

impl<'a> TryFrom<Uri<'a>> for Origin {
    type Error = OriginParseError;
    fn try_from(value: Uri<'a>) -> Result<Self, Self::Error> {
        match value {
            Uri::Absolute(a) => a.try_into(),
            _ => Err(OriginParseError::InvalidUri),
        }
    }
}

impl<'a> TryFrom<&Uri<'a>> for Origin {
    type Error = OriginParseError;

    fn try_from(value: &Uri<'a>) -> Result<Self, Self::Error> {
        value.clone().try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() -> anyhow::Result<()> {
        let origin = Origin::try_from("https://test.com")?;

        assert_eq!(OriginScheme::Https, origin.scheme);
        assert_eq!("test.com", origin.host);
        assert_eq!(None, origin.port);

        let origin = Origin::try_from("https://test.com:42")?;

        assert_eq!(OriginScheme::Https, origin.scheme);
        assert_eq!("test.com", origin.host);
        assert_eq!(Some(42), origin.port);

        Ok(())
    }

    #[test]
    fn test_from_string() -> anyhow::Result<()> {
        let origin = Origin::try_from(String::from("https://test.com"))?;

        assert_eq!(OriginScheme::Https, origin.scheme);
        assert_eq!("test.com", origin.host);
        assert_eq!(None, origin.port);

        let origin = Origin::try_from(String::from("https://test.com:42"))?;

        assert_eq!(OriginScheme::Https, origin.scheme);
        assert_eq!("test.com", origin.host);
        assert_eq!(Some(42), origin.port);

        Ok(())
    }

    #[test]
    fn test_from_absolute() -> anyhow::Result<()> {
        let ab = Absolute::parse_owned("https://test.com".into()).expect("A valid URI");

        let origin = Origin::try_from(ab)?;

        assert_eq!(OriginScheme::Https, origin.scheme);
        assert_eq!("test.com", origin.host);
        assert_eq!(None, origin.port);

        let ab = Absolute::parse_owned("https://test.com:42".into()).expect("A valid URI");

        let origin = Origin::try_from(ab)?;

        assert_eq!(OriginScheme::Https, origin.scheme);
        assert_eq!("test.com", origin.host);
        assert_eq!(Some(42), origin.port);

        Ok(())
    }

    #[test]
    fn test_from_uri() -> anyhow::Result<()> {
        let uri = Uri::parse_any("https://test.com").expect("A valid uri");

        let origin = Origin::try_from(uri)?;

        assert_eq!(OriginScheme::Https, origin.scheme);
        assert_eq!("test.com", origin.host);
        assert_eq!(None, origin.port);

        let uri = Uri::parse_any("https://test.com:42").expect("A valid uri");

        let origin = Origin::try_from(uri)?;

        assert_eq!(OriginScheme::Https, origin.scheme);
        assert_eq!("test.com", origin.host);
        assert_eq!(Some(42), origin.port);

        Ok(())
    }

    #[test]
    fn test_to_str() -> anyhow::Result<()> {
        let origin = Origin {
            scheme: OriginScheme::Https,
            host: "test.com".into(),
            port: None,
        };

        assert_eq!("https://test.com", origin.to_string());

        let origin = Origin {
            scheme: OriginScheme::Https,
            host: "test.com".into(),
            port: Some(42),
        };

        assert_eq!("https://test.com:42", origin.to_string());

        Ok(())
    }

    #[test]
    fn test_invalid_scheme() {
        let err = Origin::try_from("ftp://test.com").unwrap_err();
        assert_eq!(err, OriginParseError::InvalidScheme);
    }

    #[test]
    fn test_invalid_uri() {
        let err = Origin::try_from("not a uri").unwrap_err();
        assert_eq!(err, OriginParseError::InvalidUri);
    }

    #[test]
    fn test_display_trait() {
        let origin = Origin {
            scheme: OriginScheme::Http,
            host: "localhost".into(),
            port: None,
        };
        assert_eq!(origin.to_string(), "http://localhost");

        let origin = Origin {
            scheme: OriginScheme::Http,
            host: "localhost".into(),
            port: Some(42),
        };
        assert_eq!(origin.to_string(), "http://localhost:42");
    }
}
