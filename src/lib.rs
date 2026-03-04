use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::BTreeSet,
    fmt::Display,
    hash::Hash,
    ops::{Deref, DerefMut},
    time::Duration,
};

const DEFAULT_DELIMITER: &str = "~";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Default)]
struct TokenAttributeSet {
    inner: BTreeSet<Attribute>,
}

#[derive(Debug)]
pub struct TokenOutput {
    attrs: TokenAttributeSet,
    delimiter: &'static str,
}

#[derive(Debug)]
pub struct TokenBuilder<T> {
    state: T,
}

#[derive(Debug)]
pub struct WithStartAndEnd<S, E> {
    start: S,
    end: E,
}

#[derive(Debug)]
pub struct WithKey<S, E> {
    time: WithStartAndEnd<S, E>,
    key: String,
    attrs: TokenAttributeSet,
    delimiter: &'static str,
}

#[derive(Debug, Eq, PartialOrd, Ord)]
pub enum Attribute {
    Start(chrono::DateTime<Utc>),
    End(chrono::DateTime<Utc>),
    Url(String),
    Hmac(String),
}

pub enum TimeValue {
    Fixed(chrono::DateTime<Utc>),
    Relative(chrono::Duration),
}

impl TokenAttributeSet {
    fn get_all(&self) -> impl Iterator<Item = &Attribute> {
        self.inner.iter()
    }

    fn get_for_token(&self) -> impl Iterator<Item = &Attribute> {
        self.inner.iter().filter(|a| a.for_token())
    }
}

impl Deref for TokenAttributeSet {
    type Target = BTreeSet<Attribute>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TokenAttributeSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl TokenOutput {
    fn new(attrs: TokenAttributeSet, delimiter: &'static str) -> Self {
        Self { attrs, delimiter }
    }

    pub fn token(&self) -> String {
        self.attrs
            .get_for_token()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(self.delimiter)
    }
}

impl TokenBuilder<()> {
    pub fn with_start_and_end<S, E>(
        start: S,
        end: E,
    ) -> TokenBuilder<WithStartAndEnd<S, E>>
    where
        S: TryInto<TimeValue, Error = &'static str>,
        E: TryInto<TimeValue, Error = &'static str>,
    {
        TokenBuilder {
            state: WithStartAndEnd { start, end },
        }
    }
}

impl<S, E> TokenBuilder<WithStartAndEnd<S, E>> {
    pub fn with_key(self, key: impl ToString) -> TokenBuilder<WithKey<S, E>> {
        TokenBuilder {
            state: WithKey {
                time: self.state,
                key: key.to_string(),
                attrs: Default::default(),
                delimiter: DEFAULT_DELIMITER,
            },
        }
    }
}

impl<S, E> TokenBuilder<WithKey<S, E>>
where
    S: TryInto<TimeValue, Error = &'static str>,
    E: TryInto<TimeValue, Error = &'static str>,
{
    pub fn build(mut self) -> Result<TokenOutput, &'static str> {
        let start = self.state.time.start.try_into()?.offset(Utc::now());
        let end = self.state.time.end.try_into()?.offset(start);

        if end < start {
            return Err("token start date after end date");
        }

        self.state.attrs.insert(Attribute::start(start));
        self.state.attrs.insert(Attribute::end(end));

        let token = self
            .state
            .attrs
            .get_all()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(self.state.delimiter);

        let key = hex::decode(self.state.key).unwrap();

        let mut mac = HmacSha256::new_from_slice(&key)
            .map_err(|_| "HMAC can take key of any size")?;

        mac.update(token.as_bytes());

        self.state
            .attrs
            .insert(Attribute::hmac(hex::encode(mac.finalize().into_bytes())));

        Ok(TokenOutput::new(self.state.attrs, self.state.delimiter))
    }

    pub fn with_attribute(mut self, attribute: Attribute) -> Self {
        self.state.attrs.insert(attribute);
        self
    }

    pub fn with_delimiter(mut self, delimiter: &'static str) -> Self {
        self.state.delimiter = delimiter;
        self
    }
}

impl Attribute {
    fn for_token(&self) -> bool {
        !matches!(self, Attribute::Url(_))
    }

    fn start(time: chrono::DateTime<Utc>) -> Self {
        Self::Start(time)
    }

    fn end(time: chrono::DateTime<Utc>) -> Self {
        Self::End(time)
    }

    fn hmac(hmac: String) -> Self {
        Self::Hmac(hmac)
    }

    pub fn url(url: impl ToString) -> Self {
        Self::Url(escape(&url.to_string()))
    }
}

impl Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Attribute::Start(date_time) => {
                    format!("st={}", date_time.timestamp())
                }
                Attribute::End(date_time) =>
                    format!("exp={}", date_time.timestamp()),
                Attribute::Url(url) => format!("url={}", url),
                Attribute::Hmac(hmac) => format!("hmac={}", hmac),
            }
        )
    }
}

impl Hash for Attribute {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}

impl PartialEq for Attribute {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self).eq(&std::mem::discriminant(other))
    }
}

impl TimeValue {
    fn offset(&self, offset: DateTime<Utc>) -> chrono::DateTime<Utc> {
        match self {
            TimeValue::Fixed(ut) => *ut,
            TimeValue::Relative(r) => offset + *r,
        }
    }
}

impl TryFrom<i64> for TimeValue {
    type Error = &'static str;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(TimeValue::Fixed(
            DateTime::from_timestamp(value, 0).ok_or("invalid unix timestamp")?,
        ))
    }
}

impl TryFrom<Duration> for TimeValue {
    type Error = &'static str;

    fn try_from(value: Duration) -> Result<Self, Self::Error> {
        Ok(TimeValue::Relative(
            chrono::Duration::from_std(value).map_err(|_| "invalid duration")?,
        ))
    }
}

impl TryFrom<chrono::Duration> for TimeValue {
    type Error = &'static str;

    fn try_from(value: chrono::Duration) -> Result<Self, Self::Error> {
        Ok(TimeValue::Relative(value))
    }
}

impl TryFrom<chrono::DateTime<Utc>> for TimeValue {
    type Error = &'static str;

    fn try_from(value: chrono::DateTime<Utc>) -> Result<Self, Self::Error> {
        Ok(TimeValue::Fixed(value))
    }
}

fn escape(input: &str) -> String {
    let encoded = urlencoding::encode(input)
        .into_owned()
        .replace("~", "%7e")
        .replace("'", "%27")
        .replace("*", "%2a");

    lowercase_percent_hex(&encoded)
}

fn lowercase_percent_hex(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            out.push('%');
            out.push((bytes[i + 1] as char).to_ascii_lowercase());
            out.push((bytes[i + 2] as char).to_ascii_lowercase());
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }

    out
}
