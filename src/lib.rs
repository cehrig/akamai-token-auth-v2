use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::BTreeSet,
    fmt::Display,
    hash::Hash,
    net::IpAddr,
    ops::{Deref, DerefMut},
    time::Duration,
};

const DEFAULT_DELIMITER: &str = "~";
const ACL_DELIMITER: &str = "!";

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
pub struct WithUrl<S, E> {
    time: WithStartAndEnd<S, E>,
    attrs: TokenAttributeSet,
}

#[derive(Debug)]
pub struct WithKey<S, E> {
    time: WithStartAndEnd<S, E>,
    key: KeyType,
    attrs: TokenAttributeSet,
    delimiter: &'static str,
}

#[derive(Debug, Eq, PartialOrd, Ord)]
pub enum Attribute {
    Start(chrono::DateTime<Utc>),
    End(chrono::DateTime<Utc>),
    Url(String),
    Acl(Vec<String>),
    Ip(IpAddr),
    SessionId(String),
    Payload(String),
    Hmac(String),
}

pub enum TimeValue {
    Fixed(chrono::DateTime<Utc>),
    Relative(chrono::Duration),
}

#[derive(Debug)]
enum KeyType {
    Hex(String),
    Raw(Vec<u8>),
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
    pub fn with_url(self, url: impl ToString) -> TokenBuilder<WithUrl<S, E>> {
        let mut attrs = TokenAttributeSet::default();
        attrs.insert(Attribute::url(url.to_string()));

        TokenBuilder {
            state: WithUrl {
                time: self.state,
                attrs,
            },
        }
    }

    pub fn with_acl<I, A>(self, acl: I) -> TokenBuilder<WithUrl<S, E>>
    where
        I: IntoIterator<Item = A>,
        A: ToString,
    {
        let mut attrs = TokenAttributeSet::default();
        attrs.insert(Attribute::acl(
            acl.into_iter().map(|a| a.to_string()).collect(),
        ));

        self.next(attrs)
    }

    fn next(self, attrs: TokenAttributeSet) -> TokenBuilder<WithUrl<S, E>> {
        TokenBuilder {
            state: WithUrl {
                time: self.state,
                attrs,
            },
        }
    }
}

impl<S, E> TokenBuilder<WithUrl<S, E>> {
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        let ip = Attribute::ip(ip);

        self.state.attrs.insert(ip);
        self
    }

    pub fn with_session_id(mut self, id: impl ToString) -> Self {
        let session_id = Attribute::session_id(id.to_string());

        self.state.attrs.insert(session_id);
        self
    }

    pub fn with_payload(mut self, payload: impl ToString) -> Self {
        let payload = Attribute::payload(payload.to_string());

        self.state.attrs.insert(payload);
        self
    }

    pub fn with_hex(self, key: impl ToString) -> TokenBuilder<WithKey<S, E>> {
        let key = KeyType::Hex(key.to_string());

        self.next(key)
    }

    pub fn with_raw(self, key: impl AsRef<[u8]>) -> TokenBuilder<WithKey<S, E>> {
        let key = KeyType::Raw(key.as_ref().to_vec());

        self.next(key)
    }

    fn next(self, key: KeyType) -> TokenBuilder<WithKey<S, E>> {
        TokenBuilder {
            state: WithKey {
                time: self.state.time,
                key,
                attrs: self.state.attrs,
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

        let key = match self.state.key {
            KeyType::Hex(hex) => {
                hex::decode(hex).map_err(|_| "unable to decode hex key")?
            }
            KeyType::Raw(raw) => raw,
        };

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
    fn start(time: chrono::DateTime<Utc>) -> Self {
        Self::Start(time)
    }

    fn end(time: chrono::DateTime<Utc>) -> Self {
        Self::End(time)
    }

    fn hmac(hmac: String) -> Self {
        Self::Hmac(hmac)
    }

    fn url(url: String) -> Self {
        Self::Url(url)
    }

    fn acl(acl: Vec<String>) -> Self {
        Self::Acl(acl)
    }

    fn ip(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }

    fn session_id(id: String) -> Self {
        Self::SessionId(id)
    }

    fn payload(payload: String) -> Self {
        Self::Payload(payload)
    }

    fn for_token(&self) -> bool {
        !matches!(self, Attribute::Url(_))
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
                Attribute::Url(url) => format!("url={}", escape(url)),
                Attribute::Hmac(hmac) => format!("hmac={}", hmac),
                Attribute::Acl(items) => format!(
                    "acl={}",
                    items
                        .iter()
                        .map(String::as_str)
                        .map(escape)
                        .collect::<Vec<_>>()
                        .join(ACL_DELIMITER)
                ),
                Attribute::Ip(ip) => format!("ip={}", escape(&ip.to_string())),
                Attribute::SessionId(session_id) =>
                    format!("id={}", escape(session_id)),
                Attribute::Payload(payload) => format!("data={}", escape(payload)),
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

impl<S> TryFrom<Option<S>> for TimeValue
where
    S: TryInto<TimeValue, Error = &'static str>,
{
    type Error = &'static str;

    fn try_from(value: Option<S>) -> Result<Self, Self::Error> {
        value.map_or_else(|| Ok(TimeValue::Fixed(Utc::now())), TryInto::try_into)
    }
}

impl TryFrom<()> for TimeValue {
    type Error = &'static str;

    fn try_from(_: ()) -> Result<Self, Self::Error> {
        Ok(TimeValue::Fixed(Utc::now()))
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
