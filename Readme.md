# Akamai Auth Token 2.0 Generator 

This is a simple Rust library for generating Akamai Edge Authorization tokens that
can be used in either a HTTP Cookie, Query String or request Header.

## Usage

Use the TokenBuilder to add time constraints on the token. Start and End accept
- i64 Unix Timestamps
- Duration or chrono::Duration
- chrono::Datetime
- None to indicate `now`

```rust
use token_auth::TokenBuilder;

let builder = TokenBuilder::with_start_and_end(
    None::<()>,
    Duration::from_mins(60 * 24 * 30),
);
```

Specify what to protect by either providing a URL or ACL

```rust
// ACL
let builder = builder.with_acl(["/foo/*", "/bar"]);

// URL
let builder = builder.with_url("/foo");
```

Then add any additional constraints available.

```rust
let builder = builder
    .with_session_id("foo")
    .with_payload("bar")
    .with_ip(IpAddr::from_str("127.0.0.1").expect("invalid IP"));
```

And provide an HMAC key either as Hex-encoded String or raw byte Vector. The resulting
HMAC token will use SHA-256 as MAC algorithm.

```rust
const KEY: &'str = "<...>";\

// Using a Hex-encoded String (which can be auto-generated via Property Manager)
let output = builder
    .with_hex(KEY)
    .build()?;

let token = output.token();
```
