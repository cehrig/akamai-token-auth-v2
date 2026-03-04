use chrono::Utc;
use std::time::Duration;
use token_auth::{Attribute, TokenBuilder};

const KEY: &str = "<...>";

fn main() {
    let builder = TokenBuilder::with_start_and_end(
        Utc::now(),
        Duration::from_mins(60 * 24 * 30),
    )
    .with_key(KEY)
    .with_attribute(Attribute::url("/headers"));

    let token = builder.build().unwrap();

    println!("{}", token.token());
}
