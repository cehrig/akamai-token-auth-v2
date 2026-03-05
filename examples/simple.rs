use std::time::Duration;
use token_auth::TokenBuilder;

const KEY: &str = "<...>";

fn main() {
    let builder = TokenBuilder::with_start_and_end(
        None::<()>,
        Duration::from_mins(60 * 24 * 30),
    )
    .with_acl(["/*"])
    .with_hex(KEY);

    let token = builder.build().unwrap();
    println!("{}", token.token());
}
