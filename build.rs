extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .generate()
        // during dev
        // .map_or_else(
        //     |error| match error {
        //         cbindgen::Error::ParseSyntaxError { .. } => {}
        //         e => panic!("{:?}", e),
        //     },
        //     |bindings| {
        //         bindings.write_to_file("target/include/bindings.h");
        //     },
        // );
        .expect("Unable to generate bindings")
        .write_to_file("include/bindings.h");
}
