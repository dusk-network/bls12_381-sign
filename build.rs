fn main() -> Result<(), Box<dyn std::error::Error>> {
    // compiling protos using path on build time
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .out_dir("src/svc")  // you can change the generated code's location
        .compile(
            &["./proto/bls12381sig.proto"],
            &["./proto"], // specify the root location to search proto dependencies
        ).unwrap();
    Ok(())
}
