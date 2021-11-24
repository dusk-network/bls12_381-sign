fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../../schema/bls12381sig.proto")?;
    Ok(())
}
