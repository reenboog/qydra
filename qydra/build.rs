use std::io::Result as IOResult;

fn main() -> IOResult<()> {
	let files = ["protobuf/Schema.proto"];
	prost_build::compile_protos(&files, &["protobuf"])?;

	for dep in files.iter() {
		println!("cargo:rerun-if-changed={}", dep);
	}

	Ok(())
}
