#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate serde_json;

use std::env;
use std::error::Error;
use std::fmt::{self, Display};
use std::fs::write;
use std::path::PathBuf;
use std::process;

use clap::{crate_description, crate_version, App, Arg, ArgMatches};
use elf::{File, ParseError};
use serde_json::map::Map;
use serde_json::Value as JsonValue;

#[derive(Debug)]
enum TranslationError {
    MissingTextSection,
}

fn fail<T: AsRef<str> + Display>(code: i32, msg: T) -> ! {
    error!("{}", msg);
    process::exit(code);
}

//evmelf --to-json file.elf
fn main() {
    // TODO: Arg to specify which info to emit.
    // Not needed until we support more than just the text file.
    let arg_matches = App::new("evmelf")
        .version(crate_version!())
        .about(crate_description!())
        .arg(
            Arg::with_name("OUTPUT")
                .help("Sets the output file")
                .short("o")
                .long("output")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("VERBOSE")
                .help("Enables verbose debugging")
                .short("v")
                .long("verbose"),
        )
        .arg(
            Arg::with_name("PRETTY")
                .help("Enables pretty-printed JSON output")
                .long("pretty-json"),
        )
        .arg(
            Arg::with_name("FILE")
                .help("Sets the input file(s)")
                .required(true)
                .multiple(true),
        )
        .get_matches();

    // Set log level
    if arg_matches.is_present("VERBOSE") {
        env::set_var("RUST_LOG", "debug");
    }
    env_logger::init();

    let paths: Vec<&str> = arg_matches
        .values_of("FILE")
        .expect("Enforced by clap")
        .collect();
    let files = paths
        .iter()
        .map(|path| match load_elf(path) {
            Ok(file) => file,
            Err(e) => fail(1, format!("Failed to load elf: {:?}", e)), //TODO: Unwrap into something we can display
        })
        .collect();

    let json = match translate_and_link_objects(files) {
        Ok(json) => json,
        Err(e) => fail(1, format!("JSON conversion failed: {}", e)),
    };

    debug!("Serializing JSON");
    let json = if arg_matches.is_present("PRETTY") {
        serde_json::to_string_pretty(&json)
    } else {
        serde_json::to_string(&json)
    }
    .unwrap_or_else(|e| fail(1, format!("Failed to serialize JSON object: {}", e)));

    let output_path: PathBuf = if let Some(path) = arg_matches.value_of("OUTPUT") {
        path
    } else {
        "/dev/stdout"
    }
    .into();

    debug!("Writing JSON to file");
    write(output_path, json);
}

fn load_elf<T: Into<PathBuf> + Display>(path: T) -> Result<File, ParseError> {
    debug!("Loading ELF binary: {}", path);
    let path: PathBuf = path.into();
    File::open_path(&path)
}

// Translate and link a batch of elf objects
fn translate_and_link_objects(files: Vec<File>) -> Result<JsonValue, Box<dyn Error>> {
    debug!("Translating objects...");
    let contracts = files
        .into_iter()
        .map(|file| (get_elf_name(&file), elf_to_json(file)));

    let contracts: Result<Map<String, JsonValue>, Box<dyn Error>> = contracts
        .into_iter()
        .enumerate()
        .try_fold(Map::new(), |mut acc, (idx, (name, contract))| {
            let name = if let Some(name) = name {
                name
            } else {
                format!("contract_{}", idx)
            };
            // Check error here and shortcircuit
            match contract {
                Ok(contract) => {
                    debug!("Added contract '{}'", &name);
                    acc.insert(name, contract);
                    Ok(acc)
                }
                Err(e) => Err(e),
            }
        });

    match contracts {
        Ok(contracts) => {
            let contracts = JsonValue::Object(contracts);
            let ret = json!({ "contracts": contracts });
            Ok(ret)
        }
        Err(e) => Err(e),
    }
}

// Get the source file from the ELF object, if provided.
// TODO: Update this to get the metadata correctly. It is currently looking for something
// that is likely in an old version of evm_llvm.
fn get_elf_name(file: &File) -> Option<String> {
    if let Some(filename) = file.get_section(".file") {
        let ret = std::str::from_utf8(filename.data.as_ref())
            .expect("utf8 fail lmao")
            .to_string();
        debug!("Found .file section with suitable name: {}", &ret);
        Some(ret)
    } else {
        None
    }
}

// Translate an ELF object and return a JSON object representing a contract.
fn elf_to_json(file: File) -> Result<JsonValue, Box<dyn Error>> {
    // Get text section and contained code
    let code_object: JsonValue = {
        let text = match file.get_section(".text") {
            Some(section) => section,
            None => return Err(TranslationError::MissingTextSection.into()),
        };

        let encoded_bin = hex::encode(&text.data);
        JsonValue::String(encoded_bin)
    };

    let contract_object: JsonValue = json!({ "bin": code_object });
    Ok(contract_object)
}

impl Display for TranslationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl Error for TranslationError {
    fn description(&self) -> &str {
        match self {
            MissingTextSection => "Missing section .text",
        }
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert!(true);
    }
}
