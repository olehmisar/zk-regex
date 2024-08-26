mod circom;
mod errors;
mod halo2;
mod regex;
mod structs;
mod wasm;

use circom::gen_circom_template;
use errors::CompilerError;
use halo2::gen_halo2_tables;
use itertools::Itertools;
use regex::{create_regex_and_dfa_from_str_and_defs, get_regex_and_dfa};
use std::{fs::File, path::PathBuf};
use structs::{DecomposedRegexConfig, RegexAndDFA, SubstringDefinitionsJson};

/// Loads substring definitions from a JSON file or creates a default one.
///
/// # Arguments
///
/// * `substrs_json_path` - An optional path to the JSON file containing substring definitions.
///
/// # Returns
///
/// A `Result` containing either the loaded `SubstringDefinitionsJson` or a `CompilerError`.
fn load_substring_definitions_json(
    substrs_json_path: Option<&str>,
) -> Result<SubstringDefinitionsJson, CompilerError> {
    match substrs_json_path {
        Some(path) => {
            let file = File::open(path)?;
            serde_json::from_reader(file).map_err(CompilerError::JsonParseError)
        }
        None => Ok(SubstringDefinitionsJson {
            transitions: vec![vec![]],
        }),
    }
}

/// Generates output files for Halo2 and Circom based on the provided regex and DFA.
///
/// # Arguments
///
/// * `regex_and_dfa` - The `RegexAndDFA` struct containing the regex pattern and DFA.
/// * `halo2_dir_path` - An optional path to the directory for Halo2 output files.
/// * `circom_file_path` - An optional path to the Circom output file.
/// * `circom_template_name` - An optional name for the Circom template.
/// * `num_public_parts` - The number of public parts in the regex.
/// * `gen_substrs` - A boolean indicating whether to generate substrings.
///
/// # Returns
///
/// A `Result` indicating success or a `CompilerError`.
fn generate_outputs(
    regex_and_dfa: &RegexAndDFA,
    halo2_dir_path: Option<&str>,
    circom_file_path: Option<&str>,
    circom_template_name: Option<&str>,
    num_public_parts: usize,
    gen_substrs: bool,
) -> Result<(), CompilerError> {
    if let Some(halo2_dir_path) = halo2_dir_path {
        let halo2_dir_path = PathBuf::from(halo2_dir_path);
        let allstr_file_path = halo2_dir_path.join("allstr.txt");
        let substr_file_paths = (0..num_public_parts)
            .map(|idx| halo2_dir_path.join(format!("substr_{}.txt", idx)))
            .collect_vec();

        gen_halo2_tables(
            regex_and_dfa,
            &allstr_file_path,
            &substr_file_paths,
            gen_substrs,
        )?;
    }

    if let Some(circom_file_path) = circom_file_path {
        let circom_file_path = PathBuf::from(circom_file_path);
        let circom_template_name = circom_template_name
            .expect("circom template name must be specified if circom file path is specified");

        gen_circom_template(
            regex_and_dfa,
            &circom_file_path,
            &circom_template_name,
            gen_substrs,
        )?;
    }

    println!("{:#?}", regex_and_dfa);
    gen_noir_lookup(regex_and_dfa);

    Ok(())
}

fn gen_noir_lookup(regex_and_dfa: &RegexAndDFA) {
    let accept_state_id = {
        let last_state = regex_and_dfa.dfa.states.last().expect("no last state");
        assert!(
            last_state.state_type == "accept",
            "last state is accept, right??"
        );
        last_state.state_id
    };

    const BYTE_SIZE: u32 = 256; // u8 size
    let mut lookup_table_body = String::new();

    // curr_state + char_code -> next_state
    let mut rows: Vec<(usize, u8, usize)> = vec![];

    for state in regex_and_dfa.dfa.states.iter() {
        if state.state_type == "accept" {
            assert_eq!(state.transitions.len(), 0, "accept state has transitions");
        } else {
            assert!(state.transitions.len() > 0, "no transitions");
            for (&tran_next_state_id, tran) in &state.transitions {
                for &char_code in tran {
                    rows.push((state.state_id, char_code, tran_next_state_id));
                }
            }
        };
    }

    for (curr_state_id, char_code, next_state_id) in rows {
        lookup_table_body +=
            &format!("table[{curr_state_id} * {BYTE_SIZE} + {char_code}] = {next_state_id};\n",);
    }

    lookup_table_body = indent(&lookup_table_body);
    let table_size = BYTE_SIZE as usize * regex_and_dfa.dfa.states.len();
    let lookup_table = format!(
        r#"
comptime fn make_lookup_table() -> [Field; {table_size}] {{
    let mut table = [0; {table_size}];
{lookup_table_body}

    // experimentally confirmed that storing a transition for each char code for accept state produces less gates than adding an `if` to check if the current state is not "accept"
    // I might be wrong. I tested for input of length 128 and 1024.
    for i in 0..{BYTE_SIZE} {{
        table[{accept_state_id} * {BYTE_SIZE} + i] = {accept_state_id};
    }}
    table
}}
    "#
    );

    let fn_body = format!(
        r#"
global table = make_lookup_table();
fn regex_match<let N: u32>(input: [u8; N]) {{
    // regex: {regex_pattern}
    let mut s = 0;
    for i in 0..input.len() {{
        s = table[s * {BYTE_SIZE} + input[i] as Field];
    }}
    assert_eq(s, {accept_state_id}, f"no match: {{s}}");
}}
    "#,
        regex_pattern = regex_and_dfa.regex_pattern,
    );
    println!(
        r#"
        {lookup_table}
        {fn_body}
    "#
    );

    fn indent(s: &str) -> String {
        s.split("\n")
            .map(|s| {
                if s.trim().is_empty() {
                    s.to_owned()
                } else {
                    format!("{}{}", "    ", s)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Generates outputs from a decomposed regex configuration file.
///
/// # Arguments
///
/// * `decomposed_regex_path` - The path to the decomposed regex configuration file.
/// * `halo2_dir_path` - An optional path to the directory for Halo2 output files.
/// * `circom_file_path` - An optional path to the Circom output file.
/// * `circom_template_name` - An optional name for the Circom template.
/// * `gen_substrs` - An optional boolean indicating whether to generate substrings.
///
/// # Returns
///
/// A `Result` indicating success or a `CompilerError`.
pub fn gen_from_decomposed(
    decomposed_regex_path: &str,
    halo2_dir_path: Option<&str>,
    circom_file_path: Option<&str>,
    circom_template_name: Option<&str>,
    gen_substrs: Option<bool>,
) -> Result<(), CompilerError> {
    let mut decomposed_regex_config: DecomposedRegexConfig =
        serde_json::from_reader(File::open(decomposed_regex_path)?)?;
    let gen_substrs = gen_substrs.unwrap_or(false);

    let regex_and_dfa = get_regex_and_dfa(&mut decomposed_regex_config)?;

    let num_public_parts = decomposed_regex_config
        .parts
        .iter()
        .filter(|part| part.is_public)
        .count();

    generate_outputs(
        &regex_and_dfa,
        halo2_dir_path,
        circom_file_path,
        circom_template_name,
        num_public_parts,
        gen_substrs,
    )?;

    Ok(())
}

/// Generates outputs from a raw regex string and optional substring definitions.
///
/// # Arguments
///
/// * `raw_regex` - The raw regex string.
/// * `substrs_json_path` - An optional path to the JSON file containing substring definitions.
/// * `halo2_dir_path` - An optional path to the directory for Halo2 output files.
/// * `circom_file_path` - An optional path to the Circom output file.
/// * `template_name` - An optional name for the Circom template.
/// * `gen_substrs` - An optional boolean indicating whether to generate substrings.
///
/// # Returns
///
/// A `Result` indicating success or a `CompilerError`.
pub fn gen_from_raw(
    raw_regex: &str,
    substrs_json_path: Option<&str>,
    halo2_dir_path: Option<&str>,
    circom_file_path: Option<&str>,
    template_name: Option<&str>,
    gen_substrs: Option<bool>,
) -> Result<(), CompilerError> {
    let substrs_defs_json = load_substring_definitions_json(substrs_json_path)?;
    let num_public_parts = substrs_defs_json.transitions.len();

    let regex_and_dfa = create_regex_and_dfa_from_str_and_defs(raw_regex, substrs_defs_json)?;

    let gen_substrs = gen_substrs.unwrap_or(true);

    generate_outputs(
        &regex_and_dfa,
        halo2_dir_path,
        circom_file_path,
        template_name,
        num_public_parts,
        gen_substrs,
    )?;

    Ok(())
}
