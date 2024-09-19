use crate::structs::RegexAndDFA;
use itertools::Itertools;
use std::{collections::HashSet, fs::File, io::Write, iter::FromIterator, path::Path};

const ACCEPT_STATE_ID: &str = "accept";

pub fn gen_noir_fn(
    regex_and_dfa: &RegexAndDFA,
    path: &Path,
    gen_substrs: bool,
) -> Result<(), std::io::Error> {
    let noir_fn = to_noir_fn(regex_and_dfa, gen_substrs);
    let mut file = File::create(path)?;
    file.write_all(noir_fn.as_bytes())?;
    file.flush()?;
    Ok(())
}

/// Generates Noir code based on the DFA and whether a substring should be extracted.
///
/// # Arguments
///
/// * `regex_and_dfa` - The `RegexAndDFA` struct containing the regex pattern and DFA.
/// * `gen_substrs` - A boolean indicating whether to generate substrings. 
///
/// # Returns
///
/// A `String` that contains the Noir code
fn to_noir_fn(regex_and_dfa: &RegexAndDFA, gen_substrs: bool) -> String {
    let accept_state_ids = {
        let accept_states = regex_and_dfa
            .dfa
            .states
            .iter()
            .filter(|s| s.state_type == ACCEPT_STATE_ID)
            .map(|s| s.state_id)
            .collect_vec();
        assert!(accept_states.len() > 0, "no accept states");
        accept_states
    };

    const BYTE_SIZE: u32 = 256; // u8 size
    let mut lookup_table_body = String::new();

    // curr_state + char_code -> next_state
    let mut rows: Vec<(usize, u8, usize)> = vec![];

    for state in regex_and_dfa.dfa.states.iter() {
        for (&tran_next_state_id, tran) in &state.transitions {
            for &char_code in tran {
                rows.push((state.state_id, char_code, tran_next_state_id));
            }
        }
        if state.state_type == ACCEPT_STATE_ID {
            let existing_char_codes = &state
                .transitions
                .iter()
                .flat_map(|(_, tran)| tran.iter().copied().collect_vec())
                .collect::<HashSet<_>>();
            let all_char_codes = HashSet::from_iter(0..=255);
            let mut char_codes = all_char_codes.difference(existing_char_codes).collect_vec();
            char_codes.sort(); // to be deterministic
            for &char_code in char_codes {
                let next_state_id = if regex_and_dfa.has_end_anchor {
                    0 // reset if we encounter another char after we reach the end anchor
                } else {
                    state.state_id // no end anchor? Just stay in the same state
                };
                rows.push((state.state_id, char_code, next_state_id));
            }
        }
    }

    for (curr_state_id, char_code, next_state_id) in rows {
        lookup_table_body +=
            &format!("table[{curr_state_id} * {BYTE_SIZE} + {char_code}] = {next_state_id};\n",);
    }

    lookup_table_body = indent(&lookup_table_body, 1);
    let table_size = BYTE_SIZE as usize * regex_and_dfa.dfa.states.len();
    let lookup_table = format!(
        r#"
comptime fn make_lookup_table() -> [Field; {table_size}] {{
    let mut table = [0; {table_size}];
{lookup_table_body}

    table
}}
    "#
    );

    // substring_ranges contains the transitions that belong to the substring. 
    //   in Noir we only need to know in what state the substring needs to be extracted, the transitions are not needed
    //   Example: SubstringDefinitions { substring_ranges: [{(2, 3)}, {(6, 7), (7, 7)}, {(8, 9)}], substring_boundaries: None }
    //   for each substring, get the first transition and get the end state
    let substr_states: Vec<usize> = regex_and_dfa
      .substrings
      .substring_ranges
      .iter()
      .flat_map(|range_set| range_set.iter().next().map(|&(_, end_state)| end_state)) // Extract the second element (end state) of each tuple
      .collect();
    // Note: substring_boundaries is only filled if the substring info is coming from decomposed setting
    //  and will be empty in the raw setting (using json file for substr transitions). This is why substring_ranges is used here

    let final_states_condition_body = accept_state_ids
        .iter()
        .map(|id| format!("(s == {id})"))
        .collect_vec()
        .join(" | ");

    // If substrings have to be extracted, the function returns a vector of BoundedVec
    // otherwise there is no return type
    let fn_body = if gen_substrs {

        // Fill each substring when at the corresponding state
        // Per state potentially multiple substrings should be extracted
        // The code keeps track of whether a substring was already in the making, or a new one is started
        let mut conditions = substr_states
            .iter()
            .map(|state| {
                format!(
                    "if ((s_next == {state}) & (consecutive_substr == 0)) {{
  let mut substr0 = BoundedVec::new();
  substr0.push(temp);
  substrings.push(substr0);
  consecutive_substr = 1;
  substr_count += 1;
}} else if ((s_next == {state}) & (s == {state})) {{
  let mut current: BoundedVec<Field, N> = substrings.get(substr_count - 1);
  current.push(temp);
  substrings.set(substr_count - 1, current);
}} else if (s == {state}) {{
  consecutive_substr = 0;
}}")
            })
            .collect::<Vec<_>>()
            .join("\n");
        conditions = indent(&conditions, 2); // Indent twice to align with the for loop's body

        format!(
            r#"
global table = comptime {{ make_lookup_table() }};
pub fn regex_match<let N: u32>(input: [u8; N]) -> Vec<BoundedVec<Field, N>> {{
    // regex: {regex_pattern}
    let mut substrings: Vec<BoundedVec<Field, N>> = Vec::new();
    // Workaround for pop bug with Vec
    let mut substr_count = 0;

    // "Previous" state
    let mut s: Field = 0;
    // "Next"/upcoming state
    let mut s_next: Field = 0;

    let mut consecutive_substr = 0;

    for i in 0..input.len() {{
        let temp = input[i] as Field;
        s_next = table[s * 256 + temp];
        // Fill up substrings
{conditions}
        s = s_next;
    }}
    assert({final_states_condition_body}, f"no match: {{s}}");
    substrings
}}"#,
            regex_pattern = regex_and_dfa.regex_pattern
        )
    } else {
        format!(
            r#"
global table = comptime {{ make_lookup_table() }};
pub fn regex_match<let N: u32>(input: [u8; N]) {{
    // regex: {regex_pattern}
    let mut s = 0;
    for i in 0..input.len() {{
        s = table[s * {BYTE_SIZE} + input[i] as Field];
    }}
    assert({final_states_condition_body}, f"no match: {{s}}");
}}"#,
            regex_pattern = regex_and_dfa.regex_pattern,
        )
    };

    format!(
        r#"
        {fn_body}
        {lookup_table}
    "#
    )
    .trim()
    .to_owned()
}

/// Indents each line of the given string by a specified number of levels.
/// Each level adds four spaces to the beginning of non-whitespace lines.
fn indent(s: &str, level: usize) -> String {
    let indent_str = "    ".repeat(level);
    s.split("\n")
        .map(|s| {
            if s.trim().is_empty() {
                s.to_owned()
            } else {
                format!("{}{}", indent_str, s)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
