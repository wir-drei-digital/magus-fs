use automerge::{
    transaction::Transactable, ActorId, AutoCommit, ChangeHash, ObjType, ReadDoc, ROOT,
};
use magus_fs_core::{merge_text, TextMerge};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fs, io::Write, path::Path, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
struct Save {
    id: String,
    actor: String,
    frontier: String,
    text: String,
}

#[derive(Deserialize)]
struct Input {
    mode: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    base: String,
    #[serde(default)]
    saves: Vec<Save>,
    #[serde(default)]
    directory: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    size: usize,
    #[serde(default)]
    changes: usize,
}

fn emit(value: Value) -> Result<()> {
    println!("{value}");
    std::io::stdout().flush()?;
    Ok(())
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn heads(doc: &mut AutoCommit) -> Vec<String> {
    doc.get_heads().iter().map(ToString::to_string).collect()
}

fn object(doc: &AutoCommit) -> Result<automerge::ObjId> {
    doc.get(ROOT, "file")?
        .map(|(_, id)| id)
        .ok_or_else(|| "missing text object".into())
}

fn text(doc: &AutoCommit) -> Result<String> {
    Ok(doc.text(object(doc)?)?)
}

fn seed(contents: &str) -> Result<AutoCommit> {
    let mut doc = AutoCommit::new();
    doc.set_actor(ActorId::from(vec![0]));
    let obj = doc.put_object(ROOT, "file", ObjType::Text)?;
    doc.update_text(&obj, contents)?;
    doc.commit();
    Ok(doc)
}

fn actor(value: &str) -> Result<ActorId> {
    Ok(ActorId::from(vec![u8::from_str_radix(value, 16)?]))
}

fn helper(base: &[u8], left: &[u8], right: &[u8]) -> Value {
    match merge_text(base, left, right) {
        TextMerge::Merged(bytes) => {
            json!({"outcome":"merged", "sha256":hash(&bytes), "text":String::from_utf8(bytes).expect("UTF-8 merge")})
        }
        TextMerge::Overlap => json!({"outcome":"overlap"}),
        TextMerge::Unsupported => json!({"outcome":"unsupported"}),
        TextMerge::Budget => json!({"outcome":"budget"}),
    }
}

fn orders(values: &[usize]) -> Vec<Vec<usize>> {
    if values.is_empty() {
        return vec![vec![]];
    }
    let mut result = vec![];
    for (index, value) in values.iter().enumerate() {
        let mut rest = values.to_vec();
        rest.remove(index);
        for mut permutation in orders(&rest) {
            permutation.insert(0, *value);
            result.push(permutation);
        }
    }
    result
}

fn case(input: Input) -> Result<()> {
    let started = Instant::now();
    let directory = Path::new(&input.directory);
    let original = fs::read_to_string(directory.join("base.txt"))?;
    if original != input.base {
        return Err("base file differs from declared bytes".into());
    }
    let mut base = seed(&original)?;
    let base_bytes = base.save();
    fs::write(directory.join("base.am"), &base_bytes)?;
    let mut universe = AutoCommit::load(&base_bytes)?;
    let mut frontiers =
        BTreeMap::from([("base".to_string(), (base.get_heads(), original.clone()))]);
    let mut forks = vec![];
    let mut outcomes = vec![];
    let mut three_way =
        json!({"outcome":"merged", "text":original, "sha256":hash(input.base.as_bytes())});
    let mut helper_steps = vec![];
    for save in &input.saves {
        let contents = fs::read_to_string(directory.join(format!("{}.txt", save.id)))?;
        if contents != save.text {
            return Err("save file differs from declared bytes".into());
        }
        let save_start = Instant::now();
        let common = json!({"id":save.id,"actor":save.actor,"declared_frontier":save.frontier,"input_sha256":hash(contents.as_bytes()), "input_bytes":contents.len()});
        let mut outcome = common;
        if save.frontier == "unknown" || save.frontier == "unavailable" {
            let reason = if save.frontier == "unknown" {
                "unknown"
            } else {
                "base_unavailable"
            };
            let error = if save.frontier == "unavailable" {
                let invalid: ChangeHash = "ff".repeat(32).parse()?;
                match universe.fork_at(&[invalid]) {
                    Err(error) => Some(error.to_string()),
                    Ok(_) => return Err("unavailable frontier unexpectedly admitted".into()),
                }
            } else {
                None
            };
            outcome["outcome"] = json!(reason);
            outcome["heads_after"] = Value::Null;
            outcome["heads_before"] = Value::Null;
            outcome["retained_text"] = json!(contents);
            outcome["frontier_error"] = json!(error);
            three_way = json!({"outcome":reason});
        } else {
            let (at, ancestor_text) = frontiers
                .get(&save.frontier)
                .cloned()
                .ok_or("undeclared frontier")?;
            let mut doc = universe.fork_at(&at)?;
            doc.set_actor(actor(&save.actor)?);
            let before = heads(&mut doc);
            doc.update_text(&object(&doc)?, &contents)?;
            doc.commit();
            let after = doc.get_heads();
            let wire_bytes: usize = doc
                .get_changes(&at)
                .iter()
                .map(|c| c.raw_bytes().len())
                .sum();
            let saved = doc.save();
            fs::write(directory.join(format!("{}.am", save.id)), &saved)?;
            let mut loaded = AutoCommit::load(&saved)?;
            if text(&loaded)? != contents || loaded.get_heads() != after {
                return Err("save/load changed text or heads".into());
            }
            outcome["outcome"] = json!("applied");
            outcome["heads_before"] = json!(before);
            outcome["heads_after"] = json!(heads(&mut loaded));
            outcome["state_bytes"] = json!(saved.len());
            outcome["wire_bytes"] = json!(wire_bytes);
            universe.merge(&mut loaded)?;
            frontiers.insert(save.id.clone(), (after, contents.clone()));
            forks.push((save.id.clone(), saved));
            if three_way["outcome"] == "merged" {
                let next = helper(
                    ancestor_text.as_bytes(),
                    three_way["text"]
                        .as_str()
                        .ok_or("no helper text")?
                        .as_bytes(),
                    contents.as_bytes(),
                );
                helper_steps.push(json!({"save":save.id,"ancestor":save.frontier,"result":next}));
                three_way = next;
            }
        }
        outcome["elapsed_us"] = json!(save_start.elapsed().as_micros());
        outcomes.push(outcome);
    }
    let mut exchanges = vec![];
    for order in orders(&(0..forks.len()).collect::<Vec<_>>()) {
        let mut doc = AutoCommit::load(&base_bytes)?;
        let merge_start = Instant::now();
        for index in &order {
            doc.merge(&mut AutoCommit::load(&forks[*index].1)?)?;
        }
        let merge_us = merge_start.elapsed().as_micros();
        let final_text = text(&doc)?;
        let order_name = order
            .iter()
            .map(|index| forks[*index].0.clone())
            .collect::<Vec<_>>()
            .join("-");
        let state_path = directory.join(format!("final-{order_name}.am"));
        let serialize_start = Instant::now();
        let saved = doc.save();
        let serialize_us = serialize_start.elapsed().as_micros();
        fs::write(&state_path, &saved)?;
        let loaded = AutoCommit::load(&saved)?;
        if text(&loaded)? != final_text {
            return Err("final save/load mismatch".into());
        }
        exchanges.push(json!({"order":order_name,"text":final_text,"sha256":hash(final_text.as_bytes()),"heads":heads(&mut doc),"state_bytes":saved.len(),"state_path":state_path,"merge_us":merge_us,"serialize_us":serialize_us}));
    }
    emit(
        json!({"name":input.name,"base_heads":heads(&mut base),"base_state_bytes":base_bytes.len(),"saves":outcomes,"exchanges":exchanges,"three_way":three_way,"helper_steps":helper_steps,"elapsed_us":started.elapsed().as_micros()}),
    )
}

fn benchmark(input: Input) -> Result<()> {
    let start = Instant::now();
    fs::create_dir(Path::new(&input.directory))?;
    let path = Path::new(&input.directory).join("ordinary.txt");
    // Fixed-width ASCII lines: exact declared byte count, 256KiB = 4096 lines.
    let line = format!("{:0>8}{}\n", "0", "x".repeat(55));
    let mut contents = line.repeat(input.size / 64);
    if contents.len() != input.size {
        return Err("fixture size must be divisible by 64".into());
    }
    fs::write(&path, &contents)?;
    let mut current = seed(&fs::read_to_string(&path)?)?;
    let initial_state = current.save();
    let mut total_wire: usize = current
        .get_changes(&[])
        .iter()
        .map(|c| c.raw_bytes().len())
        .sum();
    emit(
        json!({"kind":"initial","input_bytes":input.size,"state_bytes":initial_state.len(),"wire_bytes":total_wire,"elapsed_us":start.elapsed().as_micros(),"heads":heads(&mut current)}),
    )?;
    for index in 0..input.changes {
        let iteration = Instant::now();
        let previous = contents.clone();
        let offset = (index % (input.size / 64)) * 64;
        contents.replace_range(offset..offset + 8, &format!("{:08}", index + 1));
        fs::write(&path, &contents)?;
        let read = fs::read_to_string(&path)?;
        let before = current.get_heads();
        let update_start = Instant::now();
        let mut fork = current.fork_at(&before)?;
        fork.set_actor(ActorId::from(vec![1 + (index % 2) as u8]));
        fork.update_text(&object(&fork)?, &read)?;
        fork.commit();
        let update_us = update_start.elapsed().as_micros();
        let wire_bytes: usize = fork
            .get_changes(&before)
            .iter()
            .map(|c| c.raw_bytes().len())
            .sum();
        total_wire += wire_bytes;
        let merge_start = Instant::now();
        current.merge(&mut fork)?;
        let merge_us = merge_start.elapsed().as_micros();
        let save_start = Instant::now();
        let state = current.save();
        let serialize_us = save_start.elapsed().as_micros();
        let helper_start = Instant::now();
        let result = merge_text(previous.as_bytes(), read.as_bytes(), previous.as_bytes());
        let helper_us = helper_start.elapsed().as_micros();
        if text(&current)? != read || result != TextMerge::Merged(read.as_bytes().to_vec()) {
            return Err("benchmark text mismatch".into());
        }
        emit(
            json!({"kind":"change","index":index,"actor":1+(index%2),"heads_before":before.iter().map(ToString::to_string).collect::<Vec<_>>(),"heads_after":heads(&mut current),"input_bytes":read.len(),"input_sha256":hash(read.as_bytes()),"state_bytes":state.len(),"wire_bytes":wire_bytes,"cumulative_wire_bytes":total_wire,"update_us":update_us,"merge_us":merge_us,"serialize_us":serialize_us,"helper_us":helper_us,"helper_outcome":"merged","iteration_us":iteration.elapsed().as_micros()}),
        )?;
    }
    fs::write(Path::new(&input.directory).join("final.am"), current.save())?;
    emit(
        json!({"kind":"complete","changes":input.changes,"elapsed_us":start.elapsed().as_micros(),"sha256":hash(text(&current)?.as_bytes())}),
    )
}

fn main() -> Result<()> {
    let path = std::env::args().nth(1).ok_or("input JSON path required")?;
    let input: Input = serde_json::from_slice(&fs::read(path)?)?;
    match input.mode.as_str() {
        "case" => case(input),
        "benchmark" => benchmark(input),
        "helper" => emit(
            json!({"name":input.name,"three_way":helper(input.base.as_bytes(),input.saves[0].text.as_bytes(),input.saves[1].text.as_bytes())}),
        ),
        "reload" => {
            let mut doc = AutoCommit::load(&fs::read(input.path)?)?;
            let contents = text(&doc)?;
            emit(
                json!({"text":contents,"heads":heads(&mut doc),"sha256":hash(contents.as_bytes())}),
            )
        }
        _ => Err("unknown mode".into()),
    }
}
