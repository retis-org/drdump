use std::{collections::BTreeMap, fmt::Write, path::PathBuf};

use anyhow::{bail, Result};
use btf_rs::{utils::BtfCollection, Type};
use clap::{builder::PossibleValuesParser, Parser};

// Keep this in-sync with the kernel definition in include/net/dropreason.h
//
// Used to detect if the kernel supports more drop reasons than we know of.
const SKB_DROP_REASON_SUBSYS_NUM: usize = 5;

// Known drop reason definitions in the kernel (except for core that is
// mandatory).
const NON_CORE_DROP_REASONS: &[&str] = &["mac80211_drop_reason", "ovs_drop_reason"];

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Dumps and translates skb drop reasons given a set of BTF files",
    long_about = None,
)]
struct Args {
    #[arg(
        long,
        default_value = "/sys/kernel/btf",
        help = "Directory where BTF files are stored"
    )]
    btf: PathBuf,
    #[arg(
        short,
        long,
        help = "Resolve given value into a drop reason enum value"
    )]
    resolve: Option<u32>,
    #[arg(
        short,
        long,
        value_parser = PossibleValuesParser::new(["raw", "bpftrace", "stap"]),
        default_value = "raw",
        help = "Format to output the drop reason values:
- raw: output on stdout all the drop reasons that were found
- bpftrace: construct a bpftrace monitoring script
- stap: construct a system-tap monitoring script
",
    )]
    format: String,
    #[arg(
        short,
        long,
        help = "Increase verbosity (eg. display sub-system for drop reasons)"
    )]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let btf =
        BtfCollection::from_dir(args.btf).or_else(|e| bail!("Could not parse BTF files: {e}"))?;

    // First parse core drop reasons. If not found, the kernel doesn't support
    // drop reasons.
    let mut reasons = match parse_enum(&btf, "skb_drop_reason") {
        Ok(Some(reasons)) => reasons,
        Ok(None) => bail!("Drop reasons are not supported by this kernel"),
        Err(e) => bail!(e),
    };

    // Special case the drop reason mask (SKB_DROP_REASON_SUBSYS_MASK).
    reasons.remove(&0xffff0000);

    // Parse non-core drop reasons.
    for r#enum in NON_CORE_DROP_REASONS {
        if let Some(mut subsys_reasons) = parse_enum(&btf, r#enum)? {
            while let Some((val, reason)) = subsys_reasons.pop_first() {
                // Do not overwrite known values. Some sub-system do this for
                // reusing some of the very generic core reasons. Eg.
                // SKB_CONSUMED.
                reasons.entry(val).or_insert(reason);
            }
        }
    }

    // Get a list of all the known subsystems that can register non-core drop
    // reasons. This might return more elements than the ones we know of (if we
    // haven't added support for those yet).
    let subsys = parse_enum(&btf, "skb_drop_reason_subsys")?;
    if let Some(ref subsys) = subsys {
        if subsys.len() > SKB_DROP_REASON_SUBSYS_NUM {
            eprint!("INFO: found more drop reasons than we know of. Drdump will still be able to resolve raw values into a sub-system when using --resolve.\n\n");
        }
    }

    // Handle the output. Depends on which operation was requested.
    if let Some(resolve) = args.resolve {
        println!(
            "{}",
            format_reason(resolve, &reasons, subsys.as_ref(), args.verbose)
        );
    } else {
        match args.format.as_str() {
            "raw" => {
                let width = (reasons
                    .keys()
                    .max()
                    .unwrap_or(&0)
                    .checked_ilog10()
                    .unwrap_or(0)
                    + 1) as usize;
                reasons.keys().for_each(|i| {
                    println!(
                        "{i:width$} = {}",
                        format_reason(*i, &reasons, subsys.as_ref(), args.verbose)
                    )
                });
            }
            "bpftrace" => println!("{}", format_bpftrace(&reasons)),
            "stap" => println!("{}", format_stap(&reasons)),
            _ => (),
        }
    }

    Ok(())
}

// Formats a reason for pretty printing. If verbose is set, prints the subsystem
// enum variant corresponding to a reason. If a reason is not known, try to
// always print its subsystem if we have a match.
fn format_reason(
    val: u32,
    reasons: &BTreeMap<u32, String>,
    subsys: Option<&BTreeMap<u32, String>>,
    verbose: bool,
) -> String {
    let format = |s: &str, verbose: bool| -> String {
        if verbose && subsys.is_some() {
            let subsys_id = val >> 16;

            // Unwrap as we just made sure it's Some<>.
            if let Some(name) = subsys.unwrap().get(&subsys_id) {
                return format!("{s} (sub-system: {name})");
            }
        }
        s.to_string()
    };

    match reasons.get(&val) {
        Some(name) => format(name, verbose),
        None => format(&format!("Unknown reason {val}"), true),
    }
}

// Parses a kernel enum into an ordered BTreeMap of (val <> name).
fn parse_enum(btf: &BtfCollection, name: &str) -> Result<Option<BTreeMap<u32, String>>> {
    let mut values = BTreeMap::new();

    let types = match btf.resolve_types_by_name(name) {
        Ok(types) => types,
        Err(_) => return Ok(None),
    };

    let (btf, r#enum) = match types.iter().find(|(_, t)| matches!(t, &Type::Enum(_))) {
        Some((btf, Type::Enum(r#enum))) => (btf, r#enum),
        _ => return Ok(None),
    };

    for member in r#enum.members.iter() {
        let val = member.val() as u32;
        values.insert(val, btf.resolve_name(member)?);
    }

    Ok(Some(values))
}

// Construct a bpftrace script to monitor drop reasons.
fn format_bpftrace(reasons: &BTreeMap<u32, String>) -> String {
    let reasons_def = reasons.iter().fold(String::new(), |mut out, (val, name)| {
        write!(out, "    @drop_reasons[{val}] = \"{name}\";\n").unwrap();
        out
    });

    format!(
        "#!/usr/bin/bpftrace

BEGIN
{{
    printf(\"Tracing dropped skbs... Hit Ctrl-C to end.\\n\");
}}

tracepoint:skb:kfree_skb
{{
{reasons_def}
    @stack[ksym(args->location),@drop_reasons[args->reason]] = count();
    clear(@drop_reasons);
}}

interval:s:5
{{
    time(\"%F %T %z (%Z)\\n\");
    print(@stack);
    printf(\"\\n\");
    clear(@stack);
}}

END
{{
  clear(@stack);
}}"
    )
}

// Construct a stap script to monitor drop reasons.
fn format_stap(reasons: &BTreeMap<u32, String>) -> String {
    let reasons_def = reasons.iter().fold(String::new(), |mut out, (val, name)| {
        write!(out, "    drop_reasons[{val}] = \"{name}\";\n").unwrap();
        out
    });

    format!("#! /usr/bin/env stap

global skb_drop_reason
global drop_reasons

probe kernel.trace(\"kfree_skb\") {{
    skb_drop_reason[$location, $reason] <<< 1;
}}

probe begin {{
    printf(\"Tracing dropped skbs... Hit Ctrl-C to end.\\n\");
}}

# Report every 5 seconds
probe timer.sec(5)
{{
    printf(\"\\n%s\", tz_ctime(gettimeofday_s()))
{reasons_def}
    printf(\"\\n%-35s%-35s%10s\\n\",\"Drop\",\"Location\",\"Count\");
    foreach([location, reason] in skb_drop_reason) {{
        printf(\"%-35s%-35s%10d\\n\",symname(location),drop_reasons[reason],@count(skb_drop_reason[location, reason]))
    }}
    delete skb_drop_reason
}}")
}
