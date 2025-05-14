use clap::Parser;
use regex::Regex;
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;

/// Subdomain enumerator and simple crawler with port scanning
#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Target domain to enumerate
    #[arg(short, long)]
    domain: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let domain = &args.domain;
    // 1 & 2: create output directory
    fs::create_dir_all(domain)?;
    let base = Path::new(domain);

    // 3: enumerate subdomains via haktrails
    let subs_txt = base.join("subdomains.txt");
    println!("[*] Enumerating subdomains via haktrails...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo {} | haktrails subdomains | anew {}",
            domain,
            subs_txt.display()
        ))
        .status()?;

    // 3.a: augment subdomains via TLS certificate SANs using tlsx
    println!("[*] Extracting certificate SANs with tlsx...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo {} | tlsx -json -silent | jq -r '.subject_an[] | ltrimstr(\"*.\")' | anew {}",
            domain,
            subs_txt.display()
        ))
        .status()?;

    // 3.1: resolve subdomains to IPs via dnsx
    let ips_txt = base.join("ips.txt");
    println!("[*] Resolving subdomains to IPs with dnsx...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | dnsx -a -resp-only -silent -o {}",
            subs_txt.display(),
            ips_txt.display()
        ))
        .status()?;

    // 3.2: port scan with masscan on IPs
    let masscan_txt = base.join("masscan.txt");
    println!("[*] Scanning ports with masscan...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "masscan -iL {} --ports 1-65535 --rate 10000 -oL {}",
            ips_txt.display(),
            masscan_txt.display()
        ))
        .status()?;

    // 3.3: validate open ports with httpx
    let ports_txt = base.join("ports.txt");
    println!("[*] Validating open ports with httpx...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            r#"cat {} | awk '/open/ {{print $4 ":" $3}}' | httpx -silent -o {}"#,
            masscan_txt.display(),
            ports_txt.display()
        ))
        .status()?;

    // 4: resolve alive hosts via httpx
    let http200_txt = base.join("http200.txt");
    println!("[*] Resolving hosts with httpx...");
    Command::new("httpx")
        .args(&[
            "-silent",
            "-follow-redirects",
            "-max-redirects",
            "10",
            "-list",
            &subs_txt.to_string_lossy(),
            "-o",
            &http200_txt.to_string_lossy(),
        ])
        .status()?;

    // Prepare output files
    let mut s3_file = File::create(base.join("s3.txt"))?;
    let mut urls_file = File::create(base.join("urls.txt"))?;
    let mut hidden_file = File::create(base.join("hiddenparams.txt"))?;

    // Regex patterns
    let re_s3 = Regex::new(r"[a-z0-9\-]+\.s3\.amazonaws\.com")?;
    let re_comment_urls = Regex::new(r#"https?://[^"\s]+"#)?;
    let re_comments = Regex::new(r#"<!--([\s\S]*?)-->"#)?;
    let re_hidden = Regex::new(r#"<input[^>]+name=('?"?)([^"'>\s]+)("?'?)"#)?;

    // HTTP client
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()?;

    // Trackers to avoid duplicates
    let mut seen_s3: HashSet<String> = HashSet::new();
    let mut seen_urls: HashSet<String> = HashSet::new();
    let mut seen_hidden: HashSet<String> = HashSet::new();

    // 5-7: crawl each alive URL
    let file = File::open(&http200_txt)?;
    for line in BufReader::new(file).lines() {
        let url = line?;
        println!("[+] Crawling: {}", url);
        if let Ok(resp) = client.get(&url).send() {
            if let Ok(body) = resp.text() {
                let document = Html::parse_document(&body);
                // 5: extract S3 buckets
                for cap in re_s3.find_iter(&body) {
                    let bucket = cap.as_str().to_string();
                    if seen_s3.insert(bucket.clone()) {
                        writeln!(s3_file, "{}", bucket)?;
                    }
                }
                // 6: extract in-scope links (<a> and comments)
                let sel = Selector::parse("a[href]").unwrap();
                for elem in document.select(&sel) {
                    if let Some(href) = elem.value().attr("href") {
                        if href.contains(domain) && seen_urls.insert(href.to_string()) {
                            writeln!(urls_file, "{}", href)?;
                        }
                    }
                }
                for caps in re_comments.captures_iter(&body) {
                    let comment_text = &caps[1];
                    for url_cap in re_comment_urls.find_iter(comment_text) {
                        let link = url_cap.as_str().trim_end_matches('"').to_string();
                        if link.contains(domain) && seen_urls.insert(link.clone()) {
                            writeln!(urls_file, "{}", link)?;
                        }
                    }
                }
                // 7: extract hidden parameters and build URLs
                if let Some(hurls) = extract_hidden_params(&url, &body, &re_hidden) {
                    for hurl in hurls {
                        if seen_hidden.insert(hurl.clone()) {
                            writeln!(hidden_file, "{}", hurl)?;
                        }
                    }
                }
            }
        }
    }

    // 8: extract all params via hakrawler
    println!("[*] Extracting params with hakrawler...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | hakrawler -s href -subs | anew {}",
            http200_txt.display(),
            base.join("params.txt").display()
        ))
        .status()?;

    // 9: fast vulnerability scanning with Nuclei
    println!("[*] Running Nuclei scan (fast mode)...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | nuclei -silent -etags ssl -l {} -c 100 -o {}",
            http200_txt.display(),
            http200_txt.display(),
            base.join("nuclei.txt").display()
        ))
        .status()?;

    println!(
        "[*] Done. Results saved in \"{}\" directory. Files: subdomains.txt, masscan.txt, ports.txt, http200.txt, s3.txt, urls.txt, hiddenparams.txt, params.txt, nuclei.txt",
        domain
    );
    Ok(())
}

/// Extracts hidden <input name="..."> fields and constructs URLs with airi payload
fn extract_hidden_params(
    base_url: &str,
    html: &str,
    re_hidden: &Regex,
) -> Option<Vec<String>> {
    let mut params = Vec::new();
    for cap in re_hidden.captures_iter(html) {
        let name = cap[2].to_string();
        if name.contains("__") {
            continue;
        }
        params.push(format!("{}=enumrust", name));
    }
    if params.is_empty() {
        return None;
    }
    let sep = if base_url.contains('?') { "&" } else { "?" };
    let full = format!("{}{}{}", base_url, sep, params.join("&"));
    Some(vec![full])
}
