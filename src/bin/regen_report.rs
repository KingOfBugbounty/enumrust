// Regenerate report with new design
use std::path::Path;
use enumrust::report_generator::generate_html_report;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: regen_report <scan_directory>");
        eprintln!("Example: regen_report /path/to/domain.com");
        std::process::exit(1);
    }

    let scan_dir = Path::new(&args[1]);

    if !scan_dir.exists() {
        eprintln!("Error: Directory not found: {}", scan_dir.display());
        std::process::exit(1);
    }

    // Extract domain from directory name
    let domain = scan_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    println!("Regenerating report for: {}", domain);
    println!("Scan directory: {}", scan_dir.display());

    match generate_html_report(scan_dir, domain) {
        Ok(path) => {
            println!("Report generated successfully!");
            println!("Output: {}", path);
        }
        Err(e) => {
            eprintln!("Error generating report: {}", e);
            std::process::exit(1);
        }
    }
}
