//! Tiny unified-diff parser. We only need enough structure to (a) cap the size
//! we send to the model and (b) verify that each finding's `path:line` is
//! actually grounded in the diff.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ParsedDiff {
    /// For each touched file (new path; falls back to old path on deletes),
    /// the set of new-side line numbers that appear in any hunk.
    pub lines_by_file: HashMap<String, Vec<u32>>,
}

impl ParsedDiff {
    pub fn empty() -> Self {
        ParsedDiff {
            lines_by_file: HashMap::new(),
        }
    }

    pub fn touches(&self, path: &str, line: u32) -> bool {
        self.lines_by_file
            .get(path)
            .map(|lines| lines.binary_search(&line).is_ok())
            .unwrap_or(false)
    }

    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.lines_by_file.keys().map(|s| s.as_str())
    }

    pub fn nearest_line(&self, path: &str, line: u32) -> Option<u32> {
        let lines = self.lines_by_file.get(path)?;
        if lines.is_empty() {
            return None;
        }
        let mut best = lines[0];
        let mut best_dist = best.abs_diff(line);
        for &l in &lines[1..] {
            let d = l.abs_diff(line);
            if d < best_dist {
                best = l;
                best_dist = d;
            }
        }
        Some(best)
    }
}

pub fn parse(diff: &str) -> ParsedDiff {
    let mut current_path: Option<String> = None;
    let mut current_new_line: u32 = 0;
    let mut by_file: HashMap<String, Vec<u32>> = HashMap::new();

    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            // `diff --git a/foo b/foo` — take the b-side path as default.
            if let Some(b) = rest.split_whitespace().nth(1) {
                let p = b.strip_prefix("b/").unwrap_or(b);
                current_path = Some(p.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("+++ b/") {
            current_path = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            let r = rest.trim();
            if r != "/dev/null" {
                current_path = Some(r.trim_start_matches("b/").to_string());
            }
        } else if line.starts_with("--- ") {
            // ignored; we key on the new-side path.
        } else if let Some(rest) = line.strip_prefix("@@") {
            // Format: `@@ -A,B +C,D @@ optional context`
            // We need C (new-file start line).
            if let Some(new_part) = rest.split_whitespace().find(|s| s.starts_with('+')) {
                let nums = new_part.trim_start_matches('+');
                let start: u32 = nums
                    .split(',')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                current_new_line = start;
            }
        } else if let Some(path) = current_path.as_deref() {
            if line.starts_with("+++") || line.starts_with("---") {
                continue;
            }
            match line.as_bytes().first() {
                Some(b'+') => {
                    by_file
                        .entry(path.to_string())
                        .or_default()
                        .push(current_new_line);
                    current_new_line += 1;
                }
                Some(b'-') => { /* old-side, no new line consumed */ }
                Some(b' ') | None if current_new_line > 0 => {
                    current_new_line += 1;
                }
                _ => {}
            }
        }
    }

    for v in by_file.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    ParsedDiff {
        lines_by_file: by_file,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,3 +1,4 @@
 fn one() {}
-fn two() {}
+fn two_v2() {}
+fn three() {}
 fn four() {}
diff --git a/src/b.rs b/src/b.rs
--- a/src/b.rs
+++ b/src/b.rs
@@ -10,2 +10,3 @@
 fn x() {}
+fn y() {}
 fn z() {}
";

    #[test]
    fn parses_two_files_with_new_lines() {
        let d = parse(SAMPLE);
        assert!(d.touches("src/a.rs", 2));
        assert!(d.touches("src/a.rs", 3));
        assert!(!d.touches("src/a.rs", 1));
        assert!(d.touches("src/b.rs", 11));
        assert!(!d.touches("src/b.rs", 10));
    }

    #[test]
    fn nearest_line_finds_closest() {
        let d = parse(SAMPLE);
        assert_eq!(d.nearest_line("src/a.rs", 5), Some(3));
    }
}
