use std::fs;
use std::hint::black_box;
use std::io;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use repo_core::{Repository, ScanOptions, content_hash};
use repo_indexer::{IndexOptions, index_to_writer};

fn ten_thousand_files() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    for directory in 0..100 {
        let path = temp.path().join(format!("part-{directory:03}"));
        fs::create_dir(&path).unwrap();
        for file in 0..100 {
            fs::write(
                path.join(format!("file-{file:03}.py")),
                "def example(value):\n    return value + 1\n",
            )
            .unwrap();
        }
    }
    temp
}

fn representative_tree() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    for directory in ["php", "javascript", "typescript", "python", "docs"] {
        fs::create_dir(temp.path().join(directory)).unwrap();
    }
    for file in 0..40 {
        let mut php = String::from("<?php\nclass Example {\n");
        let mut js = String::from("export class Example {\n");
        let mut ts =
            String::from("export interface Shape { area(): number; }\nexport class Example {\n");
        let mut py = String::from("class Example:\n");
        for symbol in 0..16 {
            php.push_str(&format!(
                "    public function method{symbol}($input) {{ return $input + {symbol}; }}\n"
            ));
            js.push_str(&format!(
                "    method{symbol}(input) {{ return input + {symbol}; }}\n"
            ));
            ts.push_str(&format!(
                "    method{symbol}(input: number): number {{ return input + {symbol}; }}\n"
            ));
            py.push_str(&format!(
                "    def method{symbol}(self, value):\n        return value + {symbol}\n\n"
            ));
        }
        php.push_str("}\neval($untrusted);\n");
        js.push_str("}\neval(untrusted);\n");
        ts.push_str("}\neval(untrusted);\n");
        py.push_str("\neval(untrusted)\n");
        for (path, source) in [
            (format!("php/file-{file:03}.php"), php),
            (format!("javascript/file-{file:03}.js"), js),
            (format!("typescript/file-{file:03}.ts"), ts),
            (format!("python/file-{file:03}.py"), py),
        ] {
            fs::write(temp.path().join(path), source).unwrap();
        }
    }
    fs::write(
        temp.path().join("package.json"),
        "{\"name\":\"benchmark-fixture\",\"private\":true}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("docs/README.md"),
        "# Synthetic fixture\nBenchmarks do not execute this tree.\n",
    )
    .unwrap();
    temp
}

fn engine_benches(criterion: &mut Criterion) {
    let files = ten_thousand_files();
    let options = ScanOptions {
        threads: 4,
        ..Default::default()
    };
    let mut walk = criterion.benchmark_group("inventory");
    walk.throughput(Throughput::Elements(10_000));
    walk.bench_function("walk_classify_hash_10k", |benchmark| {
        benchmark.iter(|| black_box(Repository::open(files.path(), options.clone()).unwrap()));
    });
    walk.finish();

    let bytes = vec![b'x'; 1024 * 1024];
    let mut hash = criterion.benchmark_group("hash");
    hash.throughput(Throughput::Bytes(bytes.len() as u64));
    hash.bench_function("blake3_1mib", |benchmark| {
        benchmark.iter(|| black_box(content_hash(black_box(&bytes))))
    });
    hash.finish();

    let fixture = representative_tree();
    let repository = Repository::open(fixture.path(), options).unwrap();
    let mut scan = criterion.benchmark_group("representative_tree");
    scan.throughput(Throughput::Elements(repository.files.len() as u64));
    scan.bench_function("analyze_metadata", |benchmark| {
        benchmark.iter(|| black_box(repo_analyzer::analyze(black_box(&repository)).unwrap()));
    });
    scan.bench_function("index_jsonl_sink", |benchmark| {
        benchmark.iter(|| {
            black_box(
                index_to_writer(black_box(&repository), &IndexOptions::default(), io::sink())
                    .unwrap(),
            )
        });
    });
    scan.bench_function("security_scan", |benchmark| {
        benchmark.iter(|| black_box(repo_security::scan(black_box(&repository)).unwrap()));
    });
    scan.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = engine_benches
}
criterion_main!(benches);
