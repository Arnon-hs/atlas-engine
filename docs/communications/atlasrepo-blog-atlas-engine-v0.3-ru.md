# Atlas Engine: честный анализ репозитория без ложных нулей

Сканер репозитория может вернуть `0 findings` по двум противоположным причинам.
В первом случае он завершил проверку и ничего не нашёл. Во втором он не понял
язык, не прочитал файл или исчерпал бюджет парсинга. В обычном отчёте оба исхода
легко превращаются в один и тот же ноль.

[Atlas Engine](https://github.com/Arnon-hs/atlas-engine) — новый open-source
движок на Rust, который сохраняет эту разницу. Он читает переданный caller
snapshot репозитория без запуска кода из него и выдаёт ограниченные,
версионированные записи. Сам caller обязан сделать snapshot неизменяемым и
read-only. Consumer может проверить records до индексации, security gate или
показа пользователю.

> **Статус проекта:** статья описывает v0.3 source candidate на коммите
> [`c5d4483`](https://github.com/Arnon-hs/atlas-engine/commit/c5d448367706ae6f86f6c5ff814d0f0824355ae2).
> [Pull request #5](https://github.com/Arnon-hs/atlas-engine/pull/5) открыт. У
> проекта пока нет v0.3 tag, опубликованного binary release, завершённого
> независимого security audit, OpenSSF badge или заявленного SLSA level.

## Почему отсутствие evidence нельзя записывать как ноль

Представим security dashboard с `0 findings` напротив Rust-файла. Проверял ли
scanner нужные Rust-конструкции? Уложился ли parser в лимит? Не оказался ли файл
слишком большим? Существует ли реализация этого rule domain? Одно число не
отвечает ни на один из этих вопросов.

Atlas Engine v0.3 добавляет coverage contract для каждого принятого файла и
каждого нативного домена анализа:

| Статус | Что он означает | Возможен ли точный count? |
| --- | --- | --- |
| `complete` | Все обязательные этапы завершены для выбранного scope | Да, включая точный ноль |
| `partial` | Часть input, parsing, evaluation или reporting потеряна | Нет, count равен `null` |
| `unsupported` | Домен выбрал файл, но не имеет подходящей реализации | Нет, count равен `null` |
| `excluded` | Явная политика оставила файл вне домена | Нет, count равен `null` |
| `not_reported` | Producer не сообщил результат домена | Нет, count равен `null` |

В отчёте отдельно записываются стадии `selected`, `read`, `parsed` и
`evaluated`. Если домену не нужен parser, `parsed` равен `null`, а не нулю.
Наблюдения внутри partial-результата остаются полезными фактами, но их количество
нельзя превращать в точный total или percentage.

Так AtlasRepo Scout, CI gate или другой consumer может сказать: «полная проверка
не нашла finding» — и не подменять фразой «безопасно» результат «мы не знаем».

## Capability и signal вместо автоматического vulnerability verdict

Первый нативный security inventory ищет execution surfaces, полезные для ревью,
но не пытается доказать exploitable flow. Он выдаёт сигналы с фиксированным
словарём для:

- npm и Composer scripts;
- Cargo build scripts и build dependencies;
- GitHub Actions triggers, permissions, reusable actions и mutable refs;
- Docker entry points, явного root user и privileged Compose services;
- прямых literal options, отключающих TLS verification;
- typed process, shell, dynamic evaluation и deserialization primitives.

Это capabilities. Process API или lifecycle script могут быть полностью
легитимными. Atlas Engine не называет их наличие подтверждённой уязвимостью, не
сохраняет команду, не копирует source snippet и не раскрывает значение секрета
или абсолютный путь хоста. Такие records помогают расставить приоритеты ревью,
не перенося hostile content репозитория в публичное хранилище.

В движке есть и одна намеренно узкая flow-модель. Внутри одной Python-функции она
может провести параметр через ограниченную цепочку assignments к `eval`, `exec`
или поддерживаемому `subprocess` с literal `shell=True`. Модель не выводит HTTP
attacker control, не загружает framework semantics и не строит cross-file graph.
При ambiguity или превышении лимита по nodes, facts, variables, hops либо parser
deadline coverage становится `partial`: отсутствие пути не выдумывается.

## Внешние scanners остаются снаружи

Atlas Engine не скачивает и не запускает scanner. Consumer может выполнить
проверенный инструмент в своём sandbox, оставить сырой результат приватным и
передать Atlas Engine небольшой evidence manifest. Manifest описывает:

- runner и scanner через bounded names, version и заявленный SHA-256 binary;
- `configuration`, `database` и `ruleset` как materials со state `present`,
  `not_applicable` или `not_reported`; SHA-256 обязателен только для `present`, а
  configuration всегда должна быть present;
- IDs snapshot, configuration и selection;
- scope, exclusions, а также `selected_files`/`evaluated_files` как integer или
  `null`; только complete run требует оба числа и их равенство;
- execution status `complete`, `incomplete` или `failed` и ограниченную
  termination reason;
- result state; SHA-256 и размер приватного artifact присутствуют только при
  state `present`, а failed run обязан иметь absent result.

Публичный manifest не может содержать raw finding records, messages, source
snippets, найденные секреты, команды, environment values, URLs или абсолютные
пути. Агрегированные finding totals обязательны только для complete run. Для
incomplete или failed run они равны `null`; incomplete stage counts могут
оставаться lower-bound integers или `null`. Такой run не проходит security
gate. Валидный manifest и совпавший `evidence_id` доказывают согласованность
заявленных данных, но не аутентифицируют runner, не доказывают соблюдение sandbox
и не решают, доверены ли tool version или digest.

Текущая companion policy предлагает консервативные offline-first профили:
[zizmor](https://docs.zizmor.sh/usage/) и
[actionlint](https://github.com/rhysd/actionlint) для GitHub Actions,
[Gitleaks](https://github.com/gitleaks/gitleaks) в режиме текущего snapshot и
[OSV-Scanner](https://google.github.io/osv-scanner/) на явных lockfiles или SBOM
с pinned database и отключённым Rust call analysis.
[Opengrep](https://github.com/opengrep/opengrep) рассматривается как отдельный
SAST pilot с небольшим Atlas-authored pinned ruleset. Ни один из этих
инструментов или rulesets не встроен в Atlas Engine.

## Анализ репозитория за пределами security signals

Тот же принцип честного coverage применяется к остальному v0.3 анализу:

- PHP, JavaScript, TypeScript и Python поддерживают Tree-sitter symbol
  extraction; для Rust и Shell доступен opt-in extended grammar profile.
- Static dependency edge появляется только при точном разрешении локального
  target. Dynamic imports остаются `dynamic_unresolved`.
- Связи test-to-source имеют evidence labels `exact_import`,
  `naming_heuristic` или `unmapped`. Это не executed-test coverage.
- Structural metrics считают поддерживаемые syntax facts: branch points,
  control nesting и functions. Они не выдаются за универсальную cyclomatic
  complexity.
- Churn приходит из ограниченного history manifest, сформированного consumer.
  Atlas Engine не запускает Git и не читает object database репозитория.
- Произведение `branch_points * commit_count` — точный syntax/history факт для
  приоритизации ревью, а не generic complexity score, вероятность дефекта или
  уязвимости.

Snapshot protocol из v0.2 добавляет детерминированные upsert/delete events от
принятого base manifest. Consumer обязан сначала собрать полную transaction, а
затем применить её атомарно. При неполном traversal deletions не выдаются, чтобы
truncated scan не удалил ранее принятые records.

## Небольшая и явная trust boundary

Atlas Engine читает переданный filesystem snapshot. Он не клонирует remote, не
устанавливает packages, не выполняет hooks, build или код анализируемого
репозитория, не вызывает LLM, не создаёт embeddings, не поднимает HTTP service,
не пишет в database, не планирует jobs, не модерирует findings и не публикует
content. Движок не следует по symlinks; traversal, размер файла, total bytes,
depth, parser work, threads и output ограничены.

Операционная граница остаётся у caller: read-only mount, запрет network, trusted
binary вне input tree, CPU/RSS/wall-time/process/output limits и atomic
acceptance. Native parser всё ещё может упасть или выйти за cooperative deadline,
поэтому hostile input должен обрабатываться в реальном OS sandbox.

Для AtlasRepo эта граница особенно полезна. Scout может владеть acquisition,
scheduling, retries, persistence, moderation и publication, а Atlas Engine
останется заменяемым subprocess с компактным evidence. Он независим от
AtlasRepo; Scout — один возможный consumer, а не скрытая runtime-зависимость.

В репозитории уже есть
[prompt для Scout shadow integration](https://github.com/Arnon-hs/atlas-engine/blob/c5d448367706ae6f86f6c5ff814d0f0824355ae2/docs/integrations/atlasrepo-scout-v0.3-prompt.md),
который сохраняет эту границу и требует pin точного binary digest.

## Как попробовать source candidate

Текущий default branch ещё не содержит candidate. Собирать движок нужно только
из доверенного checkout точного коммита или reviewed PR branch Atlas Engine.
Первый Cargo build может скачать dependencies доверенного engine; готовому
binary сеть для сканирования не нужна. Нельзя запускать Cargo, package manager
или repository-defined command внутри репозитория, который анализируется.

```bash
git fetch origin
git checkout c5d448367706ae6f86f6c5ff814d0f0824355ae2
cargo build --locked --release

./target/release/atlas-engine analyze /path/to/snapshot --format json \
  --repo-id owner/name --advanced

./target/release/atlas-engine security /path/to/snapshot --format json \
  --repo-id owner/name --fail-on high
```

Machine data выводится в stdout, diagnostics — в stderr. Consumer должен
захватывать эти потоки раздельно, валидировать все нужные schemas, требовать
успешное завершение, отклонять truncated output и принимать точные counts только
из complete domains. Exit code 6 означает incomplete security gate или snapshot
transaction, а не чистый результат.

## Что проверено на точном коммите

Для source candidate
[`c5d4483`](https://github.com/Arnon-hs/atlas-engine/commit/c5d448367706ae6f86f6c5ff814d0f0824355ae2):

- [hosted CI](https://github.com/Arnon-hs/atlas-engine/actions/runs/33230078008)
  прошёл Linux и macOS tests, formatting, Clippy, release build, schema/SARIF,
  Node consumer, dependency-security и offline workflow-security jobs;
- [CodeQL](https://github.com/Arnon-hs/atlas-engine/actions/runs/33230077961)
  успешно проверил Rust и GitHub Actions; trusted result publication намеренно
  пропущен для pull request;
- PR фиксирует полные локальные source/fuzz gates на предыдущем implementation
  commit [`953bdb6`](https://github.com/Arnon-hs/atlas-engine/commit/953bdb6d7e83c151fe0439df257f2889a246c3aa):
  178 tests плюс семь benchmark smoke cases и восемь стабильных fuzz harnesses
  по 100 ограниченных non-instrumented runs. Для CI-only head `c5d4483` отдельно
  повторены targeted workflow/repository checks; acceptance и security diff
  также прошли отдельные внутренние agent reviews.

Эти результаты относятся к указанному коммиту. Они не создают release,
deployment, security certification или гарантию для другой revision.

## Что дальше

Следующий полезный шаг — не добавлять сразу все scanners и languages. Сначала
стоит проверить contracts в Scout-owned shadow integration, измерить долю
`unsupported` и `partial`, а затем добавлять grammars или flow classes под
конкретные решения о репозитории.

Хороший contribution начинается со scoped issue: реальный use case, причина
недостаточности текущего evidence, security и compatibility risks, hostile
fixtures и проверяемый acceptance criterion. Remote acquisition, scheduling,
retries, embeddings, databases, moderation и publication остаются вне движка.
Код проекта доступен по выбору пользователя под `MIT OR Apache-2.0`.

Посмотрите [репозиторий](https://github.com/Arnon-hs/atlas-engine), прочитайте
[v0.3 pull request](https://github.com/Arnon-hs/atlas-engine/pull/5) и принесите
case, где разница между `zero` и `unknown` действительно меняет решение.
