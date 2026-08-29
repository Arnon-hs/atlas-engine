# Atlas Engine v0.3 source candidate: как не выдавать unknown за zero

Показываем source candidate Atlas Engine v0.3 — локального read-only движка на
Rust для структурного анализа репозиториев и компактных security signals.

Главная проблема, которую мы хотели решить: `0 findings` может означать как
«проверили и не нашли», так и «не прочитали файл, не поддержали язык или вышли за
лимит». Поэтому для каждого допущенного к инвентаризации файла и каждого домена
движок сохраняет один из статусов `complete`, `partial`, `unsupported`,
`excluded`, `not_reported` и отдельные стадии `selected`, `read`, `parsed`,
`evaluated`. Точный count, включая ноль, разрешён только при `complete`; во всех
остальных случаях он равен `null`.

Что уже есть в v0.3:

- execution-surface signals для npm/Composer/Cargo, GitHub Actions,
  Docker/Compose, literal TLS disable и typed process/eval/deserialization
  primitives;
- один bounded Python flow внутри функции: parameter → assignments →
  `eval`/`exec` или поддерживаемый `subprocess` с literal `shell=True`;
- opt-in Rust/Shell grammars, доказанные static relative-import edges с
  resolution `resolved`, явные `dynamic_unresolved` imports и evidence-labelled
  test-to-source mapping;
- structural syntax facts и caller-supplied churn, где hotspot равен точному
  `branch_points * commit_count`, а не risk probability;
- passive evidence manifests для внешних scanners, которые consumer запускает
  отдельно в sandbox.

Это **capabilities/signals**, а не автоматические vulnerability verdicts.
Движок не запускает код из анализируемого repo, scanner, Git, package manager или
build; не делает network calls, embeddings, moderation и publication.
Execution-surface, bounded-dataflow и external-evidence records не содержат raw
source snippets, commands, secret values или absolute host paths. Index content
редактируется по отдельному contract, а security finding может содержать только
ограниченный `redacted_preview`.

Для внешнего evidence Atlas Engine проверяет bounded shape и invariants, binding
к snapshot и заявленные SHA-256/size приватного result artifact. Consumer сам
должен проверить, что tool version, binary/rules/database digests доверены,
аутентифицировать runner и обеспечить реальный sandbox.

**Честный статус:** код находится в открытом
[PR #5](https://github.com/Arnon-hs/atlas-engine/pull/5) на коммите
[`c5d4483`](https://github.com/Arnon-hs/atlas-engine/commit/c5d448367706ae6f86f6c5ff814d0f0824355ae2).
CI и CodeQL прошли на этом SHA. Тега, опубликованного binary release, деплоя и
заявления о завершённом независимом security audit пока нет.

Репозиторий: <https://github.com/Arnon-hs/atlas-engine>

Scout shadow-integration prompt:
<https://github.com/Arnon-hs/atlas-engine/blob/c5d448367706ae6f86f6c5ff814d0f0824355ae2/docs/integrations/atlasrepo-scout-v0.3-prompt.md>

Хочется собрать реальные cases для следующей версии:

1. Для какого языка или manifest честный coverage нужен в первую очередь?
2. Какой один source-to-sink flow даст максимум пользы без полноценного
   cross-file CPG?
3. Какой execution surface стоит добавить следующим?
4. Какой внешний scanner первым проверить через evidence manifest в Scout
   shadow mode?

Лучший формат предложения — scoped issue с use case, рисками, hostile fixtures и
проверяемым acceptance criterion. Реальные секреты и детали нераскрытой
уязвимости не публикуйте в теме или issue: используйте
[SECURITY.md](https://github.com/Arnon-hs/atlas-engine/blob/c5d448367706ae6f86f6c5ff814d0f0824355ae2/SECURITY.md).
