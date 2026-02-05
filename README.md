# secret-ref

A small, dependency-light crate for **referencing secrets declaratively** without embedding secret values directly in configuration.

`secret-ref` lets you describe *where* a secret lives (environment variable, file, or HTTP endpoint), deserialize it consistently across formats (JSON / YAML / TOML), and resolve it at runtime under an explicit security policy.

This crate is intentionally **domain-agnostic**: no Rocket, no protocol schema, no frontend assumptions.

---

## Why this crate exists

Passing raw secrets through config files, protocol layers, or APIs is fragile and dangerous.

Instead of this:

```toml
database_password = "super-secret"
```

you write this:

```toml
database_password = "env://DATABASE_PASSWORD"
```

…and resolve it explicitly at runtime, with policy controls.

---

## Core types

### `SecretRef`

A reference to a secret location:

```rust
pub enum SecretRef {
    Env(String),
    File(PathBuf),
    Http(url::Url),
}
```

It can be:
- parsed from a URL-style string (`env://`, `file://`, `https://`)
- deserialized from structured config
- serialized back to a canonical string form

---

### `SecretPolicy`

Controls which secret sources are allowed at resolution time:

```rust
pub struct SecretPolicy {
    pub allow_env: bool,
    pub allow_file: bool,
    pub allow_http: bool,
}
```

Default policy:
- ✅ env
- ✅ file
- ❌ http (opt-in)

This makes dangerous sources explicit and reviewable.

---

### `SecretValue`

A thin wrapper around the resolved secret value:

```rust
pub struct SecretValue(String);
```

Access requires an explicit call:

```rust
let value: &str = secret_value.expose();
```

This avoids accidental formatting or logging.

---

## Supported formats

`SecretRef` deserializes cleanly from:

### URL-style (recommended)

```json
{ "secret": "env://DATABASE_PASSWORD" }
```

```yaml
secret: file:///run/secrets/db_password
```

```toml
secret = "https://secrets.example.com/db"
```

---

### Structured form

```json
{
  "secret": {
    "scheme": "env",
    "value": "API_TOKEN"
  }
}
```

This is useful when configuration systems restrict URL-like strings.

---

## Fetching secrets

Resolving a secret is explicit and async:

```rust
let secret: SecretRef = /* from config */;
let policy = SecretPolicy::default();

let value = secret.fetch(policy).await?;
println!("length = {}", value.expose().len());
```

Behavior depends on the variant:

| Variant | Behavior |
|--------|----------|
| `Env`  | Reads from `std::env` |
| `File` | Reads file contents (trimmed) |
| `Http` | Performs a GET request (opt-in) |

---

## Error handling

Resolution errors are explicit and typed:

- missing environment variables
- file read failures
- HTTP errors and non-success status codes
- policy violations

Parsing errors clearly distinguish:
- unsupported schemes
- missing identifiers
- invalid URLs

---

## Serialization behavior

- `SecretRef` serializes as a **string**
- Round-trips cleanly across formats
- No secret material is ever serialized

Example:

```rust
let s = SecretRef::Env("FOO".into());
assert_eq!(serde_json::to_string(&s)?, "\"env://FOO\"");
```

---

## Security notes

This crate intentionally:
- does **not** log or redact values
- does **not** auto-fetch secrets on deserialization
- does **not** enable HTTP by default
- keeps the API surface small and reviewable

If you need:
- secret zeroization
- in-memory protection
- secret rotation
- vault integrations

Those should live **above** this crate.

---

## When to use this crate

Use `secret-ref` if you want:
- config-safe secret references
- consistent parsing across services and frontends
- explicit runtime secret resolution
- a clean dependency boundary

Do **not** use it to store or transport secret values themselves.

---

## License

Licensed under MIT/Apache2.