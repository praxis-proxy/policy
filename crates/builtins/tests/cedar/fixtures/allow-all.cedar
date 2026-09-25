// Fixture for the `policy_file:` config path. Checked in rather than written to
// a temp dir, following crates/ppe-core/tests/fixtures, so the tests need no
// `tempfile` dev-dependency.
@id("allow-all")
permit(principal, action, resource);
