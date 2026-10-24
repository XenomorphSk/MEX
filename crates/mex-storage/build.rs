//! Recompila o crate quando as migrations mudam (elas são embutidas pelo
//! `sqlx::migrate!` em tempo de compilação).
fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
