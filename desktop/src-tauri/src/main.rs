// Hide the console window in release builds. Note that lib.rs settles the
// order of operations: process hardening runs before any vault work.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    node_runner_lib::run()
}
