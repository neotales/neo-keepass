#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Desktop UI entrypoint for `neo-keepass` built on Rune.

mod controller;
mod icons;
mod ui;

use rune::{AppSpec, ImageCache, Tx};
use ui::{AppState, view};

fn main() {
    let mut spec = AppSpec::new("neo-keepass", (1024.0, 680.0), AppState::default, view);
    spec.min_size = Some((760.0, 520.0));
    spec.setup = Some(|state: &mut AppState, waker| {
        state.images = Some(ImageCache::new(waker.clone()));
        state.unlock_worker.set_waker(waker.clone());
        state.save_worker.set_waker(waker);
    });
    spec.poll = Some(|state: &mut AppState, secs: f64, tx: &mut Tx| state.poll_frame(secs, tx));
    rune::run(spec);
}
