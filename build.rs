//#[macro_use]
//extern crate clap;
extern crate serde_codegen;

use std::env;
use std::path::Path;

fn main() {
    {
        let out_dir = env::var_os("OUT_DIR").unwrap();

        let src = Path::new("src/main_types.in.rs");
        let dst = Path::new(&out_dir).join("main_types.rs");

        serde_codegen::expand(&src, &dst).unwrap();
    }

    {
        let out_dir = env::var_os("OUT_DIR").unwrap();

        let src = Path::new("src/host_types.in.rs");
        let dst = Path::new(&out_dir).join("host_types.rs");

        serde_codegen::expand(&src, &dst).unwrap();
    }
    /*
     * it is broken
    {
        let yaml = load_yaml!("src/cli.yml");
        let mut app = App::from_yaml(yaml).version(crate_version!());

        app.gen_completions("grainsquery", Shell::Bash, "autocomplete");
        app.gen_completions("grainsquery", Shell::Fish, "autocomplete");
        app.gen_completions("grainsquery", Shell::Zsh, "autocomplete");
    }*/
}
