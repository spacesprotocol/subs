use risc0_zkvm::guest::env;

use program::guest::{run};

fn main() {
    let (subtree, input, policy_step, policy_fold): (Vec<u8>, Vec<u8>, [u32; 8], [u32; 8]) = env::read();

    let out = match run(subtree, input, policy_step, policy_fold) {
        Ok(out) => out,
        Err(e) => panic!("{}", e),
    };

    env::commit(&out);
}
