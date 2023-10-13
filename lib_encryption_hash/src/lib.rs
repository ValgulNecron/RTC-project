use std::error::Error;
use argon2::{password_hash::{
    rand_core::OsRng, PasswordHasher, SaltString
}, Argon2, Params};
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;

pub fn hash_password(password: &str) -> Result<String,  Box<dyn Error>>  {
    let salt = SaltString::generate(&mut OsRng);
    let parameter = Params::new(40_000u32, 8u32, 1u32, Option::from(1024usize))?;
    let argon2 = Argon2::new(Argon2id, V0x13, parameter);
    Ok(argon2.hash_password(password.as_ref(), &salt)?.to_string())
}