use std::error::Error;
use std::convert::From;

pub struct MoroccoError {
    pub message: String
}

impl <A: Error> From<A> for MoroccoError {
    fn from(err: A) -> MoroccoError { 
        let message = String::from(err.description());
        MoroccoError { 
            message
        }
    }
}

pub enum PutResult {
    Stored,
    DidNotOverwrite
}

pub enum DeletionResult {
    Deleted,
    NotFound
}

pub trait Morocco {

    fn setup(&self) -> Result<String, MoroccoError>;

    fn list(&self) -> Result<Vec<String>, MoroccoError>;

    fn get(&self, id: String) -> Result<Vec<u8>, MoroccoError>;

    fn put(&self, id: String, value: Vec<u8>, overwrite: bool) -> Result<PutResult, MoroccoError>;

    fn delete(&self, id: String) -> Result<DeletionResult, MoroccoError>;

}
