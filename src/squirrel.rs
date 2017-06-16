use std::error::Error;
use std::convert::From;

pub struct SquirrelError {
    pub message: String
}

impl <A: Error> From<A> for SquirrelError {
    fn from(err: A) -> SquirrelError { 
        let message = String::from(err.description());
        SquirrelError { 
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

pub trait Squirrel {

    fn setup(&self) -> Result<String, SquirrelError>;

    fn list(&self) -> Result<Vec<String>, SquirrelError>;

    fn get(&self, id: String) -> Result<Vec<u8>, SquirrelError>;

    fn put(&self, id: String, value: Vec<u8>, overwrite: bool) -> Result<PutResult, SquirrelError>;

    fn delete(&self, id: String) -> Result<DeletionResult, SquirrelError>;

}
