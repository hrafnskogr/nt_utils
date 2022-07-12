/*
 * Error module
 * For custom errors definition
 */
use std::error::Error;
use std::fmt;

pub enum ErrState
{
    Success,
    Failure,
}

pub struct PEErr
{
    pub status: ErrState,    
    pub message : String,
}

impl fmt::Display for ErrState
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match self
        {
            ErrState::Success => write!(f, "Success"),
            ErrState::Failure => write!(f, "Failure"),
        }
    }
}

impl fmt::Display for PEErr
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "{} : {}", self.status, self.message)
    }
}

impl fmt::Debug for PEErr
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "{} : {}", self.status, self.message)
    }
}

impl Error for PEErr {}
