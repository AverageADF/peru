use pyo3::create_exception;
use pyo3::exceptions::PyException;


create_exception!(mymodule, InvalidPEFile, PyException, "Exception raised when trying to parse a file which is not a valid PE file");


macro_rules! py_unknown_error {
    ($err: ident) => {
        Err(InvalidPEFile::new_err(format!("An unknown error occurred -> {}", $err.to_string())))
    };
    ($err: ident, $err_msg: expr) => {
        Err(InvalidPEFile::new_err(format!("{} -> {}", $err_msg ,$err.to_string())))
    };
}

pub(crate) use py_unknown_error;
