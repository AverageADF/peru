use std::io::Read;
use std::fs::File;
use pyo3::PyResult;

pub mod images;
pub mod exceptions;


pub fn read_ascii_string_from_file(pe_file: &mut File) -> PyResult<String> {
    let mut string_buffer: Vec<u8> = Vec::new();

    for res_curr_char in pe_file.bytes() {
        let curr_char = res_curr_char.unwrap();
        if curr_char == 0 {
            break;
        }
        string_buffer.push(curr_char);
    }

    Ok(String::from(std::str::from_utf8(&string_buffer[..])?))
}
