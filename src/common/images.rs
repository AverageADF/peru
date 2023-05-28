use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;


pub trait PEImage {
    const SIZE_IMAGE: usize;

    fn from_bytes(buffer: &[u8]) -> PyResult<Self> where Self: Sized;

    fn new(buffer: &[u8]) ->PyResult<Self> where Self: Sized {
        if buffer.len() != Self::SIZE_IMAGE {
            Err(PyValueError::new_err(
                format!("The size of the buffer received to create a {} is incorrect (Expected size: {}, Size of the given buffer: {})", std::any::type_name::<Self>(), Self::SIZE_IMAGE, buffer.len())
                )
            )
        }
        else {
            Self::from_bytes(buffer)
        }
    }
}

macro_rules! define_pe_image_struct {
    ($struct_name: ident, $($struct_field: ident, $struct_field_type: ty),+) => {
        #[pyclass]
        #[derive(Clone)]
        pub struct $struct_name {
            $(
                #[pyo3(get)]
                pub $struct_field: $struct_field_type,
            )+
        }
    }
}


pub(crate) use define_pe_image_struct;
