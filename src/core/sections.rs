use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use crate::common::images::{PEImage, define_pe_image_struct};


define_pe_image_struct!(
    ImageImportByName,
    hint, u16,
    name, String
);


define_pe_image_struct!(
    ImageThunkData,
    ordinal_flag, u8,
    ordinal, u64,
    address_of_data, u64,
    import_by_name, Option<ImageImportByName>
);


impl ImageThunkData {

    pub fn new(buffer: &[u8]) -> PyResult<ImageThunkData>{
        if buffer.len() != 4 && buffer.len() != 8 {
            return Err(PyValueError::new_err(
                format!("The size of the buffer required to create an ImageThunkData object must be equal to either 4 or 8 (size received : {})", buffer.len())
                )
            );
        }

        if buffer.len() == 4 {
            let image_thunk_data_value = u32::from_le_bytes(buffer[..].try_into()?);

            Ok(ImageThunkData{
                ordinal_flag: (image_thunk_data_value & 0x80000000) as u8,
                ordinal: (image_thunk_data_value & 0x7FFFFFFF) as u64,
                address_of_data: image_thunk_data_value as u64,
                import_by_name: None
            })
        }
        else {
            let image_thunk_data_value = u64::from_le_bytes(buffer[..].try_into()?);
            Ok(ImageThunkData{
                ordinal_flag: (image_thunk_data_value & 0x8000000000000000) as u8,
                ordinal: image_thunk_data_value & 0x7FFFFFFFFFFFFFFF,
                address_of_data: image_thunk_data_value,
                import_by_name: None
            })
        }
    }

    pub fn get_size(pe_is_64bits: bool) -> usize {
        if pe_is_64bits {8} else {4}
    }
}


define_pe_image_struct!(
    ImageImportDescriptor,
    original_first_thunk, u32,
    time_date_stamp, u32,
    forwarder_chain, u32,
    name_rva, u32,
    first_thunk, u32
);


impl PEImage for ImageImportDescriptor {
    const SIZE_IMAGE: usize = 20;

    fn from_bytes(buffer: &[u8]) ->  PyResult<Self> {
        Ok(ImageImportDescriptor {
            original_first_thunk: u32::from_le_bytes(buffer[..4].try_into()?),
            time_date_stamp: u32::from_le_bytes(buffer[4..8].try_into()?),
            forwarder_chain: u32::from_le_bytes(buffer[8..12].try_into()?),
            name_rva: u32::from_le_bytes(buffer[12..16].try_into()?),
            first_thunk: u32::from_le_bytes(buffer[16..].try_into()?),
        })
    }
}


define_pe_image_struct!(
    ImportSectionEntry,
    name, String,
    descriptor, ImageImportDescriptor,
    thunk_data, Vec<ImageThunkData>
);


#[pyclass]
#[derive(Clone)]
pub struct ImportSection {
    #[pyo3(get)]
    pub(crate) entries: Vec<ImportSectionEntry>
}


define_pe_image_struct!(
    ExportSectionEntry,
    name, String,
    rva, u32,
    ordinal, u16,
    forwarded, bool
);


define_pe_image_struct!(
    ExportDirectoryTable,
    export_flags, u32,
    time_date_stamp, u32,
    major_version, u16,
    minor_version, u16,
    name_rva, u32,
    ordinal_base, u32,
    address_table_entries, u32,
    number_name_pointers, u32,
    export_address_table, u32,
    name_pointer, u32,
    ordinal_table, u32
);


impl PEImage for ExportDirectoryTable {
    const SIZE_IMAGE: usize = 40;

    fn from_bytes(buffer: &[u8]) ->  PyResult<Self> {
        Ok(ExportDirectoryTable {
            export_flags: u32::from_le_bytes(buffer[..4].try_into()?),
            time_date_stamp: u32::from_le_bytes(buffer[4..8].try_into()?),
            major_version: u16::from_le_bytes(buffer[8..10].try_into()?),
            minor_version: u16::from_le_bytes(buffer[10..12].try_into()?),
            name_rva: u32::from_le_bytes(buffer[12..16].try_into()?),
            ordinal_base: u32::from_le_bytes(buffer[16..20].try_into()?),
            address_table_entries: u32::from_le_bytes(buffer[20..24].try_into()?),
            number_name_pointers: u32::from_le_bytes(buffer[24..28].try_into()?),
            export_address_table: u32::from_le_bytes(buffer[28..32].try_into()?),
            name_pointer: u32::from_le_bytes(buffer[32..36].try_into()?),
            ordinal_table: u32::from_le_bytes(buffer[36..].try_into()?)
        })
    }
}


#[pyclass]
#[derive(Clone)]
pub struct ExportSection {
    #[pyo3(get)]
    pub(crate) name: String,
    #[pyo3(get)]
    pub(crate) directory_table: ExportDirectoryTable,
    #[pyo3(get)]
    pub(crate) entries: Vec<ExportSectionEntry>
}


define_pe_image_struct!(
    TlsDirectory,
    start_address_of_raw_data, u64,
    end_address_of_raw_data, u64,
    address_of_index, u64,
    address_of_callbacks, u64,
    size_of_zero_fill, u32,
    characteristics, u32
);



impl TlsDirectory {

    pub fn new(buffer: &[u8]) -> PyResult<TlsDirectory>{
        if buffer.len() != 40 && buffer.len() != 24 {
            return Err(PyValueError::new_err(
                format!("The size of the buffer required to create an TlsDirectory object must be equal to either 40 or 24 (size received : {})", buffer.len())
                )
            );
        }

        if buffer.len() == 24
        {
            Ok(TlsDirectory{
                start_address_of_raw_data: u32::from_le_bytes(buffer[..4].try_into()?) as u64,
                end_address_of_raw_data: u32::from_le_bytes(buffer[4..8].try_into()?) as u64,
                address_of_index: u32::from_le_bytes(buffer[8..12].try_into()?) as u64,
                address_of_callbacks: u32::from_le_bytes(buffer[12..16].try_into()?) as u64,
                size_of_zero_fill: u32::from_le_bytes(buffer[16..20].try_into()?),
                characteristics: u32::from_le_bytes(buffer[20..].try_into()?)
            })
        }
        else {
            Ok(TlsDirectory{
                start_address_of_raw_data: u64::from_le_bytes(buffer[..8].try_into()?),
                end_address_of_raw_data: u64::from_le_bytes(buffer[8..16].try_into()?),
                address_of_index: u64::from_le_bytes(buffer[16..24].try_into()?),
                address_of_callbacks: u64::from_le_bytes(buffer[24..32].try_into()?),
                size_of_zero_fill: u32::from_le_bytes(buffer[32..36].try_into()?),
                characteristics: u32::from_le_bytes(buffer[36..].try_into()?)
            })
        }
    }

    pub fn get_size(pe_is_64bits: bool) -> usize {
        if pe_is_64bits {40} else {24}
    }
}


define_pe_image_struct!(
    RelocEntry,
    type_reloc, u8,
    offset, u16
);


define_pe_image_struct!(
    ImageBaseRelocation,
    virtual_address, u32,
    size_of_block, u32,
    entries, Vec<RelocEntry>
);


impl PEImage for ImageBaseRelocation {
    const SIZE_IMAGE: usize = 8;

    fn from_bytes(buffer: &[u8]) ->  PyResult<Self> {
        Ok(ImageBaseRelocation {
            virtual_address: u32::from_le_bytes(buffer[..4].try_into()?),
            size_of_block: u32::from_le_bytes(buffer[4..].try_into()?),
            entries: Vec::new()
        })
    }
}

#[pyclass]
#[derive(Clone)]
pub struct RelocationSection{
    #[pyo3(get)]
    pub(crate) blocks: Vec<ImageBaseRelocation>,
}

#[pyclass]
#[derive(Clone)]
pub struct PESections {
    #[pyo3(get)]
    pub(crate) import_section: Option<ImportSection>,
    #[pyo3(get)]
    pub(crate) export_section: Option<ExportSection>,
    #[pyo3(get)]
    pub(crate) tls_directory: Option<TlsDirectory>,
    #[pyo3(get)]
    pub(crate) reloc_section: Option<RelocationSection>
}
