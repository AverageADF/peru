use std::collections::HashMap;
use std::iter::{IntoIterator, Iterator};
use std::u32;
use pyo3::prelude::*;
use lazy_static::lazy_static;
use crate::common::images::{PEImage, define_pe_image_struct};
use crate::common::exceptions::InvalidPEFile;


// ------------------------------------------- DOS HEADER ------------------------------------------

define_pe_image_struct!(
    ImageDosHeader,
    e_magic, u16,
    e_cblp, u16,
    e_cp, u16,
    e_crlc, u16,
    e_cparhdr, u16,
    e_minalloc, u16,
    e_maxalloc, u16,
    e_ss, u16,
    e_sp, u16,
    e_csum, u16,
    e_ip, u16,
    e_cs, u16,
    e_lfarlc, u16,
    e_ovno, u16,
    e_res, Vec<u16>,
    e_oemid, u16,
    e_oeminfo, u16,
    e_res2, Vec<u16>,
    e_lfanew, u32
);


impl PEImage for ImageDosHeader {
    const SIZE_IMAGE: usize = 64;

    fn from_bytes(buffer: &[u8]) ->  PyResult<Self> {

        if vec![0x4d, 0x5a] != buffer[..2] {
            return Err(InvalidPEFile::new_err("Invalid magic number"));
        }

        Ok(ImageDosHeader {
            e_magic: u16::from_le_bytes(buffer[0..2].try_into()?),
            e_cblp: u16::from_le_bytes(buffer[2..4].try_into()?),
            e_cp: u16::from_le_bytes(buffer[4..6].try_into()?),
            e_crlc: u16::from_le_bytes(buffer[6..8].try_into()?),
            e_cparhdr: u16::from_le_bytes(buffer[8..10].try_into()?),
            e_minalloc: u16::from_le_bytes(buffer[10..12].try_into()?),
            e_maxalloc: u16::from_le_bytes(buffer[12..14].try_into()?),
            e_ss: u16::from_le_bytes(buffer[14..16].try_into()?),
            e_sp: u16::from_le_bytes(buffer[16..18].try_into()?),
            e_csum: u16::from_le_bytes(buffer[18..20].try_into()?),
            e_ip: u16::from_le_bytes(buffer[20..22].try_into()?),
            e_cs: u16::from_le_bytes(buffer[22..24].try_into()?),
            e_lfarlc: u16::from_le_bytes(buffer[24..26].try_into()?),
            e_ovno: u16::from_le_bytes(buffer[26..28].try_into()?),
            e_res: buffer[28..36].chunks_exact(2).into_iter().map(|a| u16::from_le_bytes([a[0], a[1]])).collect(),
            e_oemid: u16::from_le_bytes(buffer[36..38].try_into()?),
            e_oeminfo: u16::from_le_bytes(buffer[38..40].try_into()?),
            e_res2: buffer[40..60].chunks_exact(2).into_iter().map(|a| u16::from_le_bytes([a[0], a[1]])).collect(),
            e_lfanew: u32::from_le_bytes(buffer[60..].try_into()?)
        })
    }
}


#[pymethods]
impl ImageDosHeader {
    #[new]
    pub fn new_py(buffer: &[u8]) -> PyResult<Self> {
        Self::new(buffer)
    }
}


// -------------------------------------------- NT HEADER ------------------------------------------

define_pe_image_struct!(
    ImageDataDirectory,
    virtual_address, u32,
    size, u32
);


impl PEImage for ImageDataDirectory {
    const SIZE_IMAGE: usize = 8;

    fn from_bytes(buffer: &[u8]) ->  PyResult<Self> {
        Ok(ImageDataDirectory {
            virtual_address: u32::from_le_bytes(buffer[..4].try_into()?),
            size: u32::from_le_bytes(buffer[4..].try_into()?),
        })
    }
}


#[pymethods]
impl ImageDataDirectory {
    #[new]
    pub fn new_py(buffer: &[u8]) -> PyResult<Self> {
        Self::new(buffer)
    }
}


define_pe_image_struct!(
    ImageFileHeader,
    machine, u16,
    number_of_sections, u16,
    time_date_stamp, u32,
    pointer_to_symbol_table, u32,
    number_of_symbols, u32,
    size_of_optional_header, u16,
    characteristics, u16
);


impl PEImage for ImageFileHeader {
    const SIZE_IMAGE: usize = 20;

    fn from_bytes(buffer: &[u8]) ->  PyResult<Self> {
        Ok(ImageFileHeader {
            machine: u16::from_le_bytes(buffer[..2].try_into()?),
            number_of_sections: u16::from_le_bytes(buffer[2..4].try_into()?),
            time_date_stamp: u32::from_le_bytes(buffer[4..8].try_into()?),
            pointer_to_symbol_table: u32::from_le_bytes(buffer[8..12].try_into()?),
            number_of_symbols: u32::from_le_bytes(buffer[12..16].try_into()?),
            size_of_optional_header: u16::from_le_bytes(buffer[16..18].try_into()?),
            characteristics: u16::from_le_bytes(buffer[18..20].try_into()?),
        })
    }
}


#[pymethods]
impl ImageFileHeader {
    #[new]
    pub fn new_py(buffer: &[u8]) -> PyResult<Self> {
        Self::new(buffer)
    }
}


lazy_static! {
    static ref DLL_CHARACTERISTICS_VALUE_2_DESCRIPTION: HashMap<u16, &'static str> = HashMap::from([
        (0x0020, "Image can handle a high entropy 64-bit virtual address space."),
        (0x0040, "DLL can be relocated at load time."),
        (0x0080, "Code Integrity checks are enforced."),
        (0x0100, "Image is NX compatible."),
        (0x0200, "Isolation aware, but do not isolate the image."),
        (0x0400, "Does not use structured exception (SE) handling. No SE handler may be called in this image."),
        (0x0800, "Do not bind the image."),
        (0x1000, "Image must execute in an AppContainer."),
        (0x2000, "A WDM driver."),
        (0x4000, "Image supports Control Flow Guard."),
        (0x8000, "Terminal Server aware."),
    ]);

    static ref DATA_DIRECTORY_2_TYPE: Vec<&'static str> = vec![
        "Export Directory",
        "Import Directory",
        "Resource Directory",
        "Exception Directory",
        "Security Directory",
        "Base Relocation Table",
        "Debug Directory",
        "Architecture Specific Data",
        "RVA of GlobalPtr",
        "TLS Directory",
        "Load Configuration Directory",
        "Bound Import Directory in headers",
        "Import Address Table",
        "Delay Load Import Descriptors",
        "COM Runtime descriptor",
    ];
}


trait ImageOptionalHeader {
     fn get_dll_characteristics_from_flag(flag: u16) -> Vec<&'static str>{
         DLL_CHARACTERISTICS_VALUE_2_DESCRIPTION
            .iter()
            .filter(|(ref_value, _descr)| (*ref_value & flag) != 0)
            .map(|(_ptr_value, descr)| *descr)
            .collect()
     }

    fn get_valid_data_directories(dd: &Vec<ImageDataDirectory>) -> Vec<&'static str> {
        DATA_DIRECTORY_2_TYPE
            .iter()
            .enumerate()
            .filter(|(idx, _data_directory_type)| {
                match dd.get(*idx) {
                    Some(data_directory) => data_directory.virtual_address > 0 && data_directory.size > 0,
                    None => false
                }
            })
            .map(|(_idx, data_directory_type)| *data_directory_type)
            .collect()
    }

    fn get_import_directory_from_vec(dd: &Vec<ImageDataDirectory>) -> Option<&ImageDataDirectory>{
        dd.get(1)
    }

    fn get_reloc_directory_from_vec(dd: &Vec<ImageDataDirectory>) -> Option<&ImageDataDirectory>{
        dd.get(5)
    }

    fn get_export_directory_from_vec(dd: &Vec<ImageDataDirectory>) -> Option<&ImageDataDirectory>{
        dd.get(0)
    }

    fn get_tls_data_directory_from_vec(dd: &Vec<ImageDataDirectory>) -> Option<&ImageDataDirectory>{
        dd.get(9)
    }
}


define_pe_image_struct!(
    ImageOptionalHeader64,
    magic, u16,
    major_linker_version, u8,
    minor_linker_version, u8,
    size_of_code, u32,
    size_of_initialized_data, u32,
    size_of_uninitialized_data, u32,
    address_of_entry_point, u32,
    base_of_code, u32,
    image_base, u64,
    section_alignment, u32,
    file_alignment, u32,
    major_operating_system_version, u16,
    minor_operating_system_version, u16,
    major_image_version, u16,
    minor_image_version, u16,
    major_subsystem_version, u16,
    minor_subsystem_version, u16,
    win32_version_value, u32,
    size_of_image, u32,
    size_of_headers, u32,
    checksum, u32,
    subsystem, u16,
    dll_characteristics, u16,
    size_of_stack_reserve, u64,
    size_of_stack_commit, u64,
    size_of_heap_reserve, u64,
    size_of_heap_commit, u64,
    loader_flags, u32,
    number_of_rva_and_sizes, u32,
    data_directory, Vec<ImageDataDirectory>
);


impl PEImage for ImageOptionalHeader64 {
    const SIZE_IMAGE: usize = 240;

    fn from_bytes(buffer: &[u8]) ->  PyResult<Self> {
        Ok(ImageOptionalHeader64 {
            magic: u16::from_le_bytes(buffer[..2].try_into()?),
            major_linker_version: buffer[2],
            minor_linker_version: buffer[3],
            size_of_code: u32::from_le_bytes(buffer[4..8].try_into()?),
            size_of_initialized_data: u32::from_le_bytes(buffer[8..12].try_into()?),
            size_of_uninitialized_data: u32::from_le_bytes(buffer[12..16].try_into()?),
            address_of_entry_point: u32::from_le_bytes(buffer[16..20].try_into()?),
            base_of_code: u32::from_le_bytes(buffer[20..24].try_into()?),
            image_base: u64::from_le_bytes(buffer[24..32].try_into()?),
            section_alignment: u32::from_le_bytes(buffer[32..36].try_into()?),
            file_alignment: u32::from_le_bytes(buffer[36..40].try_into()?),
            major_operating_system_version: u16::from_le_bytes(buffer[40..42].try_into()?),
            minor_operating_system_version: u16::from_le_bytes(buffer[42..44].try_into()?),
            major_image_version: u16::from_le_bytes(buffer[44..46].try_into()?),
            minor_image_version: u16::from_le_bytes(buffer[46..48].try_into()?),
            major_subsystem_version: u16::from_le_bytes(buffer[48..50].try_into()?),
            minor_subsystem_version: u16::from_le_bytes(buffer[50..52].try_into()?),
            win32_version_value: u32::from_le_bytes(buffer[52..56].try_into()?),
            size_of_image: u32::from_le_bytes(buffer[56..60].try_into()?),
            size_of_headers: u32::from_le_bytes(buffer[60..64].try_into()?),
            checksum: u32::from_le_bytes(buffer[64..68].try_into()?),
            subsystem: u16::from_le_bytes(buffer[68..70].try_into()?),
            dll_characteristics: u16::from_le_bytes(buffer[70..72].try_into()?),
            size_of_stack_reserve: u64::from_le_bytes(buffer[72..80].try_into()?),
            size_of_stack_commit: u64::from_le_bytes(buffer[80..88].try_into()?),
            size_of_heap_reserve: u64::from_le_bytes(buffer[88..96].try_into()?),
            size_of_heap_commit: u64::from_le_bytes(buffer[96..104].try_into()?),
            loader_flags: u32::from_le_bytes(buffer[104..108].try_into()?),
            number_of_rva_and_sizes: u32::from_le_bytes(buffer[108..112].try_into()?),
            data_directory: buffer[112..]
                .chunks_exact(ImageDataDirectory::SIZE_IMAGE)
                .into_iter()
                .map(|e| ImageDataDirectory::from_bytes(e))
                .collect::<Result<_, _>>()?,
        })
    }
}


impl ImageOptionalHeader for ImageOptionalHeader64 {}

impl ImageOptionalHeader64 {
    pub fn get_import_directory(&self) -> Option<&ImageDataDirectory> {
        Self::get_import_directory_from_vec(&self.data_directory)
    }

    pub fn get_reloc_directory(&self) -> Option<&ImageDataDirectory> {
        Self::get_reloc_directory_from_vec(&self.data_directory)
    }

    pub fn get_export_directory(&self) -> Option<&ImageDataDirectory> {
        Self::get_export_directory_from_vec(&self.data_directory)
    }

    pub fn get_tls_data_directory(&self) -> Option<&ImageDataDirectory> {
        Self::get_tls_data_directory_from_vec(&self.data_directory)
    }
}


#[pymethods]
impl ImageOptionalHeader64 {
    #[new]
    pub fn new_py(buffer: &[u8]) -> PyResult<Self> {
        Self::new(buffer)
    }

    pub fn resolve_characteristics(&self) -> Vec<&'static str> {
        Self::get_dll_characteristics_from_flag(self.dll_characteristics)
    }

    pub fn resolve_data_directories(&self) -> Vec<&'static str> {
        Self::get_valid_data_directories(&self.data_directory)
    }
}


define_pe_image_struct!(
    ImageOptionalHeader32,
    magic, u16,
    major_linker_version, u8,
    minor_linker_version, u8,
    size_of_code, u32,
    size_of_initialized_data, u32,
    size_of_uninitialized_data, u32,
    address_of_entry_point, u32,
    base_of_code, u32,
    base_of_data, u32,
    image_base, u32,
    section_alignment, u32,
    file_alignment, u32,
    major_operating_system_version, u16,
    minor_operating_system_version, u16,
    major_image_version, u16,
    minor_image_version, u16,
    major_subsystem_version, u16,
    minor_subsystem_version, u16,
    win32_version_value, u32,
    size_of_image, u32,
    size_of_headers, u32,
    checksum, u32,
    subsystem, u16,
    dll_characteristics, u16,
    size_of_stack_reserve, u32,
    size_of_stack_commit, u32,
    size_of_heap_reserve, u32,
    size_of_heap_commit, u32,
    loader_flags, u32,
    number_of_rva_and_sizes, u32,
    data_directory, Vec<ImageDataDirectory>
);


impl PEImage for ImageOptionalHeader32 {
    const SIZE_IMAGE: usize = 224;

    fn from_bytes(buffer: &[u8]) ->  PyResult<Self> {
        Ok(ImageOptionalHeader32 {
            magic: u16::from_le_bytes(buffer[..2].try_into()?),
            major_linker_version: buffer[2],
            minor_linker_version: buffer[3],
            size_of_code: u32::from_le_bytes(buffer[4..8].try_into()?),
            size_of_initialized_data: u32::from_le_bytes(buffer[8..12].try_into()?),
            size_of_uninitialized_data: u32::from_le_bytes(buffer[12..16].try_into()?),
            address_of_entry_point: u32::from_le_bytes(buffer[16..20].try_into()?),
            base_of_code: u32::from_le_bytes(buffer[20..24].try_into()?),
            base_of_data: u32::from_le_bytes(buffer[24..28].try_into()?),
            image_base: u32::from_le_bytes(buffer[28..32].try_into()?),
            section_alignment: u32::from_le_bytes(buffer[32..36].try_into()?),
            file_alignment: u32::from_le_bytes(buffer[36..40].try_into()?),
            major_operating_system_version: u16::from_le_bytes(buffer[40..42].try_into()?),
            minor_operating_system_version: u16::from_le_bytes(buffer[42..44].try_into()?),
            major_image_version: u16::from_le_bytes(buffer[44..46].try_into()?),
            minor_image_version: u16::from_le_bytes(buffer[46..48].try_into()?),
            major_subsystem_version: u16::from_le_bytes(buffer[48..50].try_into()?),
            minor_subsystem_version: u16::from_le_bytes(buffer[50..52].try_into()?),
            win32_version_value: u32::from_le_bytes(buffer[52..56].try_into()?),
            size_of_image: u32::from_le_bytes(buffer[56..60].try_into()?),
            size_of_headers: u32::from_le_bytes(buffer[60..64].try_into()?),
            checksum: u32::from_le_bytes(buffer[64..68].try_into()?),
            subsystem: u16::from_le_bytes(buffer[68..70].try_into()?),
            dll_characteristics: u16::from_le_bytes(buffer[70..72].try_into()?),
            size_of_stack_reserve: u32::from_le_bytes(buffer[72..76].try_into()?),
            size_of_stack_commit: u32::from_le_bytes(buffer[76..80].try_into()?),
            size_of_heap_reserve: u32::from_le_bytes(buffer[80..84].try_into()?),
            size_of_heap_commit: u32::from_le_bytes(buffer[84..88].try_into()?),
            loader_flags: u32::from_le_bytes(buffer[88..92].try_into()?),
            number_of_rva_and_sizes: u32::from_le_bytes(buffer[92..96].try_into()?),
            data_directory: buffer[96..]
                .chunks_exact(ImageDataDirectory::SIZE_IMAGE)
                .into_iter()
                .map(|e| ImageDataDirectory::from_bytes(e))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl ImageOptionalHeader for ImageOptionalHeader32 {}

impl ImageOptionalHeader32 {
    pub fn get_import_directory(&self) -> Option<&ImageDataDirectory> {
        Self::get_import_directory_from_vec(&self.data_directory)
    }

    pub fn get_reloc_directory(&self) -> Option<&ImageDataDirectory> {
        Self::get_reloc_directory_from_vec(&self.data_directory)
    }

    pub fn get_export_directory(&self) -> Option<&ImageDataDirectory> {
        Self::get_export_directory_from_vec(&self.data_directory)
    }

    pub fn get_tls_data_directory(&self) -> Option<&ImageDataDirectory> {
        Self::get_tls_data_directory_from_vec(&self.data_directory)
    }
}

#[pymethods]
impl ImageOptionalHeader32 {
    #[new]
    pub fn new_py(buffer: &[u8]) -> PyResult<Self> {
        Self::new(buffer)
    }

    pub fn resolve_characteristics(&self) -> Vec<&'static str> {
        Self::get_dll_characteristics_from_flag(self.dll_characteristics)
    }

    pub fn resolve_data_directories(&self) -> Vec<&'static str> {
        Self::get_valid_data_directories(&self.data_directory)
    }
}


define_pe_image_struct!(
    ImageNtHeader64,
    signature, u32,
    file_header, ImageFileHeader,
    optional_header, ImageOptionalHeader64
);


impl PEImage for ImageNtHeader64 {
    const SIZE_IMAGE: usize = 264;

    fn from_bytes(buffer: &[u8]) -> PyResult<Self> {
        if vec![0x50, 0x45, 0x0, 0x0] != buffer[..4] {
            return Err(InvalidPEFile::new_err("Invalid signature"));
        }

        Ok(ImageNtHeader64 {
            signature: u32::from_le_bytes(buffer[..4].try_into()?),
            file_header: ImageFileHeader::from_bytes(&buffer[4..(4 + ImageFileHeader::SIZE_IMAGE)])?,
            optional_header: ImageOptionalHeader64::from_bytes(&buffer[(4 + ImageFileHeader::SIZE_IMAGE)..])?
        })
    }
}


#[pymethods]
impl ImageNtHeader64 {
    #[new]
    pub fn new_py(buffer: &[u8]) -> PyResult<Self> {
        Self::new(buffer)
    }
}


define_pe_image_struct!(
    ImageNtHeader32,
    signature, u32,
    file_header, ImageFileHeader,
    optional_header, ImageOptionalHeader32
);


impl PEImage for ImageNtHeader32 {
    const SIZE_IMAGE: usize = 248;

    fn from_bytes(buffer: &[u8]) -> PyResult<Self> {
        if vec![0x50, 0x45, 0x0, 0x0] != buffer[..4] {
            return Err(InvalidPEFile::new_err("Invalid signature"));
        }

        Ok(ImageNtHeader32 {
            signature: u32::from_le_bytes(buffer[..4].try_into()?),
            file_header: ImageFileHeader::from_bytes(&buffer[4..(4 + ImageFileHeader::SIZE_IMAGE)])?,
            optional_header: ImageOptionalHeader32::from_bytes(&buffer[(4 + ImageFileHeader::SIZE_IMAGE)..])?
        })
    }
}


#[pymethods]
impl ImageNtHeader32 {
    #[new]
    pub fn new_py(buffer: &[u8]) -> PyResult<Self> {
        Self::new(buffer)
    }
}


pub enum ImageNtHeader{
    NtHeader32(ImageNtHeader32),
    NtHeader64(ImageNtHeader64)
}

// ----------------------------------------- SECTION HEADER ----------------------------------------


lazy_static! {
    static ref SECTION_CHARACTERISTICS_VALUE_2_DESCRIPTION: HashMap<u32, &'static str> = HashMap::from([
        (0x00000008, "The section should not be padded to the next boundary. This flag is obsolete."),
        (0x00000020, "The section contains executable code."),
        (0x00000040, "The section contains initialized data."),
        (0x00000080, "The section contains uninitialized data."),
        (0x00000200, "The section contains comments or other information."),
        (0x00000800, "The section will not become part of the image."),
        (0x00001000, "The section contains COMDAT data."),
        (0x00008000, "The section contains data referenced through the global pointer."),
        (0x00100000, "Align data on a 1-byte boundary."),
        (0x00200000, "Align data on a 2-byte boundary."),
        (0x00300000, "Align data on a 4-byte boundary."),
        (0x00400000, "Align data on an 8-byte boundary."),
        (0x00500000, "Align data on a 16-byte boundary."),
        (0x00600000, "Align data on a 32-byte boundary."),
        (0x00700000, "Align data on a 64-byte boundary."),
        (0x00800000, "Align data on a 128-byte boundary."),
        (0x00900000, "Align data on a 256-byte boundary."),
        (0x00A00000, "Align data on a 512-byte boundary."),
        (0x00B00000, "Align data on a 1024-byte boundary."),
        (0x00C00000, "Align data on a 2048-byte boundary."),
        (0x00D00000, "Align data on a 4096-byte boundary."),
        (0x00E00000, "Align data on an 8192-byte boundary."),
        (0x01000000, "The section contains extended relocations."),
        (0x02000000, "The section can be discarded as needed."),
        (0x04000000, "The section cannot be cached."),
        (0x08000000, "The section is not pageable."),
        (0x10000000, "The section can be shared in memory."),
        (0x20000000, "The section can be executed as code."),
        (0x40000000, "The section can be read."),
        (0x80000000, "The section can be written to."),
    ]);
}

define_pe_image_struct!(
    ImageSectionHeader,
    name, String,
    virtual_size, u32,
    virtual_address, u32,
    size_of_raw_data, u32,
    pointer_to_raw_data, u32,
    pointer_to_relocations, u32,
    pointer_to_line_numbers, u32,
    number_of_relocations, u16,
    number_of_line_numbers, u16,
    characteristics, u32
);


impl PEImage for ImageSectionHeader {
    const SIZE_IMAGE: usize = 40;

    fn from_bytes(buffer: &[u8]) -> PyResult<Self> {
        Ok(ImageSectionHeader{
            name: String::from(std::str::from_utf8(&buffer[..8])?),
            virtual_size: u32::from_le_bytes(buffer[8..12].try_into()?),
            virtual_address: u32::from_le_bytes(buffer[12..16].try_into()?),
            size_of_raw_data: u32::from_le_bytes(buffer[16..20].try_into()?),
            pointer_to_raw_data: u32::from_le_bytes(buffer[20..24].try_into()?),
            pointer_to_relocations: u32::from_le_bytes(buffer[24..28].try_into()?),
            pointer_to_line_numbers: u32::from_le_bytes(buffer[28..32].try_into()?),
            number_of_relocations: u16::from_le_bytes(buffer[32..34].try_into()?),
            number_of_line_numbers: u16::from_le_bytes(buffer[34..36].try_into()?),
            characteristics: u32::from_le_bytes(buffer[36..].try_into()?)
        })
    }
}

#[pymethods]
impl ImageSectionHeader {
    #[new]
    pub fn new_py(buffer: &[u8]) -> PyResult<Self> {
        Self::new(buffer)
    }

    fn resolve_characteristics(&self) -> Vec<&'static str> {
        SECTION_CHARACTERISTICS_VALUE_2_DESCRIPTION
            .iter()
            .filter(|(ref_value, _descr)| (*ref_value & self.characteristics) != 0)
            .map(|(_ptr_value, descr)| *descr)
            .collect()
    }
}
