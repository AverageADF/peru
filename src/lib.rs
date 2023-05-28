mod core;
mod common;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use pyo3::prelude::*;
use pyo3::exceptions::{PyFileNotFoundError, PyRuntimeError};
use crate::core::headers::*;
use crate::core::sections::*;
use crate::common::images::PEImage;
use crate::common::exceptions::{InvalidPEFile, py_unknown_error};


#[pyclass]
struct PEFile {
    #[pyo3(get)]
    path: PathBuf,
    #[pyo3(get)]
    dos_header: Option<ImageDosHeader>,
    nt_header: Option<ImageNtHeader>,
    #[pyo3(get)]
    section_headers: Option<Vec<ImageSectionHeader>>,
    #[pyo3(get)]
    sections: Option<PESections>
}


impl PEFile {
    fn parse_dos_header(&mut self, pe_file: &mut File) -> PyResult<()> {
        pe_file.seek(SeekFrom::Start(0))?;

        let mut buffer: Vec<u8> = vec![0; ImageDosHeader::SIZE_IMAGE];
        pe_file.read_exact(&mut buffer)?;

        self.dos_header = Some(ImageDosHeader::new(&buffer[..])?);

        Ok(())
    }

    fn parse_nt_header(&mut self, pe_file: &mut File) -> PyResult<()> {
        let dos_header = match self.dos_header.as_ref() {
            Some(pe_dos_header) => pe_dos_header,
            None => {return Err(PyRuntimeError::new_err("Cannot parse the NT Headers without having parsed the DOS Header first"));}
        };

        // Jumping to the SizeOfOptionalHeader field
        pe_file.seek(SeekFrom::Start((dos_header.e_lfanew + 20) as u64))?;

        let mut buffer_size_optional_header: Vec<u8> = vec![0; 2];
        pe_file.read_exact(&mut buffer_size_optional_header)?;

        let size_optional_header: usize = u16::from_le_bytes(buffer_size_optional_header[..].try_into()?) as usize;

        // Jumping back to the Signature Field
        pe_file.seek(SeekFrom::Start(dos_header.e_lfanew as u64))?;
        match size_optional_header {
            ImageOptionalHeader32::SIZE_IMAGE => {
                let mut buffer_file_header = vec![0; ImageNtHeader32::SIZE_IMAGE];
                pe_file.read_exact(&mut buffer_file_header)?;

                self.nt_header = Some(
                    ImageNtHeader::NtHeader32(ImageNtHeader32::new(&buffer_file_header[..])?)
                );

            },
            ImageOptionalHeader64::SIZE_IMAGE => {
                let mut buffer_file_header = vec![0; ImageNtHeader64::SIZE_IMAGE];
                pe_file.read_exact(&mut buffer_file_header)?;

                self.nt_header = Some(
                    ImageNtHeader::NtHeader64(ImageNtHeader64::new(&buffer_file_header[..])?)
                );
            },
            _ => {return Err(InvalidPEFile::new_err(format!("Incorrect size for the optional header : {size_optional_header}")));}
        }

        Ok(())
    }

    fn parse_section_headers(&mut self, pe_file: &mut File) -> PyResult<()> {
        let e_lfanew = match self.dos_header.as_ref() {
            Some(pe_dos_header) => pe_dos_header.e_lfanew,
            None => {return Err(PyRuntimeError::new_err("Cannot parse the Section Headers without having parsed the DOS Header first"));}
        };

        let (size_nt_header, n_sections) = match self.nt_header.as_ref() {
            Some(pe_nt_header) => {
                match pe_nt_header {
                    ImageNtHeader::NtHeader32(image_nt_header_32) => (ImageNtHeader32::SIZE_IMAGE, image_nt_header_32.file_header.number_of_sections),
                    ImageNtHeader::NtHeader64(image_nt_header_64) => (ImageNtHeader64::SIZE_IMAGE, image_nt_header_64.file_header.number_of_sections)
                }
            },
            None => {return Err(PyRuntimeError::new_err("Cannot parse the Section Headers without having parsed the NT Header first"));}
        };

        let mut section_headers: Vec<ImageSectionHeader> = vec![];

        for i in 0..n_sections {
            // Jumping to the ith Section Header
            pe_file.seek(SeekFrom::Start((e_lfanew as u64) + (size_nt_header as u64) + ((i as u64) * (ImageSectionHeader::SIZE_IMAGE as u64))))?;

            let mut buffer_current_section_header: Vec<u8> = vec![0; ImageSectionHeader::SIZE_IMAGE];
            pe_file.read_exact(&mut buffer_current_section_header)?;

            section_headers.push(
              ImageSectionHeader::new(&buffer_current_section_header[..])?
            );

        }

        self.section_headers = Some(section_headers);

        Ok(())
    }


    fn parse_import_section(&self, pe_file: &mut File) -> PyResult<Option<ImportSection>> {
        let opt_import_directory = match self.nt_header.as_ref() {
            Some(image_nt_header) => {
                match image_nt_header {
                    ImageNtHeader::NtHeader32(nt_header32) => nt_header32.optional_header.get_import_directory(),
                    ImageNtHeader::NtHeader64(nt_header64) => nt_header64.optional_header.get_import_directory(),
                }

            },
            None => {return Err(PyRuntimeError::new_err("Cannot parse the import section without having parsed the NT Headers first"));}
        };

        if opt_import_directory.is_none() {
            return Err(PyRuntimeError::new_err("Failed to find the import directory in the optional header"));
        }
        let import_directory = opt_import_directory.unwrap();
        if import_directory.virtual_address == 0 && import_directory.size == 0 {
            return Ok(None);
        }

        let import_directory_offset = self.rva_to_file_offset(import_directory.virtual_address)?;
        let mut count_entries = 0;
        let mut vec_section_entries: Vec<ImportSectionEntry> = Vec::new();

        loop {
            // Jumping to the ith ImageImportDescriptor / Entry
            pe_file.seek(SeekFrom::Start((import_directory_offset as u64) + count_entries * (ImageImportDescriptor::SIZE_IMAGE as u64)))?;

            let mut import_descriptor_buffer: Vec<u8> = vec![0; ImageImportDescriptor::SIZE_IMAGE];
            match pe_file.read_exact(&mut import_descriptor_buffer) {
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(PyErr::from(err)),
                _ => ()
            }

            let curr_import_descriptor = ImageImportDescriptor::new(&import_descriptor_buffer)?;

            if curr_import_descriptor.name_rva == 0 && curr_import_descriptor.first_thunk == 0 {
                break;
            }
            count_entries += 1;

            // Parsing the name of the DLL
            pe_file.seek(SeekFrom::Start(self.rva_to_file_offset(curr_import_descriptor.name_rva)? as u64))?;
            let dll_name = common::read_ascii_string_from_file(pe_file)?;

            // Parsing the imports from the DLL
            let first_thunk_offset = self.rva_to_file_offset(curr_import_descriptor.original_first_thunk)?;
            let mut count_thunk_data = 0;
            let mut vec_thunk_data: Vec<ImageThunkData> = Vec::new();

            loop {
                let thunk_data_required_size = ImageThunkData::get_size(self.is_64bit()?);

                pe_file.seek(SeekFrom::Start(
                        (first_thunk_offset as u64)
                        +
                        (count_thunk_data * thunk_data_required_size as u64)
                ))?;

                let mut thunk_data_buffer: Vec<u8> = vec![0; thunk_data_required_size];
                pe_file.read_exact(&mut thunk_data_buffer)?;
                let mut curr_thunk_data = ImageThunkData::new(&thunk_data_buffer)?;

                if curr_thunk_data.address_of_data == 0 {
                    break;
                }

                if curr_thunk_data.ordinal_flag == 0 {
                    let import_by_name_offset = self.rva_to_file_offset(curr_thunk_data.address_of_data as u32)?;
                    pe_file.seek(SeekFrom::Start(import_by_name_offset as u64))?;

                    let mut hint_buffer: Vec<u8> = vec![0; 2];
                    pe_file.read_exact(&mut hint_buffer)?;

                    curr_thunk_data.import_by_name = Some(ImageImportByName{
                        hint: u16::from_le_bytes(hint_buffer[..].try_into()?),
                        name: common::read_ascii_string_from_file(pe_file)?
                    });
                }

                vec_thunk_data.push(curr_thunk_data);
                count_thunk_data += 1;

            }

            vec_section_entries.push(ImportSectionEntry {
                name: dll_name,
                descriptor: curr_import_descriptor,
                thunk_data: vec_thunk_data
            })

        }


        Ok(Some(ImportSection{entries: vec_section_entries}))
    }

    fn parse_export_section(&self, pe_file: &mut File) -> PyResult<Option<ExportSection>> {
        let opt_export_directory = match self.nt_header.as_ref() {
            Some(image_nt_header) => {
                match image_nt_header {
                    ImageNtHeader::NtHeader32(nt_header32) => nt_header32.optional_header.get_export_directory(),
                    ImageNtHeader::NtHeader64(nt_header64) => nt_header64.optional_header.get_export_directory(),
                }

            },
            None => {return Err(PyRuntimeError::new_err("Cannot parse the export section without having parsed the NT Headers first"));}
        };

        if opt_export_directory.is_none() {
            return Err(PyRuntimeError::new_err("Failed to find the export directory in the optional header"));
        }
        let export_directory = opt_export_directory.unwrap();
        if export_directory.virtual_address == 0 && export_directory.size == 0 {
            return Ok(None);
        }

        // Jumping to the Export Directory Table
        pe_file.seek(SeekFrom::Start(self.rva_to_file_offset(export_directory.virtual_address)? as u64))?;

        let mut export_directory_table_buffer: Vec<u8> = vec![0; ExportDirectoryTable::SIZE_IMAGE];
        pe_file.read_exact(&mut export_directory_table_buffer)?;
        let export_directory_table = ExportDirectoryTable::new(&export_directory_table_buffer)?;

        // Retrieving the name of the DLL
        pe_file.seek(SeekFrom::Start(self.rva_to_file_offset(export_directory_table.name_rva)? as u64))?;
        let dll_name = common::read_ascii_string_from_file(pe_file)?;

        // Extracting data about the exported APIs
        let mut export_section_entries = Vec::new();
        let fo_name_pointer_table = self.rva_to_file_offset(export_directory_table.name_pointer)?;
        let fo_ordinal_table = self.rva_to_file_offset(export_directory_table.ordinal_table)?;
        let fo_export_address_table = self.rva_to_file_offset(export_directory_table.export_address_table)?;

        for i in 0..export_directory_table.number_name_pointers {
            // Retrieving the name of the ith Export Section Entry
            pe_file.seek(SeekFrom::Start((fo_name_pointer_table + i * 4) as u64))?;

            let mut buffer_rva_name_export_entry = vec![0; 4];
            pe_file.read_exact(&mut buffer_rva_name_export_entry)?;

            pe_file.seek(SeekFrom::Start(
                self.rva_to_file_offset(u32::from_le_bytes(buffer_rva_name_export_entry[..].try_into()?))? as u64
            ))?;
            let exported_api_name = common::read_ascii_string_from_file(pe_file)?;

            // Retrieving the ordinal value of the ith Export Section Entry
            pe_file.seek(SeekFrom::Start((fo_ordinal_table + i * 2) as u64))?;

            let mut buffer_ordinal_value = vec![0; 2];
            pe_file.read_exact(&mut buffer_ordinal_value)?;

            let ordinal_value = u16::from_le_bytes(buffer_ordinal_value[..].try_into()?);

            // Retrieving the rva of the ith Export Section Entry
            pe_file.seek(SeekFrom::Start((fo_export_address_table + (ordinal_value as u32) * 4) as u64))?;

            let mut buffer_rva_exported_api = vec![0; 4];
            pe_file.read_exact(&mut buffer_rva_exported_api)?;

            let rva_exported_api = u32::from_le_bytes(buffer_rva_exported_api[..].try_into()?);

            export_section_entries.push(ExportSectionEntry {
                name: exported_api_name,
                rva: rva_exported_api,
                ordinal: ordinal_value,
                forwarded: (
                    rva_exported_api < export_directory.virtual_address || rva_exported_api > (export_directory.virtual_address + export_directory.size)
                )
            });

        }

        Ok(Some(ExportSection{
            name: dll_name,
            directory_table: export_directory_table,
            entries: export_section_entries
        }))
    }

    fn parse_tls_directory(&self, pe_file: &mut File) -> PyResult<Option<TlsDirectory>> {
        let opt_tls_data_directory = match self.nt_header.as_ref() {
            Some(image_nt_header) => {
                match image_nt_header {
                    ImageNtHeader::NtHeader32(nt_header32) => nt_header32.optional_header.get_tls_data_directory(),
                    ImageNtHeader::NtHeader64(nt_header64) => nt_header64.optional_header.get_tls_data_directory(),
                }

            },
            None => {return Err(PyRuntimeError::new_err("Cannot parse the TLS directory without having parsed the NT Headers first"));}
        };

        if opt_tls_data_directory.is_none() {
            return Err(PyRuntimeError::new_err("Failed to find the TLS directory in the optional header"));
        }
        let tls_data_directory = opt_tls_data_directory.unwrap();
        if tls_data_directory.virtual_address == 0 && tls_data_directory.size == 0 {
            return Ok(None);
        }

        pe_file.seek(SeekFrom::Start(self.rva_to_file_offset(tls_data_directory.virtual_address)? as u64))?;

        let tls_directory_size = TlsDirectory::get_size(self.is_64bit()?);
        let mut tls_directory_buffer: Vec<u8> = vec![0; tls_directory_size];
        pe_file.read_exact(&mut tls_directory_buffer)?;

        Ok(Some(TlsDirectory::new(&tls_directory_buffer)?))
    }

    fn parse_reloc_section(&self, pe_file: &mut File) -> PyResult<Option<RelocationSection>> {
        let opt_reloc_directory = match self.nt_header.as_ref() {
            Some(image_nt_header) => {
                match image_nt_header {
                    ImageNtHeader::NtHeader32(nt_header32) => nt_header32.optional_header.get_reloc_directory(),
                    ImageNtHeader::NtHeader64(nt_header64) => nt_header64.optional_header.get_reloc_directory(),
                }

            },
            None => {return Err(PyRuntimeError::new_err("Cannot parse the reloc directory without having parsed the NT Headers first"));}
        };

        if opt_reloc_directory.is_none() {
            return Err(PyRuntimeError::new_err("Failed to find the reloc directory in the optional header"));
        }
        let reloc_directory = opt_reloc_directory.unwrap();
        if reloc_directory.virtual_address == 0 && reloc_directory.size == 0 {
            return Ok(None);
        }

        let reloc_directory_fo = self.rva_to_file_offset(reloc_directory.virtual_address)?;
        let mut current_reloc_size: u32 = 0;
        let mut vec_image_base_reloc: Vec<ImageBaseRelocation> = Vec::new();

        loop {
            pe_file.seek(SeekFrom::Start((reloc_directory_fo + current_reloc_size) as u64))?;

            let mut image_base_reloc_buffer: Vec<u8> = vec![0; ImageBaseRelocation::SIZE_IMAGE];

            match pe_file.read_exact(&mut image_base_reloc_buffer) {
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(PyErr::from(err)),
                _ => ()

            }
            let mut image_base_reloc = ImageBaseRelocation::new(&image_base_reloc_buffer)?;

            if image_base_reloc.virtual_address == 0 && image_base_reloc.size_of_block == 0 {
                break;
            }

            let n_entries = (image_base_reloc.size_of_block - (ImageBaseRelocation::SIZE_IMAGE as u32)) / 2;

            for _ in 0..n_entries {
                let mut reloc_entry_buffer: Vec<u8> = vec![0; 2];
                pe_file.read_exact(&mut reloc_entry_buffer)?;

                image_base_reloc.entries.push(RelocEntry{
                    type_reloc: reloc_entry_buffer[0] & 0xF0,
                    offset: u16::from_le_bytes(reloc_entry_buffer[..].try_into()?) & 0x0FFF
                });
            }

            current_reloc_size += image_base_reloc.size_of_block;
            vec_image_base_reloc.push(image_base_reloc);
        }

        Ok(Some(RelocationSection{
            blocks: vec_image_base_reloc
        }))
    }

    fn parse_sections(&mut self, pe_file: &mut File) -> PyResult<()> {
        self.sections = Some(PESections {
            import_section: self.parse_import_section(pe_file)?,
            export_section: self.parse_export_section(pe_file)?,
            tls_directory: self.parse_tls_directory(pe_file)?,
            reloc_section: self.parse_reloc_section(pe_file)?
        });

        Ok(())
    }
}

#[pymethods]
impl PEFile {
    #[new]
    #[pyo3(signature = (path, parse_sections=false))]
    fn new(
        path: PathBuf,
        parse_sections: bool,
    ) -> PyResult<Self> {

        if ! path.is_file() {
            return Err(PyFileNotFoundError::new_err("The given path doesn't correspond to a file"));
        }
        let mut pe = PEFile{
            path,
            dos_header: None,
            nt_header: None,
            section_headers: None,
            sections: None
        };

        let res_open = File::open(&pe.path);

        if let Err(err) = res_open {
            return py_unknown_error!(err, "An unknown error occurred while trying to open the PE file");
        }

        let mut pe_file = res_open.unwrap();

        if let Err(err) =  pe.parse_dos_header(&mut pe_file){
            return py_unknown_error!(err, "An unknown error occurred while trying to parse the DOS Header");
        }
        if let Err(err) = pe.parse_nt_header(&mut pe_file){
            return py_unknown_error!(err, "An unknown error occurred while trying to parse the NT Headers");
        }
        if let Err(err) = pe.parse_section_headers(&mut pe_file){
            return py_unknown_error!(err, "An unknown error occurred while trying to parse the Section Headers");
        }

        if parse_sections {
            if let Err(err) = pe.parse_sections(&mut pe_file){
                return py_unknown_error!(err, "An unknown error occurred while trying to parse the Sections");
            }
        }

        return Ok(pe);
    }

    #[getter]
    fn nt_header(&self, py: Python) -> PyResult<PyObject> {
        match self.nt_header.as_ref() {
            None => Err(PyRuntimeError::new_err("An unknown error occurred while trying to retrieve the nt headers")),
            Some(image) => {
                match image {
                    ImageNtHeader::NtHeader32(image_nt_header_32) => {
                        Ok(image_nt_header_32.clone().into_py(py))
                    },
                    ImageNtHeader::NtHeader64(image_nt_header_64) => {
                        Ok(image_nt_header_64.clone().into_py(py))
                    }
                }
            }
        }
    }

    fn is_64bit(&self) -> PyResult<bool> {
        match self.nt_header.as_ref() {
            None => Ok(false),
            Some(image) => {
                match image {
                    ImageNtHeader::NtHeader32(_) => {
                        Ok(false)
                    },
                    ImageNtHeader::NtHeader64(_) => {
                        Ok(true)
                    }
                }
            }
        }
    }

    fn is_32bit(&self) -> PyResult<bool> {
        match self.nt_header.as_ref() {
            None => Ok(false),
            Some(image) => {
                match image {
                    ImageNtHeader::NtHeader32(_) => {
                        Ok(true)
                    },
                    ImageNtHeader::NtHeader64(_) => {
                        Ok(false)
                    }
                }
            }
        }
    }

    fn rva_to_file_offset(&self, rva: u32) -> PyResult<u32> {
        let section_headers = match self.section_headers.as_ref() {
            None => {return Err(PyRuntimeError::new_err("Section headers must have been parsed to convert a rva into a file offset"));},
            Some(section_headers) => section_headers
        };

        for s in section_headers {
            let mut is_target_section = s.virtual_address <= rva && rva < (s.virtual_address + s.virtual_size);
            is_target_section |= s.virtual_size == 0 && s.virtual_address == rva;

            if is_target_section {
                return Ok(rva - s.virtual_address + s.pointer_to_raw_data);
            }
        }

        Err(PyRuntimeError::new_err(format!("Failed to convert {rva} to a file offset")))
    }

    fn file_offset_to_rva(&self, fo: u32) -> PyResult<u32> {
        let section_headers = match self.section_headers.as_ref() {
            None => {return Err(PyRuntimeError::new_err("Section headers must have been parsed to convert a file offset into a rva"));},
            Some(section_headers) => section_headers
        };

        for s in section_headers {
            let mut is_target_section = s.pointer_to_raw_data <= fo && fo < (s.pointer_to_raw_data + s.size_of_raw_data);
            is_target_section |= s.size_of_raw_data == 0 && s.pointer_to_raw_data == fo;

            if is_target_section {
                return Ok(fo - s.pointer_to_raw_data + s.virtual_address);
            }
        }

        Err(PyRuntimeError::new_err(format!("Failed to convert {fo} to a rva")))
    }

}


/// Module containing the PEFile class which can be used to parse PE files
#[pymodule]
fn peru(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PEFile>()?;
    m.add("InvalidPEFile", py.get_type::<InvalidPEFile>())?;

    register_headers_and_sections_modules(py, m)?;
    Ok(())
}


fn register_headers_and_sections_modules(py: Python<'_>, root_module: &PyModule) -> PyResult<()> {
    let headers_module = PyModule::new(py, "headers")?;
    let sections_module = PyModule::new(py, "sections")?;

    headers_module.add_class::<ImageDosHeader>()?;
    headers_module.add_class::<ImageDataDirectory>()?;
    headers_module.add_class::<ImageFileHeader>()?;
    headers_module.add_class::<ImageOptionalHeader64>()?;
    headers_module.add_class::<ImageOptionalHeader32>()?;
    headers_module.add_class::<ImageNtHeader64>()?;
    headers_module.add_class::<ImageNtHeader32>()?;
    headers_module.add_class::<ImageSectionHeader>()?;

    sections_module.add_class::<ImageImportByName>()?;
    sections_module.add_class::<ImageThunkData>()?;
    sections_module.add_class::<ImageImportDescriptor>()?;
    sections_module.add_class::<ImportSectionEntry>()?;
    sections_module.add_class::<ImportSection>()?;
    sections_module.add_class::<ExportSectionEntry>()?;
    sections_module.add_class::<ExportDirectoryTable>()?;
    sections_module.add_class::<ExportSection>()?;
    sections_module.add_class::<TlsDirectory>()?;
    sections_module.add_class::<RelocEntry>()?;
    sections_module.add_class::<ImageBaseRelocation>()?;
    sections_module.add_class::<RelocationSection>()?;
    sections_module.add_class::<PESections>()?;

    root_module.add_submodule(headers_module)?;
    root_module.add_submodule(sections_module)?;
    Ok(())
}
