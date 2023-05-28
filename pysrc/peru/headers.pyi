import typing


class ImageDosHeader:
    """
    Class representing the DOS Header of a PE file
    """
    def __init__(self, buffer: bytes) -> None:
        """
        Initialization of a **DosHeader** object

        :param buffer: 64 bytes corresponding to the DOS Header of a PE file
        """

    @property
    def e_magic(self) -> int:
        """
        Magic number (Should always be equal to 23117 / 0x5a4d)
        """

    @property
    def e_cblp(self) -> int:
        """
        An integer/WORD specifying the number of bytes used in the last page
        """

    @property
    def e_cp(self) -> int:
        """
        An integer/WORD specifying the number of pages required to hold the file
        """

    @property
    def e_crlc(self) -> int:
        """
        An integer/WORD specifying the number of relocation items
        """

    @property
    def e_cparhdr(self) -> int:
        """
        An integer/WORD specifying the size of the executable header in terms of paragraphs (16 byte chunks)
        """

    @property
    def e_minalloc(self) -> int:
        """
        An integer/WORD specifying the minimum number of extra paragraphs needed to be allocated to begin execution
        """

    @property
    def e_maxalloc(self) -> int:
        """
        An integer/WORD specifying the maximum number of extra paragraphs needed to be allocated by the program before it begins execution
        """

    @property
    def e_ss(self) -> int:
        """
        An integer/WORD specifying the initial SS value, which is the paragraph address of the stack segment relative to the start of the load module
        """

    @property
    def e_sp(self) -> int:
        """
        An integer/WORD specifying the initial SP value, which is the absolute value that must be loaded into the SP register before the program is given control.
        """

    @property
    def e_csum(self) -> int:
        """
        An integer/WORD specifying the checksum of the contents of the executable file.
        """

    @property
    def e_ip(self) -> int:
        """
        An integer/WORD specifying the initial IP value, which is the absolute value that should be loaded into the IP register in order to transfer control to the program.
        """

    @property
    def e_cs(self) -> int:
        """
        An integer/WORD the pre-relocated initial CS value, relative to the start of the load module, that should be placed in the CS register in order to transfer control to the program
        """

    @property
    def e_lfarlc(self) -> int:
        """
        An integer/WORD specifying the file address of the relocation table, or more specifically, the offset from the start of the file to the relocation pointer table.
        """

    @property
    def e_ovno(self) -> int:
        """
        An integer/WORD specifying the overlay number
        """

    @property
    def e_res(self) -> typing.List[int]:
        """
        4 reserved WORDs (= integers) for the program
        """

    @property
    def e_oemid(self) -> int:
        """
        An integer/WORD specifying the identifier for the OEM for e_oeminfo
        """

    @property
    def e_oeminfo(self) -> int:
        """
        An integer/WORD specifying the OEM information for a specific value of e_oeminfo
        """

    @property
    def e_res2(self) -> typing.List[int]:
        """
        10 reserved WORDs (= integers) for the program
        """

    @property
    def e_lfanew(self) -> int:
        """
        4 bytes specifying the file address of the new exe header
        """


class ImageFileHeader:
    """
    Class representing the File Header of a PE file
    """
    def __init__(self, buffer: bytes) -> None:
        """
        Initialization of a **FileHeader** object

        :param buffer: 20 bytes corresponding to the File Header of a PE file
        """

    @property
    def machine(self) -> int:
        """
        An integer/WORD specifying the type of machine the current PE file is targeting
        """

    @property
    def number_of_sections(self) -> int:
        """
        An integer/WORD specifying the number of section headers
        """

    @property
    def time_date_stamp(self) -> int:
        """
        An integer/DWORD specifying when the current PE file was created
        """

    @property
    def pointer_to_symbol_table(self) -> int:
        """
        An integer/DWORD indicating the offset to the COFF symbol table
        """

    @property
    def number_of_symbols(self) -> int:
        """
        An integer/DWORD indicating the number of entries in the COFF symbol table
        """

    @property
    def size_of_optional_header(self) -> int:
        """
        An integer/WORD specifying the number of bytes used for the Optional Header
        """

    @property
    def characteristics(self) -> int:
        """
        An integer/WORD specifying the attributes of the current PE file
        """


class ImageDataDirectory:
    """
    Class representing a single entry in the *data_directory* field of the ImageOptionalHeader64 & ImageOptionalHeader32
    classes
    """
    def __init__(self, buffer: bytes) -> None:
        """
        Initialization of a **ImageDataDirectory** object

        :param buffer: 8 bytes corresponding to the content of a single data directory
        """

    @property
    def virtual_address(self) -> int:
        """
        An integer/DWORD specifying the RVA of the table associated with the current data directory
        """

    @property
    def size(self) -> int:
        """
        An integer/DWORD specifying the size of the table associated with the current data directory
        """


class _ImageOptionalHeader:
    """
    Class defining the methods common to **ImageOptionalHeader64** and **ImageOptionalHeader32**
    """

    def resolve_characteristics(self) -> typing.List[str]:
        """
        Method extracting the characteristics from the *dll_characteristics* field
        """


    def resolve_data_directories(self) -> typing.List[str]:
        """
        Method returning the names of the data directories present in the PE file
        """


class ImageOptionalHeader64(_ImageOptionalHeader):
    """
    Class representing the Optional Header of a 64-bit PE file
    """
    def __init__(self, buffer: bytes) -> None:
        """
        Initialization of a **ImageOptionalHeader64** object

        :param buffer: 240 bytes corresponding to the Optional Header of a 64-bit PE file
        """

    @property
    def magic(self) -> int:
        """
        An integer/WORD specifying the state of the image file
        """

    @property
    def major_linker_version(self) -> int:
        """
        An integer/byte specifying the linker major version number
        """

    @property
    def minor_linker_version(self) -> int:
        """
        An integer/byte specifying the linker minor version number
        """

    @property
    def size_of_code(self) -> int:
        """
        An integer/DWORD specifying the size of the code (text) section
        """

    @property
    def size_of_initialized_data(self) -> int:
        """
        An integer/DWORD specifying the size of the initialized data section
        """

    @property
    def size_of_uninitialized_data(self) -> int:
        """
        An integer/DWORD specifying the size of the uninitialized data section (BSS)
        """

    @property
    def address_of_entry_point(self) -> int:
        """
        An integer/DWORD specifying the address of the entry point relative to the image base
        when the executable file is loaded into memory
        """

    @property
    def base_of_code(self) -> int:
        """
        An integer/DWORD specifying the address that is relative to the image base of the beginning-of-code section
        when it is loaded into memory
        """

    @property
    def image_base(self) -> int:
        """
        An integer/QWORD specifying the preferred address of the first byte of the current image when loaded into memory
        """

    @property
    def section_alignment(self) -> int:
        """
        An integer/DWORD specifying the alignment (in bytes) of sections when they are loaded into memory
        """

    @property
    def file_alignment(self) -> int:
        """
        An integer/DWORD specifying the alignment factor (in bytes) that is used to align
        the raw data of sections in the image file
        """

    @property
    def major_operating_system_version(self) -> int:
        """
        An integer/WORD specifying the major version number of the required operating system
        """

    @property
    def minor_operating_system_version(self) -> int:
        """
        An integer/WORD specifying the minor version number of the required operating system
        """

    @property
    def major_image_version(self) -> int:
        """
        An integer/WORD specifying the major version number of the image
        """

    @property
    def minor_image_version(self) -> int:
        """
        An integer/WORD specifying the minor version number of the image
        """

    @property
    def major_subsystem_version(self) -> int:
        """
        An integer/WORD specifying the major version number of the subsystem
        """

    @property
    def minor_subsystem_version(self) -> int:
        """
        An integer/WORD specifying the minor version number of the subsystem
        """

    @property
    def win32_version_value(self) -> int:
        """
        A reserved integer/DWORD always equal to 0
        """

    @property
    def size_of_image(self) -> int:
        """
        An integer/DWORD specifying the size (in bytes) of the image, including all headers,
        as the image is loaded in memory
        """

    @property
    def size_of_headers(self) -> int:
        """
        An integer/DWORD specifying the combined size of an MS-DOS stub, PE header, and section headers
        rounded up to a multiple of FileAlignment
        """

    @property
    def checksum(self) -> int:
        """
        An integer/DWORD specifying the image file checksum
        """

    @property
    def subsystem(self) -> int:
        """
        An integer/WORD specifying the subsystem that is required to run this image
        """

    @property
    def dll_characteristics(self) -> int:
        """
        An integer/WORD specifying the characteristics of the current PE file
        """

    @property
    def size_of_stack_reserve(self) -> int:
        """
        An integer/QWORD specifying the size of the stack to reserve
        """

    @property
    def size_of_stack_commit(self) -> int:
        """
        An integer/QWORD specifying the size of the stack to commit
        """

    @property
    def size_of_heap_reserve(self) -> int:
        """
        An integer/QWORD specifying the size of the local heap space to reserve
        """

    @property
    def size_of_heap_commit(self) -> int:
        """
        An integer/QWORD specifying the size of the local heap space to commit
        """

    @property
    def loader_flags(self) -> int:
        """
        A reserved integer/DWORD always equal to 0
        """

    @property
    def number_of_rva_and_sizes(self) -> int:
        """
        An integer/DWORD specifying the number of data-directory entries in the remainder of the optional header
        """

    @property
    def data_directory(self) -> typing.List[ImageDataDirectory]:
        """
        A list of **ImageDataDirectory** objects corresponding to either a table or a string in the current PE file
        """

class ImageOptionalHeader32(_ImageOptionalHeader):
    """
    Class representing the Optional Header of a 32-bit PE file
    """
    def __init__(self, buffer: bytes) -> None:
        """
        Initialization of a **ImageOptionalHeader32** object

        :param buffer: 224 bytes corresponding to the Optional Header of a 32-bit PE file
        """

    @property
    def magic(self) -> int:
        """
        An integer/WORD specifying the state of the image file
        """

    @property
    def major_linker_version(self) -> int:
        """
        An integer/byte specifying the linker major version number
        """

    @property
    def minor_linker_version(self) -> int:
        """
        An integer/byte specifying the linker minor version number
        """

    @property
    def size_of_code(self) -> int:
        """
        An integer/DWORD specifying the size of the code (text) section
        """

    @property
    def size_of_initialized_data(self) -> int:
        """
        An integer/DWORD specifying the size of the initialized data section
        """

    @property
    def size_of_uninitialized_data(self) -> int:
        """
        An integer/DWORD specifying the size of the uninitialized data section (BSS)
        """

    @property
    def address_of_entry_point(self) -> int:
        """
        An integer/DWORD specifying the address of the entry point relative to the image base
        when the executable file is loaded into memory
        """

    @property
    def base_of_code(self) -> int:
        """
        An integer/DWORD specifying the address that is relative to the image base of the beginning-of-code section
        when it is loaded into memory
        """

    @property
    def base_of_data(self) -> int:
        """
        An integer/DWORD specifying the address that is relative to the image base of the beginning-of-data section
        when it is loaded into memory
        """

    @property
    def image_base(self) -> int:
        """
        An integer/DWORD specifying the preferred address of the first byte of the current image when loaded into memory
        """

    @property
    def section_alignment(self) -> int:
        """
        An integer/DWORD specifying the alignment (in bytes) of sections when they are loaded into memory
        """

    @property
    def file_alignment(self) -> int:
        """
        An integer/DWORD specifying the alignment factor (in bytes) that is used to align
        the raw data of sections in the image file
        """

    @property
    def major_operating_system_version(self) -> int:
        """
        An integer/WORD specifying the major version number of the required operating system
        """

    @property
    def minor_operating_system_version(self) -> int:
        """
        An integer/WORD specifying the minor version number of the required operating system
        """

    @property
    def major_image_version(self) -> int:
        """
        An integer/WORD specifying the major version number of the image
        """

    @property
    def minor_image_version(self) -> int:
        """
        An integer/WORD specifying the minor version number of the image
        """

    @property
    def major_subsystem_version(self) -> int:
        """
        An integer/WORD specifying the major version number of the subsystem
        """

    @property
    def minor_subsystem_version(self) -> int:
        """
        An integer/WORD specifying the minor version number of the subsystem
        """

    @property
    def win32_version_value(self) -> int:
        """
        A reserved integer/DWORD always equal to 0
        """

    @property
    def size_of_image(self) -> int:
        """
        An integer/DWORD specifying the size (in bytes) of the image, including all headers,
        as the image is loaded in memory
        """

    @property
    def size_of_headers(self) -> int:
        """
        An integer/DWORD specifying the combined size of an MS-DOS stub, PE header, and section headers
        rounded up to a multiple of FileAlignment
        """

    @property
    def checksum(self) -> int:
        """
        An integer/DWORD specifying the image file checksum
        """

    @property
    def subsystem(self) -> int:
        """
        An integer/WORD specifying the subsystem that is required to run this image
        """

    @property
    def dll_characteristics(self) -> int:
        """
        An integer/WORD specifying the characteristics of the current PE file
        """

    @property
    def size_of_stack_reserve(self) -> int:
        """
        An integer/DWORD specifying the size of the stack to reserve
        """

    @property
    def size_of_stack_commit(self) -> int:
        """
        An integer/DWORD specifying the size of the stack to commit
        """

    @property
    def size_of_heap_reserve(self) -> int:
        """
        An integer/DWORD specifying the size of the local heap space to reserve
        """

    @property
    def size_of_heap_commit(self) -> int:
        """
        An integer/DWORD specifying the size of the local heap space to commit
        """

    @property
    def loader_flags(self) -> int:
        """
        A reserved integer/DWORD always equal to 0
        """

    @property
    def number_of_rva_and_sizes(self) -> int:
        """
        An integer/DWORD specifying the number of data-directory entries in the remainder of the optional header
        """

    @property
    def data_directory(self) -> typing.List[ImageDataDirectory]:
        """
        A list of **ImageDataDirectory** objects corresponding to either a table or a string in the current PE file
        """


class ImageNtHeader:
    """
    Class representing the NT Headers of a PE file
    """

    def __init__(self, buffer: bytes) -> None:
        """
        Initialization of a **ImageNtHeader** object

        :param buffer: 264 bytes or 248 corresponding to the NT Headers of a PE file
        """

    @property
    def signature(self) -> int:
        """
        Signature of the PE file (Should always be equal to 17744 / 0x00004550)
        """

    @property
    def file_header(self) -> ImageFileHeader:
        """
        File Header of the PE file
        """

    @property
    def optional_header(self) -> typing.Union[ImageOptionalHeader32, ImageOptionalHeader64]:
        """
        Optional header of the PE file
        """


class ImageSectionHeader:
    """
    Class representing a single Section Header of a PE file
    """

    def __init__(self, buffer: bytes) -> None:
        """
        Initialization of a **ImageSectionHeader** object

        :param buffer: 40 bytes corresponding to a Section Header of a PE file
        """

    @property
    def name(self) -> str:
        """
        Name of the section
        """

    @property
    def virtual_size(self) -> int:
        """
        An integer/DWORD specifying the total size of the section when loaded into memory
        """

    @property
    def virtual_address(self) -> int:
        """
        An integer/DWORD corresponding the RVA of the first byte of the section
        """

    @property
    def size_of_raw_data(self) -> int:
        """
        An integer/DWORD specifying the size of the section
        """

    @property
    def pointer_to_raw_data(self) -> int:
        """
        An integer/DWORD specifying the file pointer to the first page of the section
        """

    @property
    def pointer_to_relocations(self) -> int:
        """
        An integer/DWORD specifying the file pointer to the beginning of relocation entries for the section
        """

    @property
    def pointer_to_line_numbers(self) -> int:
        """
        An integer/DWORD specifying the file pointer to the beginning of line-number entries for the section
        """

    @property
    def number_of_relocations(self) -> int:
        """
        An integer/WORD specifying the number of relocation entries for the section
        """

    @property
    def number_of_line_numbers(self) -> int:
        """
        An integer/WORD specifying the number of line-number entries for the section
        """

    @property
    def characteristics(self) -> int:
        """
        An integer/DWORD containing the flags that describe the characteristics of the section
        """

    def resolve_characteristics(self) -> typing.List[str]:
        """
        Method extracting the characteristics of the section from the *characteristics* field
        """
