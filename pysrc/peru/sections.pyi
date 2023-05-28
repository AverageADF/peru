import typing



class ImageImportByName:
    """
    Class which might be used by **ImageThunkData** to describe an imported API
    """
    @property
    def hint(self) -> int:
        """
        An integer/WORD corresponding to a "hint" to the loader as to what the ordinal of the imported API might be
        """

    @property
    def name(self) -> str:
        """
        Name of the imported API
        """


class ImageThunkData:
    """
    Class containing the data of a single imported API in the .idata section
    """
    @property
    def ordinal_flag(self) -> int:
        """
        Flag (either 1 or 0) indicating whether the current object contains an **ImageImportByName** object or not
        """

    @property
    def ordinal(self) -> int:
        """
        An integer (either DWORD or QWORD) specifying the ordinal of the imported API
        """

    @property
    def address_of_data(self) -> int:
        """
        An integer (either DWORD or QWORD) corresponding to the RVA of the associated **ImageImportByName** object
        """

    @property
    def import_by_name(self) -> typing.Optional[ImageImportByName]:
        """
        A **ImageImportByName** object containing the name of the imported API
        """


class ImageImportDescriptor:
    """
    Class containing information about the imported DLL
    """
    @property
    def original_first_thunk(self) -> int:
        """
        An integer/DWORD corresponding to the RVA of the first **ImageThunkData** object
        """

    @property
    def time_date_stamp(self) -> int:
        ...

    @property
    def forwarder_chain(self) -> int:
        """
        An integer/DWORD corresponding the index of the first forwarder chain reference
        """

    @property
    def name_rva(self) -> int:
        """
        An integer/DWORD corresponding the RVA of the DLL name
        """

    @property
    def first_thunk(self) -> int:
        """
        An integer/DWORD corresponding the RVA of the IAT
        """


class ImportSectionEntry:
    """
    Class representing a single imported DLL
    """
    @property
    def name(self) -> str:
        """
        Name of the imported DLL
        """

    @property
    def descriptor(self) -> ImageImportDescriptor:
        """
        A **ImageImportDescriptor** containing additional information about the imported DLL
        """

    @property
    def thunk_data(self) -> typing.List[ImageThunkData]:
        """
        A list of **ImageThunkData** objects corresponding to the imported APIs
        """


class ImportSection:
    """
    Class containing information about the *.idata* section
    """
    @property
    def entries(self) -> typing.List[ImportSectionEntry]:
        """
        A list of **ImportSectionEntry** objects corresponding to the imported DLL
        """


class ExportSectionEntry:
    """
    Class representing a single exported API
    """
    @property
    def name(self) -> str:
        """
        Name of the exported API
        """

    @property
    def rva(self) -> int:
        """
        An integer/DWORD corresponding to the RVA of the exported API
        """

    @property
    def ordinal(self) -> int:
        """
        An integer/WORD specifying the unbiased ordinal associated with the current exported API
        """

    @property
    def forwarded(self) -> bool:
        """
        A boolean indicating whether the current exported API comes from another DLL
        """


class ExportDirectoryTable:
    """
    Class representing the Export Directory Table of a PE file
    """
    @property
    def export_flags(self) -> int:
        """
        A reserved integer/DWORD which must be equal to 0
        """

    @property
    def time_date_stamp(self) -> int:
        """
        An integer/DWORD specifying when the export data was created.
        """

    @property
    def major_version(self) -> int:
        """
        An integer/DWORD specifying the major version number
        """

    @property
    def minor_version(self) -> int:
        """
        An integer/DWORD specifying the minot version number
        """

    @property
    def name_rva(self) -> int:
        """
        An integer/DWORD corresponding to the RVA of the name of the DLL
        """

    @property
    def ordinal_base(self) -> int:
        """
        An integer/DWORD specifying the starting ordinal number for exports in this image
        """

    @property
    def address_table_entries(self) -> int:
        """
        An integer/DWORD specifying the number of entries in the export address table
        """

    @property
    def number_name_pointers(self) -> int:
        """
        An integer/DWORD specifying the number of entries in the name pointer table as well as t
        the number of entries in the ordinal table
        """

    @property
    def export_address_table(self) -> int:
        """
        An integer/DWORD corresponding to the RVA of the export address table
        """

    @property
    def name_pointer(self) -> int:
        """
        An integer/DWORD corresponding to the RVA of the export name pointer table
        """

    @property
    def ordinal_table(self) -> int:
        """
        An integer/DWORD corresponding to the RVA of the address of the ordinal table
        """


class ExportSection:
    """
    Class containing information about the *.edata* section
    """
    @property
    def name(self) -> str:
        """
        Name of the corresponding DLL
        """

    @property
    def directory_table(self) -> ExportDirectoryTable:
        """
        Data contained in the Export Directory Table
        """

    @property
    def entries(self) -> typing.List[ExportSectionEntry]:
        """
        A list of **ExportSectionEntry** objects for each exported API
        """


class TlsDirectory:
    """
    Class corresponding to the TLS directory that can be found in some PE
    """
    @property
    def start_address_of_raw_data(self) -> int:
        """
        An integer specifying the starting virtual address of the TLS template
        """

    @property
    def end_address_of_raw_data(self) -> int:
        """
        An integer specifying the virtual address of the last byte of the TLS, except for the zero fill.
        """

    @property
    def address_of_index(self) -> int:
        """
        An integer specifying the location to receive the TLS index, which the loader assigns.
        """

    @property
    def address_of_callbacks(self) -> int:
        """
        An integer specifying the virtual address of an array of TLS callback functions
        """

    @property
    def size_of_zero_fill(self) -> int:
        """
        An integer/DWORD specifying the size in bytes of the template
        """

    @property
    def characteristics(self) -> int:
        """
        An integer/DWORD corresponding to the characteristics of the current TLS directory
        """


class RelocEntry:
    """
    Class corresponding to a single relocation in a base relocation block
    """
    @property
    def type_reloc(self) -> int:
        """
        An integer specifying the type of base relocation to be applied
        """

    @property
    def offset(self) -> int:
        """
        An integer specifying where the base relocation is to be applied
        """


class ImageBaseRelocation:
    """
    Class containing data that describes a single base relocation block
    """
    @property
    def virtual_address(self) -> int:
        """
        An integer/DWORD corresponding to the RVA of the base relocation block
        """

    @property
    def size_of_block(self) -> int:
        """
        An integer/DWORD specifying the size of the base relocation block
        """

    @property
    def entries(self) -> typing.List[RelocEntry]:
        """
        The relocation entries that can be found within the current base relocation block
        """


class RelocationSection:
    """
    Class containing information about the *.reloc* section
    """
    @property
    def blocks(self) -> typing.List[ImageBaseRelocation]:
        """
        List of **ImageBaseRelocation** objects for each base relocation block in the PE file
        """

class PESections:
    """
    Class containing the information of the different sections of a PE file
    """
    @property
    def import_section(self) -> ImportSection:
        """
        Data related to the .idata section
        """

    @property
    def export_section(self) -> ExportSection:
        """
        Data related to the .edata section
        """

    @property
    def tls_directory(self) -> TlsDirectory:
        """
        Data related to the TLS directory
        """

    @property
    def reloc_section(self) -> RelocationSection:
        """
        Data related to the .reloc section
        """
