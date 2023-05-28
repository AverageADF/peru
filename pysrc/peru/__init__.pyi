import typing
from . import headers, sections


class InvalidPEFile(Exception):
    """
    Exception raised when trying to parse a file which is not a valid PE file
    """


class PEFile:
    """
    Class in charge of parsing a PE file
    """
    def __init__(self,
                 path: str,
                 parse_sections: bool = False
                 ) -> None:
        """
        Initialization of a **PEFile** object

        :param path: Path of the PE file which must be parsed. Note that the "headers" of the file
            (i.e, the DOS Header, the DOS STUB, the NT Headers, the Data Directories and the Section Headers) will be
            automatically parsed during the initialization of the current object
        :param parse_sections: Whether to parse the sections of the file (.idata, .edata ...) or not.
        """

    @property
    def path(self) -> str:
        """
        Path of the PE file
        """

    @property
    def dos_header(self) -> headers.ImageDosHeader:
        """
        DOS header of the PE file
        """

    @property
    def nt_header(self) -> headers.ImageNtHeader:
        """
        NT headers of the PE file
        """

    @property
    def section_headers(self) -> typing.List[headers.ImageSectionHeader]:
        """
        Section headers of the PE file
        """

    @property
    def sections(self) -> typing.Optional[sections.PESections]:
        """
        Data of the different sections
        """

    def is_64bit(self) -> bool:
        """
        Indicates whether the current object corresponds to a 64-bit PE file or not
        """

    def is_32bit(self) -> bytes:
        """
        Indicates whether the current object corresponds to a 32-bit PE file or not
        """

    def rva_to_file_offset(self, rva: int) -> int:
        """
        Converts a file offset into a rva
        """

    def file_offset_to_rva(self, fo: int) -> int:
        """
        Converts a rva into a file offset
        """
