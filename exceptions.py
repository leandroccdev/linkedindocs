class CookieNotFound(Exception):
    def __init__(self, name: str):
        err: str = f"Cookie '{name}' not found!"
        super().__init__(err)


class DownloadError(Exception): ...


class EmptyFileError(Exception):
    def __init__(self, file_path: str) -> None:
        err: str = f"File '{file_path}' is empty!"
        super().__init__(err)


class FileExistsError(Exception):
    def __init__(self, output_file: str) -> None:
        err: str = f"File '{output_file}' already exists!"
        super().__init__(err)


class FileNotFoundError(Exception):
    def __init__(self, file_path: str) -> None:
        err: str = f"File '{file_path}' not found!"
        super().__init__(err)


class InvalidFileError(Exception): ...


class MaxFileSizeError(Exception):
    def __init__(self, file_path: str, max_size: int) -> None:
        err: str = f"File '{file_path}' size exceeds maximum of {max_size} bytes!"
        super().__init__(err)

class UploadError(Exception): ...