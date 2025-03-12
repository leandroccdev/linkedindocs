from os.path import exists
from tqdm import tqdm
from typing import Dict, Optional, NoReturn, Union
import json
import logging
from requests import Session

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"

# Setup logger
logger = logging.getLogger(__name__)

class Linkedin:
    WEB_URL = "https://www.linkedin.com/feed/update/urn:li:ugcPost:{}/"


class DocumentDownloader:
    CHUNK_BUFFER = 8192

    def __init__(self, document_id: int) -> None:
        '''Allows to download a PDF document from own public feed.

        Args:
            document_id (int): document id.
        '''
        global logger
        self._log: logging.Logger = logger.getChild(self.__class__.__name__)
        self._document_id: int = document_id
        # Stores document url to retrieve json ld data.
        self._document_url: str = ""
        # Stores document manifest url (contains document url).
        self._manifest_url: str = ""

    def __http_get(self, s: Session, url: str) -> Optional[Union[str, NoReturn]]:
        '''Query a web resource and retrieve it contents as string.

        Args:
            s (requests.Session): HTTP Session.
            url (str): Url to be requested.

        Exceptions:
            Document.DownloadError

        Returns:
            The content of requested web resource.
        '''
        self._log.debug(f"Requesting: {url}")
        with s.get(url) as req:
            # Http error
            if req.status_code != 200:
                err: str = f"HTTP Code: {req.status_code}"
                self._log.error(err)
                self._log.error(f"Body: " + req.text)
                raise Document.DownloadError(err)

            return req.text

    def __download_file(self, output_file: str, s: Session) -> Optional[NoReturn]:
        '''Downloads url and saves into output_file.

        Args:
            output_file (str): File path to save downloaded file.
            s (requests.Session): HTTP Session.

        Exceptions:
            Document.DownloadError
            Document.FileExistsError
        '''
        if not self._document_url:
            err: str = "The document url is not set!"
            self._log.error(err)
            raise Document.DownloadError(err)

        if exists(output_file):
            err: str = f"File '{output_file}' already exists!"
            self._log.error(err)
            raise Document.FileExistsError(err)

        # Download with progress bar
        self._log.debug(f"Downloading: {self._document_url}")
        with s.get(self._document_url, stream=True) as req:
            download_size: int = int(req.headers.get("content-length", 0))
            req.raise_for_status()
            with tqdm(
                    total=download_size,
                    unit="B",
                    unit_scale=True
                ) as pb, \
                    open(output_file, 'wb') as f:
                pb.write(f"Downloading: {output_file}...")
                for chunk in req.iter_content(chunk_size=Document.CHUNK_BUFFER):
                    pb.update(len(chunk))
                    f.write(chunk)
        self._log.debug("Download finished!")

    def __load_json_ld(self, s: Session) -> Optional[NoReturn]:
        '''Loads json ld from document url.

        Args:
            s (requests.Session): HTTP Session.

        Exceptions:
            Document.DownloadError
        '''
        json_ld_tag: str = '<script type="application/ld+json">'

        self._log.debug("Retrieving json-ld data...")
        url: str = Linkedin.WEB_URL.format(self._document_id)
        content: str = self.__http_get(s, url) # type: ignore

        # json-ld tag not found
        if json_ld_tag not in content:
            err: str = f"json-ld tag not found!"
            self._log.error(err)
            raise Document.DownloadError(err)

        # Extract json-ld data
        self._log.debug("Extracting json-ld data...")
        ld_data: str = content.split(json_ld_tag)[1] \
                .split("</script>")[0] \
                .strip()
        self._log.debug(f"json-ld data: '{ld_data}'")

        # Try to decode data from json-ld
        try:
            data: Dict = json.loads(ld_data)
        except json.decoder.JSONDecodeError as e:
            self._log.error(e)
            raise Document.DownloadError(e)

        # sharedContent not found
        if "sharedContent" not in data:
            err: str = "Key 'sharedContent' not found at json-ld data!"
            self._log.error(err)
            raise Document.DownloadError(err)

        # Document manifest url found
        self._manifest_url = data["sharedContent"]["url"]
        print(self._manifest_url)

    def __load_manifest(self, s: Session) -> Optional[NoReturn]:
        '''Loads document manifest.

        Args:
            s (requests.Session): HTTP Session.

        Exceptions:
            Document.DownloadError
        '''
        if not self._manifest_url:
            raise Document.DownloadError("The manifest url is not set!")

        self._log.debug("Retrieving manifest...")
        content: str = self.__http_get(s, self._manifest_url) # type: ignore

        # Try to decode manifest
        try:
            manifest: Dict = json.loads(content)
        except json.decoder.JSONDecodeError as e:
            self._log.error(e)
            raise Document.DownloadError(e)

        # Document url not found at manifest
        if "transcribedDocumentUrl" not in manifest:
            err: str = "Key 'transcribedDocumentUrl' not found at manifest!"
            self._log.error(err)
            raise Document.DownloadError(err)

        self._document_url = manifest["transcribedDocumentUrl"]
        self._log.debug("Document url set")

    def download(self, output_file: str) -> Optional[NoReturn]:
        '''Downloads PDF document from linkedin user's public feed.

        Args:
            output_file (str): File path to save downloaded file.

        Exceptions:
            Document.DownloadError
            Document.FileExistsError
        '''
        global USER_AGENT

        if exists(output_file):
            err: str = f"File '{output_file}' already exists!"
            self._log.error(err)
            raise Document.FileExistsError(err)

        self._log.debug("Creating session...")
        s: Session = Session()
        s.headers = {
                "User-Agent": USER_AGENT
            }
        self.__load_json_ld(s)
        self.__load_manifest(s)
        self.__download_file(output_file, s)

    class DownloadError(Exception): ...


    class FileExistsError(Exception): ...

