from .exceptions import *
from io import BytesIO
from typing import List
from os.path import basename, exists
from os import stat
from requests import Session
from time import sleep
from tqdm import tqdm
from tqdm.utils import CallbackIOWrapper
from typing import Dict, NoReturn, Optional, Union
import json
import logging

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"

# Setup logger
logger = logging.getLogger(__name__)


class Linkedin:
    '''Groups common urls.

    Attributes:
        BASE (str): Base url
        FEED (str): Linkedin feed url.
        POST (str): Linkedin post url.
        VOYAGER_API (str): Url to Linkedin voyager api.
    '''
    BASE = "https://www.linkedin.com"
    FEED = "https://www.linkedin.com/feed/"
    POST = "https://www.linkedin.com/posts/{}"
    VOYAGER_API = "https://www.linkedin.com/voyager/api/"


class ContentVisibility:
    '''Groups content cretion visibility.
    
    Attributes;
        ANYONE: Anyone can view the publication (Non logged-in users included).
        CONNECTIONS_ONLY: Only contacts can view the publication.
    '''
    ANYONE = "ANYONE"
    CONNECTIONS_ONLY = "CONNECTIONS_ONLY"

    @staticmethod
    def is_valid(visibility: str) -> bool:
        '''Check if given string visibility is valid one.'''
        return visibility in [
            ContentVisibility.ANYONE,
            ContentVisibility.CONNECTIONS_ONLY
        ]


class Cookie:
    '''Represents a HTTP Cookie.'''

    def __init__(self, name: str, value: str) -> None:
        '''Initialize the instance.

        Args:
            name (str): Cookie name.
            value (str): Cookie value.
        '''
        self._name: str = name
        self._value: str = value

    def __hash__(self) -> int:
        return hash(str(self))

    def __str__(self) -> str:
        return "name: {}; value: {}; expirationDate={}".format(
                self._name, self._value)

    @property
    def name(self) -> str:
        '''Cookie's name.'''
        return self._name

    @property
    def value(self) -> str:
        '''Cookie's value.'''
        return self._value


class Cookies(list):
    '''Represents a http cookie storages that inherit from list builtin.'''

    def __init__(self) -> None:
        '''Initialize the storage.'''
        super().__init__()

    def append(self, c: Cookie) -> None:
        '''Appends cookie to storage.

        If Cookie already existes at storage, this method do nothing.
        '''
        if c not in self:
            super().append(c)

    def find(self, name: str) -> Optional[Cookie]:
        '''Find a cookie by name.'''
        r: List = list(filter(lambda c: c.name == name, self))
        return r[0] if r else None


class CookiesFileLoader:

    def __init__(self, file_path: str) -> None:
        '''Parses json file export file by Cookie-Editor extension.

        Args:
            file_path (str): cookies.json path.

        Raises:
            CookiesFileLoader.EmptyFileError
            CookiesFileLoader.FileNotFoundError
            CookiesFileLoader.InvalidFileError: When there is some json parsing
            error.
        '''
        global logger
        self._log: logging.Logger = logger.getChild(self.__class__.__name__)
        self._file_path: str = file_path
        self._cookies: Cookies = Cookies()

        self.__load_file()

    def __load_file(self) -> Optional[NoReturn]:
        '''Parse cookies file.'''
        if not exists(self._file_path):
            raise FileNotFoundError(self._file_path)

        if stat(self._file_path).st_size == 0:
            raise EmptyFileError(self._file_path)

        self._log.debug("Reading file...")
        with open(self._file_path, "r") as f:
            data:str = f.read()

        try:
            self._log.debug("Parsing...")
            cookies: Dict = json.loads(data)
        except json.JSONDecodeError as e:
            self._log.error(e)
            raise InvalidFileError(e)
        else:
            if not cookies:
                self._log.debug("No cookies for process!")
            else:
                self._log.debug("Processing cookies...")
                for c in cookies:
                    self._cookies.append(Cookie(
                            name=c["name"],
                            value=c["value"]
                        ))

    @property
    def cookies(self) -> Cookies:
        '''Cookies Storage.'''
        return self._cookies


class DocumentDownloader:
    CHUNK_BUFFER = 8192

    def __init__(self) -> None:
        '''Allows to download a PDF document from own public feed.
        '''
        global logger
        self._log: logging.Logger = logger.getChild(self.__class__.__name__)
        self._publication_path: str = ""
        # Stores document url to retrieve json ld data.
        self._document_url: str = ""
        # Stores document manifest url (contains document url).
        self._manifest_url: str = ""

    def __http_get(self, s: Session, url: str) -> Optional[Union[str, NoReturn]]:
        '''Query a web resource and retrieve it contents as string.

        Args:
            s (requests.Session): HTTP Session.
            url (str): Url to be requested.

        Raises:
            DownloadError

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
                raise DownloadError(err)

            return req.text

    def __download_file(self, output_file: str, s: Session) -> Optional[NoReturn]:
        '''Downloads url and saves into output_file.

        Args:
            output_file (str): File path to save downloaded file.
            s (requests.Session): HTTP Session.

        Raises:
            DownloadError
            FileExistsError
        '''
        if not self._document_url:
            err: str = "The document url is not set!"
            self._log.error(err)
            raise DownloadError(err)

        if exists(output_file):
            raise FileExistsError(output_file)

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
                for chunk in req.iter_content(chunk_size=self.CHUNK_BUFFER):
                    pb.update(len(chunk))
                    f.write(chunk)
        self._log.debug("Download finished!")

    def __load_json_ld(self, s: Session) -> Optional[NoReturn]:
        '''Loads json ld from document url.

        Args:
            s (requests.Session): HTTP Session.

        Raises:
            DownloadError
        '''
        json_ld_tag: str = '<script type="application/ld+json">'

        self._log.debug("Retrieving json-ld data...")
        url: str = Linkedin.POST.format(self._publication_path)
        content: str = self.__http_get(s, url) # type: ignore

        # json-ld tag not found
        if json_ld_tag not in content:
            err: str = f"json-ld tag not found!"
            self._log.error(err)
            raise DownloadError(err)

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
            raise DownloadError(e)

        # sharedContent not found
        if "sharedContent" not in data:
            err: str = "Key 'sharedContent' not found at json-ld data!"
            self._log.error(err)
            raise DownloadError(err)

        # Document manifest url found
        self._manifest_url = data["sharedContent"]["url"]
        print(self._manifest_url)

    def __load_manifest(self, s: Session) -> Optional[NoReturn]:
        '''Loads document manifest.

        Args:
            s (requests.Session): HTTP Session.

        Raises:
            DownloadError
        '''
        if not self._manifest_url:
            raise DownloadError("The manifest url is not set!")

        self._log.debug("Retrieving manifest...")
        content: str = self.__http_get(s, self._manifest_url) # type: ignore

        # Try to decode manifest
        try:
            manifest: Dict = json.loads(content)
        except json.decoder.JSONDecodeError as e:
            self._log.error(e)
            raise DownloadError(e)

        # Document url not found at manifest
        if "transcribedDocumentUrl" not in manifest:
            err: str = "Key 'transcribedDocumentUrl' not found at manifest!"
            self._log.error(err)
            raise DownloadError(err)

        self._document_url = manifest["transcribedDocumentUrl"]
        self._log.debug("Document url set")

    def __reset(self) -> None:
        '''Reinitialize the instance.'''
        self._document_id: int = 0
        self._document_url: str = ""
        self._manifest_url: str = ""
        self._log.debug("The instance has been reinitialized!")

    def download(self, publication_path: str, output_file: str
            ) -> Optional[NoReturn]:
        '''Downloads PDF document from linkedin user's public feed.

        Args:
            publication_path (str): Url Path of the publication which has the
            document as attachment.
            output_file (str): File path to save downloaded file.

        Raises:
            DownloadError
            FileExistsError
        '''
        global USER_AGENT

        if exists(output_file):
            raise FileExistsError(output_file)

        self._publication_path = publication_path
        self._log.debug(f"Publication: {self._publication_path}")

        self._log.debug("Creating session...")
        s: Session = Session()
        s.headers = {
                "User-Agent": USER_AGENT
            }
        self.__load_json_ld(s)
        self.__load_manifest(s)
        self.__download_file(output_file, s)
        self.__reset()


class Document:
    MAX_SIZE = 104857600 # In bytes

    def __init__(self, title: str, file_path: str) -> None:
        '''Document attachment

        File size must satisfy Document.MAX_SIZE.

        Args:
            title (str): Title of the document once is uploaded.
            file_path (str): A valid path for the document to upload.

        Raises:
            Exception: For empty title and generics.
            FileNotFoundError: When file doesn't exists or is inaccessible.
            MaxFileSizeError: When file size exceeds maximum allowed.
        '''
        global logger
        self._log: logging.Logger = logger.getChild(self.__class__.__name__)
        self._title: str = title
        self._file_path: str = file_path
        self._file_data: bytes = b""

        if not self._title:
            err: str = "Empty title!"
            self._log.error(err)
            raise Exception(err)

        if not exists(self._file_path):
            raise FileNotFoundError(self._file_path)

        if stat(self._file_path).st_size == 0:
            raise EmptyFileError(self._file_path)

        # File size exceeds maximum allowed
        if stat(self._file_path).st_size > Document.MAX_SIZE:
            raise MaxFileSizeError(self._file_path, Document.MAX_SIZE)

        if not self._title:
            self._title = basename(self._file_path)
            self._log.debug("Empty 'title'. Set from 'file_path' base name!")

        self._file_name: str = basename(file_path)

        self.__read_file_contents()

    def __len__(self) -> int:
        '''Length of document contents.'''
        return len(self._file_data)

    def __read_file_contents(self) -> None:
        '''Reads file contents into _file_data property.'''
        self._log.debug("Reading file...")
        with open(self._file_path, "rb") as f:
            self._file_data = f.read()
        self._log.debug("Read done!")

    @property
    def data(self) -> bytes:
        '''Binary data of document.'''
        return self._file_data

    @property
    def file_name(self) -> str:
        '''File name.'''
        return self._file_name

    @property
    def title(self) -> str:
        return self._title


class Publication:

    def __init__(self, document: Document, text_comment: str, visibility: str
            ) -> None:
        global logger
        self._log: logging.Logger = logger.getChild(self.__class__.__name__)
        self._text_comment: str = text_comment
        self._visibility: str = visibility
        self._document: Document = document
        # Stores publication url once publication was created
        self._url: str = ""
        # Stores resource urn once publication was created
        self._urn: int = 0

        if not ContentVisibility.is_valid(self._visibility):
            err: str = f"Visibility '{self._visibility}' is unknown!"
            self._log.error(err)
            raise Exception(err)

    @property
    def attachment_document(self) -> Document:
        '''Attachment document to be uploaded.'''
        return self._document

    @property
    def text_comment(self) -> str:
        '''Comment of the publication.'''
        return self._text_comment

    @property
    def visibility(self) -> str:
        return self._visibility

    @property
    def url(self) -> str:
        '''Publication url. It's available once publication is created.'''
        return self._url

    @url.setter
    def url(self, url: str) -> None:
        '''Sets url.

        Raises:
            Exception: When try to set empty url.
        '''
        if not url:
            raise Exception("Url can't be empty!")
        self._url = url

    @property
    def urn(self) -> int:
        '''Publication urn. It's available once publication is created.

        Returns 0 when publication wasn't created yet. A big integer otherwise.
        '''
        return self._urn

    @urn.setter
    def urn(self, urn: int) -> None:
        self._urn = urn


class AttachmentCreator:

    def __init__(self, cookies: Cookies) -> None:
        '''Create new publication with a pdf document as attachment.

        Raises:
            CookieNotFound: When JSESSIONID is not at cookies.
        '''
        global logger
        self._log: logging.Logger = logger.getChild(self.__class__.__name__)
        # Stores the publication to be sended (from upload method)
        self._publication: Publication
        self._cookies: Cookies = cookies
        self._media_urn: str = ""
        # Url to upload document
        self._single_upload_url: str = ""
        # Upload process bar
        self._upload_process_bar: Optional[tqdm] = None

        self._c_jsession_id: Optional[Cookie] = cookies.find("JSESSIONID")
        if not self._c_jsession_id:
            self._log.error(f"Cookie 'JSESSIONID' is necesary for csrf token!")
            raise CookieNotFound("JSESSIONID")

    def __create_content(self, s: Session) -> Optional[NoReturn]:
        '''Creates the publication which the document as attachment.

        Args:
            s (requests.Session): HTTP Session.

        Raises:
            UploadError'''
        query: str = '''{
    "variables": {
        "post": {
            "allowedCommentersScope": "CONNECTIONS_ONLY",
            "intendedShareLifeCycleState": "PUBLISHED",
            "origin": "FEED",
            "visibilityDataUnion": {
                "visibilityType": "{content_visibility}"
            },
            "commentary": {
                "text": "{text_comment}",
                "attributesV2": []
            },
            "media": {
                "category": "NATIVE_DOCUMENT",
                "mediaUrn": "{media_urn}",
                "title": "{media_title}",
                "recipes": [
                    "urn:li:digitalmediaRecipe:feedshare-document-preview",
                    "urn:li:digitalmediaRecipe:feedshare-document"
                ]
            }
        }
    },
    "queryId": "voyagerContentcreationDashShares.2e462fe06c2124f6ec35370ea350e18a"
}'''
        query = query.replace("\n", "").replace("    ", "")
        query = query.replace("{content_visibility}", self._publication.visibility) \
            .replace("{media_title}", self._publication.attachment_document.title) \
            .replace("{media_urn}", self._media_urn) \
            .replace("{text_comment}", self._publication.text_comment)
        self._log.debug(f"Query: {query}");
        s.headers.update({
                "Accept": "application/json; charset=UTF-8",
                "Content-Type": "application/json; charset=UTF-8",
            })
        url: str = Linkedin.VOYAGER_API \
            + "graphql?action=execute&queryId=" \
            + "voyagerContentcreationDashShares.2e462fe06c2124f6ec35370ea350e18a"
        self._log.debug("Url: " + url)
        self._log.debug("Headers: " + str(s.headers))

        with s.post(url, data=query) as req:
            # HTTP error
            if not req.status_code == 200:
                err: str = f"HTTP Code: {req.status_code}; Body: {req.text}"
                self._log.error(err)
                raise UploadError(err)

            try:
                data: Dict = req.json()
            except json.JSONDecodeError as e:
                self._log.error(e)
                raise UploadError(e)

            self._log.debug("Publication created!")
            self._log.debug("Response: " + req.text)
            # Set url & url to publication
            state: Dict = data["value"]["data"]["createContentcreationDashShares"] \
                ["entity"]["status"]["lifecycleState"]["PublishedState"]
            self._publication.urn = int(state["metadata"]["backendUrn"] \
                .replace("urn:li:activity:", ""))
            self._publication.url = state["socialContent"]["shareUrl"]

        # Headers cleaning
        del s.headers["Accept"]
        del s.headers["Content-Type"]
        self._log.debug("Deleted headers: Accept, Content-Type!")

    def __request_upload_file(self, s: Session) -> Optional[NoReturn]:
        '''Requests file upload to linkedin voyager api.

        Args:
            s (requests.Session): HTTP Session.

        Raises:
            UploadError
        '''
        url: str = Linkedin.VOYAGER_API \
                + "voyagerVideoDashMediaUploadMetadata?action=upload"
        payload: str = json.dumps({
                "mediaUploadType": "DOCUMENT_SHARING",
                "filename": self._publication.attachment_document.file_name,
                "fileSize": len(self._publication.attachment_document)
            }) # type: ignore
        s.headers.update({
                "Accept": "application/vnd.linkedin.normalized+json+2.1",
                "Content-Type": "application/json; charset=UTF-8"
            })
        self._log.debug("Url: " + url)
        self._log.debug("Headers: " + str(s.headers))
        self._log.debug("Payload: " + payload)
        with s.post(url, data=payload) as req:
            # HTTP error
            if not req.status_code == 200:
                err: str = f"HTTP Code: {req.status_code}; Body: {req.text}"
                self._log.error(err)
                raise UploadError(err)

            try:
                data: Dict = req.json()
            except json.JSONDecodeError as e:
                self._log.error(e)
                raise UploadError(e)

            self._log.debug("Response: " + req.text)

            self._media_urn = data["data"]["value"]["urn"]
            self._single_upload_url = data["data"]["value"]["singleUploadUrl"]
            self._log.debug(f"Media urn: {self._media_urn}")
            self._log.debug(f"Single upload url: {self._single_upload_url}")

        # Headers cleaning
        del s.headers["Accept"]
        del s.headers["Content-Type"]
        self._log.debug("Deleted headers: Accept, Content-Type!")

    def __reset(self) -> None:
        '''Reinitialize the instance.'''
        self._publication = None # type: ignore
        self._media_urn = ""
        self._single_upload_url = ""
        self._upload_process_bar = None
        self._log.debug("The instance has been reinitialized!")

    def __upload_file(self, s: Session) -> Optional[NoReturn]:
        '''Uploads a file.

        Args:
            s (requests.Session): HTTP Session.

        Raises:
            UploadError
        '''

        if not self._single_upload_url:
            raise UploadError("Upload url was not requested first!")

        s.headers.update({
            "Accept": "*/*",
            "Content-Type": "application/pdf",
            "media-type-family": "PAGINATEDDOCUMENT"
            })

        self._log.debug("Uploading file...")
        # data: bytes = self._publication.attachment_document.data
        data_reader: CallbackIOWrapper = CallbackIOWrapper(
                self._upload_process_bar.update, # type: ignore
                BytesIO(self._publication.attachment_document.data),
                "read"
            )
        with s.put(self._single_upload_url, data=data_reader) as req:
            # HTTP error
            if req.status_code != 201:
                err: str = f"HTTP Code: {req.status_code}; Body: {req.text}"
                self._log.error(err)
                raise UploadError(err)
        self._log.debug("Uploading done!")

        # Headers cleaning
        del s.headers["Accept"]
        del s.headers["Content-Type"]
        del s.headers["media-type-family"]
        self._log.debug("Deleted headers: Accept, Content-Type, media-type-family!")

    def send(self, publication: Publication) -> Optional[NoReturn]:
        '''Send new publication with PDF file as document attachment.

        Args:
            publication (Publication): The publication to send.

        Raises:
            UploadError
        '''
        self._publication = publication
        # Set upload bar
        self._upload_process_bar = tqdm(
                desc="Uploading {}...".format(
                        self._publication.attachment_document.file_name
                    ),
                total=len(self._publication.attachment_document),
                unit='B',
                unit_divisor=1024,
                unit_scale=True
            )

        self._log.debug("Setup session...")
        s: Session = Session()
        # Setup cookies is simpler this way
        h_cookies: str = "; ".join([f"{c.name}={c.value}" for c in self._cookies])
        self._log.debug("Cookies: " + h_cookies)

        # Setup minimun headers, each method setup their own headers itself
        s.headers = {
                "Cookie": h_cookies,
                "csrf-token": self._c_jsession_id.value.replace('"', ""), # type: ignore
                "Origin": Linkedin.BASE,
                "Referer": Linkedin.FEED,
                "User-Agent": USER_AGENT
            }

        self._log.debug("Initiating upload process...")
        self.__request_upload_file(s)
        self.__upload_file(s)
        self._log.debug("Waiting for file processing at server (5 seconds)...")
        sleep(5)
        self.__create_content(s)
        self.__reset()
