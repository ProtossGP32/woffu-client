from operator import itemgetter
import sys
import json
import logging
from .stdrequests_session import Session
from pathlib import Path

# Initialize a logger
logger = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    format="[%(asctime)s] %(levelname)s %(module)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# TODO: Make log level configurable
logger.setLevel("INFO")


class WoffuAPIClient(Session):
    # Class arguments
    _woffu_api_url: str = "https://app.woffu.com"


    def _retrieve_access_token(self, username: str = "", password: str = "") -> None:
        """
        Authentication process to retrieve token
        """
        if not username or not password:
            logger.error("No username or password provided.")
            return
        
        logger.info("Requesting access token...")
        response = self.post(
            url=f"{self._woffu_api_url}/token",
            data = f"grant_type=password&username={username}&password={password}"
        )
        

    def _load_credentials(self, creds_file: str = "") -> None:
        """
        Load Woffu credentials stored in provided file
        """
        # Update the config file path if a new one is provided
        if creds_file:
            self._config_file = Path(creds_file)
        
        if not self._config_file.exists():
            logger.error(f"Config file '{self._config_file}' doesn't exist! Exiting")
            sys.exit(1)

        with open(self._config_file, "r") as f:
            creds_info = json.load(f)
            self._domain, self._username, self._token, self._user_id, self._company_id = itemgetter(
                "domain",
                "username",
                "token",
                "user_id",
                "company_id"
            )(creds_info)

        # Compose the headers and store it in the Session.hearers attribute
        self._headers = {
            'Authorization': f"Bearer {self._token}",
            'Accept': 'application/json',
            'Content-Type': 'application/json;charset=utf-8'
        }


    def __init__(self, **kwargs) -> None:
        # Instance arguments
        self._domain: str = ""
        self._username: str = ""
        self._token: str = ""
        self._user_id: str = ""
        self._company_id: str = ""
        self._config_file: Path = Path(kwargs["config"]) if "config" in kwargs else Path.joinpath(Path.home(), ".config/woffu/woffu_auth.json")
        self._headers: dict[str, str] = {}
        self._documents_path : Path = Path(kwargs["documents_path"]) if "documents_path" in kwargs else Path.joinpath(Path.home(), "Documents/woffu/docs")

        # load config file if provided
        self._load_credentials()

        super().__init__(headers=self._headers)

    
    def get_documents(self, page_size: int = 200) -> list[dict]:
        """
        Return a dictionary with the user's available documents
        """

        documents_dict = self.get(
            url=f"https://{self._domain}/api/users/{self._user_id}/all/documents",
            params={
                "visible": "true",
                "pageSize": str(page_size)
            }
        ).json()

        if "Documents" in documents_dict:
            logger.info(f"{documents_dict['TotalRecords']} documents found")
            return documents_dict["Documents"]
        
        logger.warning(f"No documents available for user {self._username}")
        return []
    

    def download_document(self, document: dict, output_dir: str) -> None:
        """
        Download the document to the defined output_path 
        """
        if output_dir:
            output_path: Path = Path(output_dir)
        else:
            output_path: Path = self._documents_path

        # Compose the file path
        #document_path = os.path.join(output_path, document["Name"])
        document_path = Path.joinpath(Path(output_path), document["Name"])

        if document_path.exists():
            logger.debug(f"Document '{document['Name']}' already exists in the documents folder, not downloading again")
            return
        
        # Create output path if it doesn't exist        
        if not output_path.exists():
            logger.debug(f"Creating output directory: {output_path}")
            output_path.mkdir(parents=True, exist_ok=True)

        # Compose the download link
        document_url = f"https://{self._domain}/api/documents/{document['DocumentId']}/download2"

        document_response = self.get(url=document_url)

        # Save the document
        if document_response.status == 200:
            logger.info(f"Saving '{document['Name']}'...")
            #with open(file=document_path, mode='bw') as f:
            #    f.write(document_response.content())
            document_path.write_bytes(document_response.content())

    def download_all_documents(self, output_dir: str = "") -> None:
        """
        Download all user's documents
        """
        # Retrieve the list of available documents
        documents_list = self.get_documents()
        
        # Iterate over all documents and download them
        if documents_list:
            logger.info("Downloading all documents...")
            for document in documents_list:
                self.download_document(document=document, output_dir=output_dir)
            logger.info("All documents downloaded!")

