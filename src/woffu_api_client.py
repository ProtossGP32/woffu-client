from operator import itemgetter
import os
import sys
import json
import logging
from .stdrequests_session import Session

# Initialize a logger
logger = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    format="[%(asctime)s] %(levelname)s %(module)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


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
        

    def load_credentials(self, creds_file: str = "") -> None:
        """
        Load Woffu credentials stored in provided file
        """
        # Update the config file path if a new one is provided
        if creds_file and os.path.exists(creds_file):
            self._config_file = creds_file

        with open(self._config_file, "r") as f:
            creds_info = json.load(f)
            self._domain, self.username, self.token, self._user_id, self._company_id = itemgetter(
                "domain",
                "username",
                "token",
                "user_id",
                "company_id"
            )(creds_info)


    def __init__(self, **kwargs) -> None:
        # Instance arguments
        self._domain: str = ""
        self._username: str = ""
        self._token: str = ""
        self._user_id: str = ""
        self._company_id: str = ""
        self._config_file: str = ""

        # load config file if provided
        if "config" in kwargs and os.path.exists(kwargs["config"]):
            self._config_file = kwargs["config"]
            self.load_credentials()
        else:
            logger.error("No config file provided. Proceeding with manual authentication:")

        