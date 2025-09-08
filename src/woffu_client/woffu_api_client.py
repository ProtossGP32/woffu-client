from operator import itemgetter
import sys
import json
import logging
from .stdrequests_session import Session
from pathlib import Path
from getpass import getpass
from datetime import datetime, timedelta
from tzlocal import get_localzone
import os

# Initialize a logger
logger = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    format="[%(asctime)s] %(levelname)s %(module)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# TODO: Make log level configurable
logger.setLevel("INFO")

DEFAULT_CONFIG = Path.home() / ".config/woffu/woffu_auth.json"
DEFAULT_DOCS_DIR = Path.home() / "Documents/woffu/docs"

DEFAULT_DATE_FORMAT = "%Y-%m-%d"

class WoffuAPIClient(Session):
    # Class arguments
    _woffu_api_url: str = "https://app.woffu.com"


    def _get_domain_user_companyId(self):
        """
        Get the required Company ID, Domain and User ID, required for HTTP requests.
        One-time only call; this data should be stored in a file and reused from there.
        """
        # This function should only be called the first time the script runs.
        # We'll store the results for subsequent executions
        logger.debug("Retrieving Company IDs...")
        
        # First we need the Company ID from the Users information
        users = self.get(
            url=f"{self._woffu_api_url}/api/users"
        ).json()

        # With that, we retrieve the company Domain
        company = self.get(
            url=f"{self._woffu_api_url}/api/companies/{users['CompanyId']}"
        ).json()

        # Set class arguments
        self._domain = company["Domain"]
        self._user_id, self._company_id = itemgetter(
            'UserId',
            'CompanyId'
        )(users)


    def _retrieve_access_token(self, username: str = "", password: str = ""):
        """
        Authentication process to retrieve token
        """
        if not username or not password:
            logger.error("No username or password provided.")
            return
        
        logger.info("Requesting access token...")
        token_response = self.post(
            url=f"{self._woffu_api_url}/token",
            data = {
                "grant_type": "password",
                "username": username,
                "password": password
            }
        )

        if token_response.status == 200:
            self._token = token_response.json()['access_token']
        else:
            logger.error(f"Can't retrieve access token. Please review username and password and try again. Error code: {token_response.status}")
            self._token = ""
        

    def _save_credentials(self):
        """
        Save the credentials in a config file for later use.
        """
        self._config_file.parent.mkdir(parents=True, exist_ok=True)
        self._config_file.write_text(
            data = json.dumps(
                {
                    "username": self._username,
                    "token": self._token,
                    "user_id": self._user_id,
                    "company_id": self._company_id,
                    "domain": self._domain
                }
            )
        )
        logger.info(f"✅ Credentials stored in: {self._config_file}")


    def _request_credentials(self):
        """
        Request all available information to compose credentials
        Use WOFFU_USERNAME and WOFFU_PASSWORD environment variables for unattended request
        """
        self._username = os.environ.get('WOFFU_USERNAME', "")
        password = os.environ.get('WOFFU_PASSWORD', "")

        # Ask for credentials manually if not provided
        if (not self._username or not password):
            if self._interactive:
                self._username = input("Enter your Woffu username (mail):\n")
                password = getpass(prompt="Enter your password:\n")
            else:
                logger.error("Can't request token in non-interactive method without username and password. Please provide them in WOFFU_USERNAME and WOFFU_PASSWORD.")
                sys.exit(1)

        # Retrieve access token
        self._retrieve_access_token(
            username=self._username,
            password=password
        )

        # Set authentication headers
        self.headers=self._compose_auth_headers()
        logger.info("Retrieving Company information...")

        # Get Company information
        self._get_domain_user_companyId()


    def _load_credentials(self, creds_file: str = "") -> None:
        """
        Load Woffu credentials stored in provided file
        """
        # Update the config file path if a new one is provided
        if creds_file:
            self._config_file = Path(creds_file)
        
        if not self._config_file.exists():
            logger.error(f"Config file '{self._config_file}' doesn't exist! Requesting authentication token...")
            self._request_credentials()
            self._save_credentials()
            
        else:
            with open(self._config_file, "r") as f:
                creds_info = json.load(f)
                self._domain, self._username, self._token, self._user_id, self._company_id = itemgetter(
                    "domain",
                    "username",
                    "token",
                    "user_id",
                    "company_id"
                )(creds_info)
                # Set authentication headers
                self.headers=self._compose_auth_headers()


    def _compose_auth_headers(self) -> dict:
        """
        Compose the authentication headers
        """
        return {
            'Authorization': f"Bearer {self._token}",
            'Accept': 'application/json',
        }


    def __init__(self, **kwargs) -> None:
        # Instance arguments
        self._domain: str = ""
        self._username: str = ""
        self._token: str = ""
        self._user_id: str = ""
        self._company_id: str = ""
        self._config_file: Path = Path(kwargs["config"]) if "config" in kwargs else DEFAULT_CONFIG
        self._documents_path : Path = Path(kwargs["documents_path"]) if "documents_path" in kwargs else DEFAULT_DOCS_DIR
        self._interactive: bool = kwargs["interactive"] if "interactive" in kwargs else False

        # Initialize the parent class
        super().__init__()

        # load config file if provided
        self._load_credentials()


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

    def get_presence(self, from_date: str = "", to_date: str = "", page_size: int = 1000) -> dict:
        """
        Return the presence summary of a user within the provided time window. If no dates are defined, they will be initialized to the current date
        params:
        from_date: str. Start of the time window formatted as 'YYYY-mm-dd'
        to_date: str. End of the time window formatted as 'YYYY-mm-dd'
        page_size: int. Number of entries to retrieve. This should match the number of queried days, but we'll leave it at 1000 by default.
        """

        current_date = datetime.now(tz=get_localzone())
        
        # Initialize date values
        if not from_date:
            from_date = current_date.strftime(DEFAULT_DATE_FORMAT)
            to_date = current_date.strftime(DEFAULT_DATE_FORMAT)

        hours_response = self.get(
            url=f"https://{self._domain}/api/svc/core/diariesquery/users/{self._user_id}/diaries/summary/presence",
            params={
                "userId": self._user_id,
                "fromDate": from_date,
                "toDate": to_date,
                "pageSize": page_size,
                "includeHourTypes":	True,
                "includeNotHourTypes": True,
                "includeDifference": True
            }
        )

        if hours_response.status == 200:
            return hours_response.json()
    
        else:
            logger.error(f"Can't retrieve presence for the time period {from_date} - {to_date}!")
            return {}


    def _get_diary_hour_types(self, date: str) -> dict:
        """
        Return the hour types' summary for a given date
        """

        hour_types_response = self.get(
            url=f"https://{self._domain}/api/svc/core/diariesquery/diarysumaries/workday/diaryhourtypes",
            params={
                "userId": self._user_id,
                "date": date
            }
        )

        if hour_types_response.status == 200:
            return hour_types_response.json()['diaryHourTypes']
    
        else:
            logger.error(f"Can't retrieve hour types for date {date}!")
            return {}
    

    def _get_workday_slots(self, diary_summary_id: int) -> dict:
        """
        Return the workday slots for a given day. Each slot is comprised by the following keys: "in, "out" and "motive"
        params:
        diary_summary_id: int. It can be retrieved via `get_presence`; each diary entry has its own `diarySummaryId` key.
        """

        workday_slots_response = self.get(
            url=f"https://{self._domain}/api/svc/core/diariesquery/diarysummaries/{diary_summary_id}/workday/slots/self"
        )

        if workday_slots_response.status == 200:
            return workday_slots_response.json()
    
        else:
            logger.error(f"Can't retrieve workday slots for diary entry {diary_summary_id}!")
            return {}


    def get_sign_requests(self, date: str):
        """
        Return the user requests for a given date, such as Holidays
        params:
        date: str. Sign requests date. WARNING! Date format must be "mm/dd/YYYY", this is different from the rest of queries.
        """
        # TODO: unify date argument to the same format as the rest of methods and reformat it before sending the GET request

        sign_motives_response = self.get(
            url=f"https://{self._domain}/api/svc/core/diary/user/requests",
            params={
                "date": date
            }
        )

        if sign_motives_response.status == 200:
            return sign_motives_response.json()
    
        else:
            logger.error(f"Can't retrieve sign motives for date {date}!")
            return {}
        
    
    def get_status(self, only_running_clock: bool = False) -> tuple[timedelta, bool]:
        """
        Return the total amount of worked hours as well as whether we're signed-in or signed-out at the moment
        """
        signs_in_day = self.get(
            url=f"{self._woffu_api_url}/api/signs"
        ).json()

        # Initialize a timer and the running clock boolean
        total_time = timedelta()
        running_clock = False

        # Just return the las sign status
        if only_running_clock:
            return total_time, signs_in_day[-1]['SignIn'] if signs_in_day else running_clock

        # Go through all the signs.
        # Prepare current time with local timezone to use in case UTC offsets are wrong in Woffu
        # - We do it this way to take into account Daylight Saving Timezones (CET +1, CEST +2, for example)
        current_time = datetime.now(tz=get_localzone())

        for sign in signs_in_day:
            running_clock = sign['SignIn']
            sign_date = sign['TrueDate']
            # Split UtcTime and keep only the offset
            utc_offset = f"{sign['UtcTime'].split(' ')[1].zfill(3)}00"
            # WORKAROUND: Woffu stores incorrect UTC information when signing in from the Webapp, showing same local date on 'TrueDate' and 'UtcTime' but with no UTC offset (+0)
            # - In the time being, we'll be using our local timezone for any sign that comes with +0 in the UtcTime as we suspect Woffu DB is running on a server with the same local timezone as us
            if utc_offset == "+0000":
                utc_offset = current_time.strftime("%z")

            sign_date_timezoned = f"{sign_date}{utc_offset}"

            if running_clock:
                t1 = datetime.strptime(sign_date_timezoned, f"{DEFAULT_DATE_FORMAT}T%H:%M:%S.%f%z")
            else:
                t2 = datetime.strptime(sign_date_timezoned, f"{DEFAULT_DATE_FORMAT}T%H:%M:%S.%f%z")
                # Only update total_time when there's a sign-out
                total_time += (t2 - t1)
                logger.debug(f"Total time on closed signs: {total_time.total_seconds() / 3600}")
        
        logger.debug(f"Total time on closed signs: {total_time.total_seconds() / 3600}")

        # If clock is still running, add the remaining time
        if running_clock:
            logger.debug(f"Current time: {current_time.isoformat()}")
            total_time += (current_time - t1)

        # Log worked hours:
        hours, rem = divmod(total_time.total_seconds(), 3600)
        minutes, seconds = divmod(rem, 60)
        logger.info('Hours worked today: {:02d}:{:02d}:{:02d}'.format(int(hours), int(minutes), int(seconds)))
        logger.info(f"You're currently signed {'in' if running_clock else 'out'}.")
        return total_time, running_clock

    def sign(self, type: str = "", motive: str = ""):
        """
        Sign in/out on Woffu
        params:
        type: str. Can be "in", "out" or "empty". If empty, it will sign in/out without checking the current status.
        """
        # TODO: Include the sign-in reason in the sign-in ("Working from home", "Office", etc...)
        # Get current sign status
        _, signed_in = self.get_status(only_running_clock=True)

        # Evaluate current sign value against desired
        match type:
            case "in" | "out":
                requested_sign: bool = True if type == "in" else False
                if signed_in == requested_sign:
                    logging.warning(f"User is already signed {type}, skipping new sign.")
                    return
            case _:
                pass

        # Send sign request
        logger.info("Sending sign request...")
        # Get the current datetime with local timezone
        current_time = datetime.now(tz=get_localzone())

        # Get the actual time offset in minutes
        utc_offset = current_time.utcoffset()
        if utc_offset:
            timezone_offset =- int(utc_offset.total_seconds() / 60)
        else:
            timezone_offset = 0
        
        return self.post(
            url=f"https://{self._domain}/api/svc/signs/signs",
            # You don't need to send any data, just an empty JSON object.
            # The only known keys that are sent from the webpage are:
            # - agreementEventId: probably auto-generated on sign-in event, always empty on sign-out
            # - deviceId: like "WebApp"
            # - latitude: always Null
            # - longitude: always Null
            # - requestId: always Null
            # - timezoneOffset: matches the UTC offset of the timezone in minutes, and in inverse sign (-120 minutes for CEST, for example)
            json={
                #'StartDate': current_time.isoformat(sep='T', timespec='seconds'),
                #'EndDate': current_time.isoformat(sep='T', timespec='seconds'),
                #'timezoneOffset': timezone_offset,
                #'UserId': self._user_id
            }
        )
    

    def get_diary_hour_types_summary(self, from_date: str = "", to_date:str = "") -> dict:
        """
        Return a summary of the diary hour types other than the working ones, such as 'Extr. a compensar'
        """

        hour_types_summary: dict = {}

        from_dt = datetime.strptime(from_date, DEFAULT_DATE_FORMAT).astimezone(get_localzone())
        to_dt = datetime.strptime(to_date, DEFAULT_DATE_FORMAT).astimezone(get_localzone())

        for day in range(0, (to_dt - from_dt).days +1):
            date = from_dt + timedelta(days=day)
            date_str = date.strftime(DEFAULT_DATE_FORMAT)
            hour_types = self._get_diary_hour_types(date=date.strftime(date_str))

            hour_types_dict = {}

            for hour_type in hour_types:
                if hour_type['name'] not in hour_types_dict:
                    hour_types_dict[hour_type['name']] = hour_type['hours']
                else:
                    hour_types_dict[hour_type['name']] =+ hour_type['hours']

            hour_types_summary[date_str] = hour_types_dict

        return hour_types_summary