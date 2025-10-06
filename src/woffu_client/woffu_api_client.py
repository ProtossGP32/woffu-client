"""WoffuAPIClient.

Woffu API client module.
"""
from __future__ import annotations

import csv
import json
import logging
import os
import sys
from datetime import datetime
from datetime import timedelta
from getpass import getpass
from operator import itemgetter
from pathlib import Path

from tzlocal import get_localzone

from .stdrequests_session import HTTPResponse
from .stdrequests_session import Session

# Initialize a logger
logger = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    format="[%(asctime)s] %(levelname)s %(module)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger.setLevel("INFO")

DEFAULT_CONFIG = Path.home() / ".config/woffu/woffu_auth.json"
DEFAULT_DOCS_DIR = Path.home() / "Documents/woffu/docs"
DEFAULT_SUMMARY_REPORTS_DIR = Path.home() / "Documents/woffu/summary_reports"

DEFAULT_DATE_FORMAT = "%Y-%m-%d"


class WoffuAPIClient(Session):
    """Provides a Session class with access to Woffu endpoints."""

    # Class arguments
    _woffu_api_url: str = "https://app.woffu.com"
    _localzone = get_localzone()

    hour_types_dict: dict = {5: "Extr. a compensar"}

    def _get_domain_user_companyId(self):
        """
        Get the required Company ID, Domain and User ID, \
            required for HTTP requests.

        One-time only call; this data should be stored \
            in a file and reused from there.
        """
        # This function should only be called the first time the script runs.
        # We'll store the results for subsequent executions
        logger.debug("Retrieving Company IDs...")

        # First we need the Company ID from the Users information
        users = self.get(url=f"{self._woffu_api_url}/api/users").json()

        # With that, we retrieve the company Domain
        company = self.get(
            url=f"{self._woffu_api_url}/api/companies/{users['CompanyId']}",
        ).json()

        # Set class arguments
        self._domain = company["Domain"]
        self._user_id, self._company_id = itemgetter("UserId", "CompanyId")(
            users,
        )

    def _retrieve_access_token(self, username: str = "", password: str = ""):
        """Retrieve a Woffu access token."""
        if not username or not password:
            logger.error("No username or password provided.")
            return

        logger.info("Requesting access token...")
        try:
            token_response = self.post(
                url=f"{self._woffu_api_url}/token",
                data={
                    "grant_type": "password",
                    "username": username,
                    "password": password,
                },
            )

            if token_response.status != 200:
                self._token = ""
                logger.error(
                    f"Failed to retrieve access token, \
                        status={token_response.status}",
                )
                return
            self._token = token_response.json().get("access_token", "")

        except Exception as e:
            self._token = ""
            logger.error(f"Exception retrieving token: {e}")

    def _save_credentials(self):
        """Save the credentials in a config file for later use."""
        self._config_file.parent.mkdir(parents=True, exist_ok=True)
        self._config_file.write_text(
            data=json.dumps(
                {
                    "username": self._username,
                    "token": self._token,
                    "user_id": self._user_id,
                    "company_id": self._company_id,
                    "domain": self._domain,
                },
            ),
        )
        logger.info(f"✅ Credentials stored in: {self._config_file}")

    def _request_credentials(self):
        """
        Request and store user credentials for accessing the Woffu API.

        This method retrieves credentials from environment variables
        (WOFFU_USERNAME and WOFFU_PASSWORD) or prompts the user for them
        if running in interactive mode.

        Raises:
            SystemExit: If credentials are required but cannot be obtained
                         in either interactive or non-interactive mode.
        """
        self._username = os.environ.get("WOFFU_USERNAME", "")
        password = os.environ.get("WOFFU_PASSWORD", "")

        # Ask for credentials manually if not provided
        if not self._username or not password:
            if self._interactive:
                self._username = input("Enter your Woffu username (mail):\n")
                password = getpass(prompt="Enter your password:\n")
            else:
                logger.error(
                    "Can't request token in non-interactive \
method without username and password. \
Please provide them in WOFFU_USERNAME and WOFFU_PASSWORD.",
                )
                sys.exit(1)

        # Retrieve access token
        self._retrieve_access_token(username=self._username, password=password)

        # Set authentication headers
        self.headers = self._compose_auth_headers()
        logger.info("Retrieving Company information...")

        # Get Company information
        self._get_domain_user_companyId()

    def _load_credentials(self, creds_file: str = "") -> None:
        """Load Woffu credentials stored in provided file."""
        # Update the config file path if a new one is provided
        if creds_file:
            self._config_file = Path(creds_file)

        if not self._config_file.exists():
            logger.warning(
                f"Config file '{self._config_file}' doesn't exist! \
Requesting authentication token...",
            )
            self._request_credentials()
            self._save_credentials()

        else:
            with open(self._config_file, "r") as f:
                creds_info = json.load(f)
                (
                    self._domain,
                    self._username,
                    self._token,
                    self._user_id,
                    self._company_id,
                ) = itemgetter(
                    "domain", "username", "token", "user_id", "company_id",
                )(
                    creds_info,
                )
                # Set authentication headers
                self.headers = self._compose_auth_headers()

    def _compose_auth_headers(self) -> dict:
        """Compose the authentication headers."""
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }

    def __init__(self, **kwargs) -> None:
        """Initialize the class object."""
        # Instance arguments
        self._domain: str = ""
        self._username: str = ""
        self._token: str = ""
        self._user_id: str = ""
        self._company_id: str = ""
        self._config_file: Path = (
            Path(kwargs["config"]) if "config" in kwargs else DEFAULT_CONFIG
        )
        self._documents_path: Path = (
            Path(kwargs["documents_path"])
            if "documents_path" in kwargs
            else DEFAULT_DOCS_DIR
        )
        self._interactive: bool = (
            kwargs["interactive"] if "interactive" in kwargs else False
        )
        # Set logger level
        logger.setLevel(kwargs.get("log_level", "INFO"))
        # Initialize the parent class
        super().__init__()

        # load config file if provided
        self._load_credentials()

    def get_documents(self, page_size: int = 200) -> list[dict]:
        """Return a dictionary with the user's available documents."""
        documents_dict = self.get(
            url=f"https://{self._domain}/api/users/\
{self._user_id}/all/documents",
            params={"visible": "true", "pageSize": str(page_size)},
        ).json()

        if "Documents" in documents_dict:
            logger.info(f"{documents_dict['TotalRecords']} documents found")
            return documents_dict["Documents"]

        logger.warning(f"No documents available for user {self._username}")
        return []

    def download_document(self, document: dict, output_dir: str) -> None:
        """Download the document to the defined output_path."""
        if output_dir:
            output_path: Path = Path(output_dir)
        else:
            output_path: Path = self._documents_path

        # Compose the file path
        # document_path = os.path.join(output_path, document["Name"])
        document_path = Path.joinpath(Path(output_path), document["Name"])

        if document_path.exists():
            logger.debug(
                f"Document '{document['Name']}' already exists \
in the documents folder, not downloading again",
            )
            return

        # Create output path if it doesn't exist
        if not output_path.exists():
            logger.debug(f"Creating output directory: {output_path}")
            output_path.mkdir(parents=True, exist_ok=True)

        # Compose the download link
        document_url = f"https://{self._domain}/api/documents/\
{document['DocumentId']}/download2"

        try:
            document_response = self.get(url=document_url)
        except Exception as e:
            logger.error(f"Failed to download '{document['Name']}': {e}")
            return

        # Save the document
        if document_response.status == 200:
            logger.info(f"Saving '{document['Name']}'...")
            document_path.write_bytes(document_response.content)
        else:
            logger.error(f"Failed to download '{document['Name']}'")

    def download_all_documents(self, output_dir: str = "") -> None:
        """Download all user's documents."""
        # Retrieve the list of available documents
        documents_list = self.get_documents()

        # Iterate over all documents and download them
        if documents_list:
            logger.info("Downloading all documents...")
            for document in documents_list:
                try:
                    self.download_document(
                        document=document, output_dir=output_dir,
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to download {document.get('Name')}: {e}",
                    )
            logger.info("All documents downloaded!")

    def _get_presence(
        self, from_date: str = "", to_date: str = "", page_size: int = 1000,
    ) -> list:
        """Return the presence summary of a user \
        within the provided time window.

        If no dates are defined, they will be initialized \
        to the current date.

        :params
        :str from_date: Start of the time window formatted as 'YYYY-mm-dd'.
        :str to_date: End of the time window formatted as 'YYYY-mm-dd'.
        :int page_size: Number of entries to retrieve. \
            This should match the number of queried days, \
            but we'll leave it at 1000 by default.
        """
        current_date = datetime.now(tz=self._localzone)

        # Initialize date values
        if not from_date:
            from_date = current_date.strftime(DEFAULT_DATE_FORMAT)
            to_date = current_date.strftime(DEFAULT_DATE_FORMAT)

        hours_response = self.get(
            url=f"https://{self._domain}/api/svc/core/diariesquery/users/\
{self._user_id}/diaries/summary/presence",
            params={
                "userId": self._user_id,
                "fromDate": from_date,
                "toDate": to_date,
                "pageSize": page_size,
                "includeHourTypes": True,
                "includeNotHourTypes": True,
                "includeDifference": True,
            },
        )

        if hours_response.status == 200:
            return hours_response.json().get("diaries", [])

        logger.error(
            f"Can't retrieve presence for the time period \
{from_date} - {to_date}!",
        )
        return []

    def _get_diary_hour_types(self, date: str) -> dict:
        """Return the hour types' summary for a given date."""
        hour_types_response = self.get(
            url=f"https://{self._domain}/api/svc/core/\
diariesquery/diarysumaries/workday/diaryhourtypes",
            params={"userId": self._user_id, "date": date},
        )

        data = (
            hour_types_response.json()
            if getattr(hour_types_response, "status", None) == 200
            else {}
        )
        # Coerce data to dict if possible; otherwise, return empty dict
        return (
            dict(data).get("diaryHourTypes", {})
            if isinstance(data, dict)
            else {}
        )

    def _get_workday_slots(self, diary_summary_id: int) -> list:
        """
        Return the workday slots for a given day.

        Each slot is comprised by the following keys: "in, "out" and "motive".
        :params
        :int diary_summary_id: It can be retrieved via `get_presence`;\
             each diary entry has its own `diarySummaryId` key.
        """
        workday_slots_response = self.get(
            url=f"https://{self._domain}/api/svc/core/diariesquery/\
diarysummaries/{diary_summary_id}/workday/slots/self",
        )

        if workday_slots_response.status == 200:
            return workday_slots_response.json().get("slots", [])

        logger.error(
            f"Can't retrieve workday slots for diary entry \
{diary_summary_id}!",
        )
        return []

    def get_sign_requests(self, date: str) -> dict | list:
        """
        Return the user requests for a given date, such as Holidays.

        :params
        :str date: Sign requests date. \
            WARNING! Date format must be "mm/dd/YYYY", \
            this is different from the rest of queries.
        """
        sign_motives_response = self.get(
            url=f"https://{self._domain}/api/svc/core/diary/user/requests",
            params={"date": date},
        )

        if sign_motives_response.status == 200:
            data = sign_motives_response.json()
            if isinstance(data, (dict, list)):
                return data
            return {}

        logger.error(f"Can't retrieve sign motives for date {date}!")
        return {}

    def get_status(
        self, only_running_clock: bool = False,
    ) -> tuple[timedelta, bool]:
        """Return the total amount of worked hours and current sign status."""
        signs_in_day = self.get(url=f"{self._woffu_api_url}/api/signs").json()

        # Initialize a timer and the running clock boolean
        total_time = timedelta()
        running_clock = False

        # Just return the las sign status
        if only_running_clock:
            return total_time, (
                signs_in_day[-1]["SignIn"] if signs_in_day else running_clock
            )

        # Go through all the signs.
        # Prepare current time with local timezone to use in case
        # UTC offsets are wrong in Woffu.
        # - We do it this way to take into account
        #   Daylight Saving Timezones (CET +1, CEST +2, for example).
        current_time = datetime.now(tz=self._localzone)

        for sign in signs_in_day:
            # running_clock = sign['SignIn']
            # sign_date = sign['TrueDate']
            # # Split UtcTime and keep only the offset
            # utc_offset = f"{sign['UtcTime'].split(' ')[1].zfill(3)}00"

            running_clock = sign.get("SignIn", False)
            sign_date = sign.get("TrueDate", None)
            utc_time = sign.get("UtcTime", "")
            try:
                # Split UtcTime and keep only the offset (format '+HHMM')
                utc_offset = f"{utc_time.split(' ')[1].zfill(3)}00"
            except (IndexError, AttributeError):
                utc_offset = "+0000"  # fallback to UTC

            # WORKAROUND: Woffu stores incorrect UTC information
            # when signing in from the Webapp, showing same local date
            # on 'TrueDate' and 'UtcTime' but with no UTC offset (+0).
            # - For the time being, we'll be using our local timezone
            #   for any sign that comes with +0 in the UtcTime as we
            #   suspect Woffu DB is running on a server with the same
            #   local timezone as us.
            if utc_offset == "+0000":
                utc_offset = current_time.strftime("%z")

            sign_date_timezoned = f"{sign_date}{utc_offset}"

            if running_clock:
                t1 = datetime.strptime(
                    sign_date_timezoned,
                    f"{DEFAULT_DATE_FORMAT}T%H:%M:%S.%f%z",
                )
            else:
                t2 = datetime.strptime(
                    sign_date_timezoned,
                    f"{DEFAULT_DATE_FORMAT}T%H:%M:%S.%f%z",
                )
                # Only update total_time when there's a sign-out
                total_time += t2 - t1
                logger.debug(
                    f"Total time on closed signs: \
{total_time.total_seconds() / 3600}",
                )

        logger.debug(
            f"Total time on closed signs: \
{total_time.total_seconds() / 3600}",
        )

        # If clock is still running, add the remaining time
        if running_clock:
            logger.debug(f"Current time: {current_time.isoformat()}")
            total_time += current_time - t1

        # Log worked hours:
        hours, rem = divmod(total_time.total_seconds(), 3600)
        minutes, seconds = divmod(rem, 60)
        logger.info(
            "Hours worked today: {:02d}:{:02d}:{:02d}".format(
                int(hours), int(minutes), int(seconds),
            ),
        )
        logger.info(
            f"You're currently signed {'in' if running_clock else 'out'}.",
        )
        return total_time, running_clock

    def sign(self, type: str = "") -> HTTPResponse | None:
        """
        Sign in/out on Woffu.

        params:
        type: str. Can be "in", "out" or "empty". If empty, \
            it will sign in/out without checking the current status.
        """
        # Get current sign status
        _, signed_in = self.get_status(only_running_clock=True)

        # Evaluate current sign value against desired
        match type:
            case "in" | "out":
                requested_sign: bool = True if type == "in" else False
                if signed_in == requested_sign:
                    logger.warning(
                        f"User is already signed {type}, skipping new sign.",
                    )
                    return

        # Send sign request
        logger.info("Sending sign request...")
        # # Get the current datetime with local timezone
        # current_time = datetime.now(tz=self._localzone)

        # # Get the actual time offset in minutes
        # utc_offset = current_time.utcoffset()
        # if utc_offset:
        #     timezone_offset = -(int(utc_offset.total_seconds() / 60))
        # else:
        #     timezone_offset = 0

        return self.post(
            url=f"https://{self._domain}/api/svc/signs/signs",
            # You don't need to send any data, just an empty JSON object.
            # The only known keys that are sent from the webpage are:
            # - agreementEventId: probably auto-generated on sign-in event,
            #   always empty on sign-out
            # - deviceId: like "WebApp"
            # - latitude: always Null
            # - longitude: always Null
            # - requestId: always Null
            # - timezoneOffset: matches timezone's UTC offset in minutes
            #   and in inverse sign (-120 minutes for CEST, for example)
            json={
                # 'StartDate': current_time.isoformat(
                #                               sep='T',
                #                               timespec='seconds'
                #                               ),
                # 'EndDate': current_time.isoformat(
                #                               sep='T',
                #                               timespec='seconds'
                #                               ),
                # 'timezoneOffset': timezone_offset,
                # 'UserId': self._user_id
            },
        )

    def get_diary_hour_types_summary(
        self, from_date: str = "", to_date: str = "",
    ) -> dict:
        """Return a summary of all diary hour types.

        Other types are, for example, 'Extr. a compensar'.
        """
        hour_types_summary: dict = {}

        from_dt = datetime.strptime(from_date, DEFAULT_DATE_FORMAT).astimezone(
            self._localzone,
        )
        to_dt = datetime.strptime(to_date, DEFAULT_DATE_FORMAT).astimezone(
            self._localzone,
        )

        for day in range(0, (to_dt - from_dt).days + 1):
            date = from_dt + timedelta(days=day)
            date_str = date.strftime(DEFAULT_DATE_FORMAT)
            hour_types = self._get_diary_hour_types(
                date=date.strftime(date_str),
            )

            hour_types_dict = {}

            for hour_type in hour_types:
                if hour_type["name"] not in hour_types_dict:
                    hour_types_dict[hour_type["name"]] = hour_type["hours"]
                else:
                    hour_types_dict[hour_type["name"]] += hour_type["hours"]

            hour_types_summary[date_str] = hour_types_dict

        return hour_types_summary

    def get_summary_report(
        self, from_date: str = "",
        to_date: str = "",
    ) -> dict:
        """Generate a summary report based on Presence endpoint data."""
        diaries: list = self._get_presence(
            from_date=from_date, to_date=to_date,
        )
        logger.info("Retrieving workday slots and extra hours...")

        summary_report = {}
        for diary in diaries:
            date = diary["date"]
            summary_report[date] = self._build_event_report(diary)

        return summary_report

    def _build_event_report(self, diary: dict) -> dict:
        """Build the report for a single diary entry."""
        event_report: dict = {}
        diary_summary_id = diary["diarySummaryId"]

        # Work hours from slots
        slots = self._get_workday_slots(diary_summary_id=diary_summary_id)
        event_report["work_hours"] = self._calculate_total_hours(
            slots, diary["date"],
        )

        # Hour types summary
        self._aggregate_hour_types(
            event_report, diary.get(
                "diaryHourTypes", [],
            ), diary["date"],
        )

        return event_report

    def _calculate_total_hours(self, slots: list, date: str) -> float:
        """Calculate total worked hours from a list of slots."""
        total_time = 0.0
        for slot in slots:
            try:
                total_time += self._get_slot_hours(slot, date)
            except Exception as e:
                logger.warning(f"Skipping slot due to parsing error: {e}")
        return total_time

    def _get_slot_hours(self, slot: dict, date: str) -> float:
        """Return the hours for a single slot, using motive if available."""
        if slot and slot.get("motive"):
            return slot["motive"]["hours"]

        logger.info(
            f"Slot of date {date} doesn't have motive.\
Using `in`/`out` keys...",
        )
        return self._calculate_hours_from_in_out(slot)

    def _calculate_hours_from_in_out(self, slot: dict) -> float:
        """Calculate hours from 'in' and 'out' keys of a slot."""
        in_utc_parts = slot["in"]["utcTime"].split(" ")
        out_utc_parts = slot["out"]["utcTime"].split(" ")
        if len(in_utc_parts) < 2 or len(out_utc_parts) < 2:
            logger.warning(
                f"Skipping slot with invalid UTC times: "
                f"in='{slot['in']['utcTime']}'"
                f"out='{slot['out']['utcTime']}'",
            )
            return 0.0

        in_dt = self._parse_datetime(slot["in"]["trueDate"], in_utc_parts[1])
        out_dt = self._parse_datetime(
            slot["out"]["trueDate"], out_utc_parts[1],
        )
        return (out_dt - in_dt).total_seconds() / 3600

    def _parse_datetime(self, date_str: str, utc_offset: str) -> datetime:
        """Parse date string and UTC offset safely into datetime."""
        date_timezoned = f"{date_str}{utc_offset.zfill(3)}00"
        return datetime.strptime(
            date_timezoned,
            f"{DEFAULT_DATE_FORMAT}T%H:%M:%S%z",
        )

    def _aggregate_hour_types(
        self, event_report: dict,
        hour_types: list, date: str,
    ):
        """Aggregate hour types into the event report."""
        for hour_type in hour_types:
            hour_type_id = hour_type.get("hourTypeId")
            if hour_type_id is None:
                logger.warning(
                    f"Skipping hour type with missing 'hourTypeId' \
in diary for date {date}",
                )
                continue

            hour_type_name = self.hour_types_dict.get(
                hour_type_id, hour_type_id,
            )
            event_report[hour_type_name] = event_report.get(
                hour_type_name, 0,
            ) + hour_type.get("hours", 0)

    def export_summary_to_csv(
        self,
        summary_report: dict,
        from_date: str = "",
        to_date: str = "",
        output_path: Path = Path(
            Path.home() / "Documents/woffu/summary_reports",
        ),
        delimiter: str = ",",
    ):
        """Export the summary report to a CSV file."""
        # Convert JSON to a proper array
        reports_list = []
        reports_header = set()

        search_date_range = False
        min_date = datetime.now(tz=self._localzone)
        max_date = datetime.strptime(
            "2000-01-01", DEFAULT_DATE_FORMAT,
        ).astimezone(tz=self._localzone)

        if not from_date or not to_date:
            search_date_range = True

        else:
            min_date = datetime.strptime(
                from_date, DEFAULT_DATE_FORMAT,
            ).astimezone(tz=self._localzone)
            max_date = datetime.strptime(
                to_date, DEFAULT_DATE_FORMAT,
            ).astimezone(tz=self._localzone)

        for date, summary in summary_report.items():
            summary["date"] = date
            reports_list.append(summary)
            # Update the header in case there are new keys in the summaries
            reports_header.update(summary.keys())

            if search_date_range:
                date_dt = datetime.strptime(
                    date, DEFAULT_DATE_FORMAT,
                ).astimezone(tz=self._localzone)
                if date_dt < min_date:
                    min_date = date_dt
                if date_dt > max_date:
                    max_date = date_dt

        logger.debug(f"CSV header = {reports_header}")
        logger.debug(f"Reports list: {reports_list}")

        # Prepare the CSV filename
        csv_filename = (
            output_path
            / f"""woffu_summary_report_from_{
                min_date.strftime(
                    DEFAULT_DATE_FORMAT
                )
            }_to_{
                max_date.strftime(
                    DEFAULT_DATE_FORMAT
                )
            }.csv"""
        )
        csv_filename.parent.mkdir(parents=True, exist_ok=True)

        with open(csv_filename, "w", newline=os.linesep) as csvfile:
            # Prepare the CSV writer
            writer = csv.DictWriter(
                csvfile,
                fieldnames=sorted(reports_header),
                delimiter=delimiter,
                quoting=csv.QUOTE_MINIMAL,
            )
            writer.writeheader()

            # Write rows
            for report in reports_list:
                writer.writerow(report)

        logger.info(f"✅ CSV exported to {csv_filename}")
