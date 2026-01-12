import requests, os, time
from ..storage.api_key import VirusTotalApiStorage
from typing import Tuple

CHECK_ANALYSIS_ENDPOINT = "https://www.virustotal.com/api/v3/analyses"
FILES_ENDPOINT = "https://www.virustotal.com/api/v3/files"


class ErrorNotAuthorized(Exception):
    pass


class ErrorCannotSendRequest(Exception):
    pass


class ErrorApiError(Exception):
    pass


class FileAnalysis:
    def __init__(self, status: str, stats: dict = {}):
        self.is_completed: bool = status == "completed"
        self.status = status
        self.malicious = stats.get("malicious", "")
        self.suspicious = stats.get("suspicious", "")
        self.undetected = stats.get("undetected", "")
        self.unsupported = stats.get("type-unsupported", "")

    def __str__(self) -> str:
        return f"completed: {self.is_completed}, status: {self.status}, m:{self.malicious}, s: {self.suspicious}, ud: {self.undetected}, us: {self.unsupported}"

    def print(self):
        print(f"malicious: {self.malicious}")
        print(f"suspicious: {self.suspicious}")
        print(f"undetected: {self.undetected}")
        print(f"unsupported: {self.unsupported}")


class VirusTotalApi:
    def __init__(self, key_storage: VirusTotalApiStorage):
        self.key_storage = key_storage

    def get_default_headers(self) -> dict:
        headers = {
            "accept": "application/json",
            "x-apikey": self.key_storage.get_key(),
        }
        return headers

    def upload_file_for_check(self, file_path: str) -> str:
        """
        returns analysis id
        """
        filename = os.path.basename(file_path)

        with open(file_path, "rb") as f:
            files = {"file": (filename, f)}

            try:
                response = requests.post(
                    FILES_ENDPOINT, headers=self.get_default_headers(), files=files
                )
            except Exception:
                raise ErrorCannotSendRequest

            if response.status_code in (401, 403):
                raise ErrorNotAuthorized

        analysis_id = ""
        try:
            res_json = response.json()
            analysis_id = res_json["data"]["id"]
        except Exception:
            print(response.text)
            raise ErrorApiError
        return analysis_id

    def get_analysis_info_by_hash(
        self, sha256_file_hash: str
    ) -> Tuple[bool, FileAnalysis]:
        """
        returns
        - was the file found
        - if found, its analysis
        """

        response = requests.get(
            f"{FILES_ENDPOINT}/{sha256_file_hash}", headers=self.get_default_headers()
        )

        if response.status_code in (401, 403):
            raise ErrorNotAuthorized

        if response.status_code == 404:
            return False, FileAnalysis("")

        try:
            res_json = response.json()
            last_analysis_stats = res_json["data"]["attributes"]["last_analysis_stats"]

            if "last_analysis_date" not in res_json["data"]["attributes"]:
                return True, FileAnalysis("not completed")

            res = FileAnalysis("completed", last_analysis_stats)
        except Exception:
            return False, FileAnalysis("")
        return True, res

    def get_analysis_by_id(self, analysis_id: str) -> FileAnalysis:
        response = requests.get(
            f"{CHECK_ANALYSIS_ENDPOINT}/{analysis_id}",
            headers=self.get_default_headers(),
        )

        if response.status_code in (401, 403):
            raise ErrorNotAuthorized

        try:
            res_json = response.json()
            attrs = res_json["data"]["attributes"]
            stats = attrs["stats"]
            res = FileAnalysis(attrs["status"], stats)
        except Exception:
            raise ErrorApiError
        return res
