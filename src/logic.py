from .storage import History, Result, VirusTotalApiStorage
from .api import VirusTotalApi, ErrorNotAuthorized
import os
import hashlib


def sha256_file(path: str, chunk_size: int = 8192) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


class Usecase:
    def __init__(
        self,
        args: list[str],
        api: VirusTotalApi,
        history: History,
        key_storage: VirusTotalApiStorage,
    ):
        self.args = args
        self.api = api
        self.history = history
        self.api_key_storage = key_storage

    def get_history(self):
        history = History()
        results = history.get_results()
        if len(results) == 0:
            print("History is clear")
            exit()

        print("History (m-maliciois,  s-suspicious, ud-undetected, us-unsupported):")

        for i in history.get_results():
            print(
                f"{i.filename} m:{i.malicious} s:{i.suspicious} ud:{i.undetected} us:{i.unsupported}"
            )

    def set_api_key(self):
        if len(self.args) != 1:
            print("set api key takes one argument: [virus total api key]")
            return

        self.api_key_storage.set_key(self.args[0])

    def check_file(self):
        if not os.path.exists(self.args[0]):
            print("file doesn't exists")
            return

        """
        analysis_id = self.api.upload_file_for_check(self.args[0])
        print(f"uploaded file for check, analysis id: {analysis_id}")

        analysis = self.api.get_analysis_by_id(analysis_id)

        print(f"its analysis: {analysis}")

        """
        try:
            found, analysis = self.api.get_analysis_info_by_hash(
                sha256_file(self.args[0])
            )
        except ErrorNotAuthorized:
            print("Api key not set, or it's wrong (Not Authorized)")
            return

        if found:
            if analysis.is_completed:
                print(f"This file is already analysed, results: ")
                analysis.print()
            else:
                print(f"This file is being analysed, status: {analysis.status}")
                print("wait some time and try again")
            return
        else:
            print("File not analysed, starting analysis")
            analysis_id = self.api.upload_file_for_check(self.args[0])

            try:
                while True:
                    analysis = self.api.get_analysis_by_id(analysis_id)
                    if analysis.is_completed:
                        print("results:")
                        analysis.print()
                        res = Result(
                            filename=os.path.basename(self.args[0]),
                            malicious=analysis.malicious,
                            suspicious=analysis.suspicious,
                            undetected=analysis.undetected,
                            unsupported=analysis.unsupported,
                        )
                        self.history.add_result(res)
                        self.history.save()

                        break
                    else:
                        print(f"Analysis is processing, status: {analysis.status}")
                        input("Press ENTER to check status ( ctrl + c to exit )")
                        continue
            except KeyboardInterrupt:
                print("exiting.. ( you can check status with same command )")
