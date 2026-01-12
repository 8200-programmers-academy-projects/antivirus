import json, os

DEFAULT_HISTORY = []
HISTORY_FILE_PATH = "history.json"


class Result:
    def __init__(
        self,
        filename: str = "",
        malicious: int = 0,
        suspicious: int = 0,
        undetected: int = 0,
        unsupported: int = 0,
    ):
        self.filename = filename
        self.malicious = malicious
        self.suspicious = suspicious
        self.undetected = undetected
        self.unsupported = unsupported

    @staticmethod
    def from_json(data: dict) -> Result:
        res = Result()
        res.filename = data["filename"]
        res.malicious = data["malicious"]
        res.suspicious = data["suspicious"]
        res.undetected = data["undetected"]
        res.unsupported = data["unsupported"]
        return res

    def to_json(self) -> dict:
        return {
            "malicious": self.malicious,
            "filename": self.filename,
            "suspicious": self.suspicious,
            "undetected": self.undetected,
            "unsupported": self.unsupported,
        }


# deletes/creates file with history
def reset_history():
    with open(HISTORY_FILE_PATH, "w") as f:
        f.write(json.dumps(DEFAULT_HISTORY))


class History:
    def __init__(self):
        self._results: list[Result]
        if not os.path.exists(HISTORY_FILE_PATH):
            reset_history()
        with open(HISTORY_FILE_PATH, "r") as f:
            data = json.loads(f.read())
            if not isinstance(data, list):
                reset_history()

        with open(HISTORY_FILE_PATH, "r") as f:
            data = json.loads(f.read())
            self._results = []
            for i in data:
                if not isinstance(i, dict):
                    continue
                result = Result.from_json(i)
                self._results.append(result)

    def add_result(self, res: Result):
        self._results.append(res)

    def get_results(self) -> list[Result]:
        return self._results

    def save(self):
        with open(HISTORY_FILE_PATH, "w") as f:
            results = []
            for i in self._results:
                results.append(i.to_json())

            data = json.dumps(results)
            f.seek(0)
            f.write(data)
