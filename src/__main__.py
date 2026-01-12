import sys
from .storage import api_key, history
from .api import virus_total
from .logic import Usecase

if __name__ == "__main__":
    call = sys.argv[0]
    args = sys.argv[1:]

    use_docs = f"""
    Use:
    - {call} [filename] optional[--nocache no local cache, -a all info]
    - {call} set_api_key [virus total api key]
    - {call} history
    - {call} help
    """

    if len(args) == 0 or args[0].lower() in ("help", "--help"):
        print(use_docs)
        exit()

    api_key_storage = api_key.VirusTotalApiStorage()
    history_storage = history.History()

    virus_total_api = virus_total.VirusTotalApi(api_key_storage)
    usecase = Usecase(args, virus_total_api, history_storage, api_key_storage)

    if args[0] == "set_api_key":
        usecase.args = args[1:]
        usecase.set_api_key()
    elif args[0] == "history":
        usecase.args = args[1:]
        usecase.history()
    else:
        usecase.check_file()
