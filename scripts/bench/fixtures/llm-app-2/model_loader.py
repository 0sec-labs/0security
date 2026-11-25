"""Loads the ranking model at start-up. Planted flaws are intentional."""
import json
import pickle
import urllib.request

WEIGHTS_URL = "https://models.bench-example.test/ranker/latest.pkl"
CONFIG_URL = "https://models.bench-example.test/ranker/config.json"


def download_weights(path: str = "ranker.pkl") -> str:
    urllib.request.urlretrieve(WEIGHTS_URL, path)
    return path


def load_ranker(path: str):
    with open(path, "rb") as handle:
        return pickle.load(handle)


def load_config() -> dict:
    with urllib.request.urlopen(CONFIG_URL, timeout=10) as response:
        return json.loads(response.read())
