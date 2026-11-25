"""A stand-in for a model client. The benchmark fixture makes no network calls."""
import os

MODEL_KEY = os.environ.get("MODEL_API_KEY", "")


class Client:
    def complete(self, messages, tools=None):
        raise NotImplementedError("connect a model provider here")


client = Client()
