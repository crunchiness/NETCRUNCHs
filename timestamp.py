__author__ = 'crunch'
from datetime import datetime


class TimeStamp:
    def __init__(self, timestamp):
        self.value = timestamp

    def get_datetime(self):
        return datetime.fromtimestamp(self.value)

    def get_seconds(self):
        return int(self.value)

    def get_ms(self):
        return int(self.value*1000)