import time
import random
#initiates with rdm value between 0 and 50000, adds every 900 sec a rdm value between 1000 and 3000
class zaehler:
    def __init__(self):
        self.zaehler = 0

    def count(self):
        self.zaehler = random.randint(0,50000)
        while True:
            time.sleep(900)
            self.zaehler += random.randint(1000, 3000)