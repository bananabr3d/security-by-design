# Packages for Electricity Meter
import time
import random

em_id = None
em_value = None

# Getter and Setter
def get_em_id() -> int|None:
    global em_id
    return em_id

def set_em_id(new_em_id: int):
    global em_id
    em_id = new_em_id

def get_em_value() -> int|None:
    global em_value
    return em_value

def set_em_value(new_em_value: int):
    global em_value
    em_value = new_em_value

# ===== Program configurations =====

# === Electricity Meter configurations ===

def initialize():
    set_em_id(new_em_id=random.randint(0, 9999999))
    set_em_value(new_em_value=random.randint(0,50000))


def count():
    set_em_value(get_em_value() + random.randint(11, 33))