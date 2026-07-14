import math

MAX = 500
MIN = 100
STEEP = 0.2
BASE = 3

def points(sev, steep=STEEP):
    x = sev - BASE
    if x <= 0:
        return MAX
    p = MAX - steep * math.log(x) * (MAX - MIN)
    return int(round(max(MIN, p)))

if __name__ == "__main__":
    for sev in [139, 27, 13, 3]:
        print(sev, points(sev))
