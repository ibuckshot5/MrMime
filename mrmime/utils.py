import math
import random

import geopy
import geopy.distance


def jitter_location(lat, lng, maxMeters=3):
    origin = geopy.Point(lat, lng)
    b = random.randint(0, 360)
    d = math.sqrt(random.random()) * (float(maxMeters) / 1000)
    destination = geopy.distance.distance(kilometers=d).destination(origin, b)
    return destination.latitude, destination.longitude
