def goodbye(name, adjective):
    print('Goodbye %s, it was %s to meet you.' % (name, adjective))

import atexit
from time import sleep

atexit.register(goodbye, adjective='nice', name='Donny')

sleep(10)