from threading import Timer
import time



def hello():
    print("hello, world")


t = Timer(1, hello)
t.start()

time.sleep(2)

print('hello after')

