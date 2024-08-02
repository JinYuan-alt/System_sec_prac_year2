import time, uuid
import random
from flask_bcrypt import Bcrypt

CT = time.localtime()

bcrypt=Bcrypt()
def ud():
    rando=['integer','kilio','hashapow','gigadick','misterander89']
    for i in range(5):
        passw=random.randint(0,4)
        rand=bcrypt.generate_password_hash(rando[passw])
    len=('temp' + str(uuid.uuid4()))
    print(rand)
    print(len)

yr = str(CT.tm_year)
day = str(CT.tm_mday)
month = str(CT.tm_mon)
date_sql=yr+"-"+"0"+month+"-"+day
#print(int('07')-6)
#if int(day)>=28:
    #print('y')


ud()