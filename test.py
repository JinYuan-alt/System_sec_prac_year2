import time

CT = time.localtime()

yr = str(CT.tm_year)
day = str(CT.tm_mday)
month = str(CT.tm_mon)
date_sql=yr+"-"+"0"+month+"-"+day
print(int('07')-6)
if int(day)>=28:
    print('y')
