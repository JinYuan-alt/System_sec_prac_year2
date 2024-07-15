import time


#make sure this executes when user registers and creates the passwd

time_list=[]

def register():
   CT=time.localtime()
   yr=str(CT.tm_year)
   day=str(CT.tm_mday)
   month=str(CT.tm_mon)
   time_list=[yr,int(month)+3,day]
   P_yr=str(time_list[0])
   P_month=str(time_list[1])
   P_day=str(time_list[2])
   #write some sql code to store this into database under user's username
   expiry(P_yr,P_day,P_month)

def expiry(P_yr,P_day,P_month):
   #this should retrieve the data from sql
   CT = time.localtime()
   yr = str(CT.tm_year)
   day = str(CT.tm_mday)
   month = str(CT.tm_mon)
   if P_yr == yr and P_month == month:
      if P_day == day:
        print("yes")
      else: pass
   else: pass
