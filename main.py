from PIL import Image
import os
from PIL.ExifTags import TAGS
from iptcinfo3 import IPTCInfo
import login
def check():
    file_path= 'static/sanitized/WIN_20240811_21_14_29_Pro.jpg'
    image=Image.open(file_path)
    exifdata = image.getexif()
    info=IPTCInfo(file_path)
    # looping through all the tags present in exifdata
    for tagid in exifdata:
        # getting the tag name instead of tag id
        tagname = TAGS.get(tagid, tagid)

        # passing the tagid to get its respective value
        value = exifdata.get(tagid)

        # printing the final result
        print(f"{tagname:25}: {value}")
    if info != None:
        print(info)
    else: print("nothing found")

def presanitize():
    file_path = 'uploads/WIN_20240811_21_14_29_Pro.jpg'
    image = Image.open(file_path)
    exifdata = image.getexif()
    info = IPTCInfo(file_path)
    xmpdata=image.getxmp()
    # looping through all the tags present in exifdata
    print(xmpdata)
    print(info)
    for tagid in exifdata:
        # getting the tag name instead of tag id
        tagname = TAGS.get(tagid, tagid)

        # passing the tagid to get its respective value
        value = exifdata.get(tagid)

        # printing the final result
        print(f"{tagname:25}: {value}")


check()
presanitize()