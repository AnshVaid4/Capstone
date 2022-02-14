import pandas as pd
import numpy as np
from sklearn import preprocessing
import matplotlib.pyplot as plt
import seaborn as sns
import random
import time
from datetime import datetime,timedelta
from scipy import stats
df = pd.concat(map(pd.read_csv, glob.glob(os.path.join('', "*.csv"))))
df.to_csv('hell.csv',index=False)

df = pd.read_csv('/content/2022-02-10.csv')
Encoder1=preprocessing.LabelEncoder()
Encoder2=preprocessing.LabelEncoder()
Encoder3=preprocessing.LabelEncoder()
Encoder4=preprocessing.LabelEncoder()

def cleandata(data):
  data.columns = ['Sourceip','Destinationip','Sourceport','Destinationport','OS','Flags','Protocol','TTL','Length','Date','Time','Comments']
  data = data[data.Sourceip.str.contains('Sourceip') == False]
  data.dropna(subset=['Sourceip','Sourceport'], inplace=True)
  data["DateTime"]=data.Date+ " "+data.Time
  if(data['DateTime'].values[0].find("-")>-1):
    data['DateTime'] = pd.to_datetime(data['DateTime'], format='%d-%m-%Y %H:%M:%S')
  elif(data['DateTime'].values[0].find("/")>-1):
    data['DateTime'] = pd.to_datetime(data['DateTime'], format='%Y/%m/%d %H:%M:%S')
    data['DateTime'] = data['DateTime'].dt.strftime('%d-%m-%Y %H:%M:%S')
  data.drop(["Date","Time"],axis=1,inplace=True)
  values = {"Comments": "[SAFE]", "Flags": "NO"}
  data.fillna(value=values,inplace=True)
  data = data.reindex(columns=['DateTime','Sourceip','Destinationip','Sourceport','Destinationport','OS','Flags','Protocol','TTL','Length','Comments'])
  for feature in ["Sourceport","Destinationport","TTL","Length"]:
    data[feature]=pd.to_numeric(data[feature], downcast='unsigned')
  return data

def fragment(data):
  data[['Source1','Source2','Source3','Source4']]=df.Sourceip.str.split('.', expand=True)
  data[['dest1','dest2','dest3','dest4']]=df.Destinationip.str.split('.', expand=True)
  data.drop(['Sourceip','Destinationip'],axis=1,inplace=True)
  if("Total" not in data.columns.tolist()):
    cols=['DateTime','Source1','Source2','Source3','Source4','dest1','dest2','dest3','dest4','Sourceport','Destinationport','OS','Flags','Protocol','TTL','Length','Comments']
    data = data.reindex(columns=cols)
  for item in ["1","2","3","4"]:
    feature="Source"+item
    data[feature]=pd.to_numeric(data[feature], downcast='unsigned')
  for item in ["1","2","3","4"]:
    feature="dest"+item
    data[feature]=pd.to_numeric(data[feature], downcast='unsigned')
  return data

def unfragment(data):
  for item in ["1","2","3","4"]:
    feature="dest"+item
    data[feature] = data[feature].astype(str)
  for item in ["1","2","3","4"]:
    feature="Source"+item
    data[feature] = data[feature].astype(str)
  data["Source1"]=data["Source1"]+"."+data["Source2"]+"."+data["Source3"]+"."+data["Source4"]
  data["dest1"]=data["dest1"]+"."+data["dest2"]+"."+data["dest3"]+"."+data["dest4"]
  data.drop(['Source2','Source3','Source4','dest2','dest3','dest4'],axis=1,inplace=True)
  data.rename(columns={'Source1': 'Sourceip', 'dest1': 'Destinationip'}, inplace=True)
  if("Total" not in data.columns.tolist()):
    cols=['DateTime','Sourceip','Destinationip','Sourceport','Destinationport','OS','Flags','Protocol','TTL','Length','Comments']
    data = data.reindex(columns=cols)
  return data

def labelize(data):
  data["Comments"]=Encoder1.fit_transform(data["Comments"])
  data["Protocol"]=Encoder2.fit_transform(data["Protocol"])
  data["Flags"]=Encoder3.fit_transform(data["Flags"])
  data["OS"]=Encoder4.fit_transform(data["OS"])
  return data

def unlabelize(data):
  data["Comments"]=Encoder1.inverse_transform(data["Comments"])
  data["Potocol"]=Encoder2.inverse_transform(data["Protocol"])
  data["Flags"]=Encoder3.inverse_transform(data["Flags"])
  data["OS"]=Encoder4.inverse_transform(data["OS"])
  return data

def genpie(data):
  if(df["Comments"].dtypes!="object"):
    data=unlabelize(data)
  values=dict(data["Comments"].value_counts())
  pie_val=dict()
  if ("[SAFE]" in  list(values.keys())):
    pie_val["SAFE"]=values["[SAFE]"]
    del values['[SAFE]']
  if ("[PORT]" in  list(values.keys())):
    pie_val["PORT"]=values["[PORT]"]
    del values['[PORT]']
  if ("[IP]" in  list(values.keys())):
    pie_val["IP"]=values["[IP]"]
    del values['[IP]']
  if ("[FLAG]" in  list(values.keys())):
    pie_val["FLAG"]=values["[FLAG]"]
    del values['[FLAG]']
  if (len(values)>0):
    pie_val["MULTIPLE"]=0
    for key in values:
      pie_val["MULTIPLE"]=pie_val["MULTIPLE"]+values[key]
  exp=list()
  for x in range(len(pie_val)):
    exp.append(0.1)  
  colors = sns.color_palette('pastel')
  plt.pie(pie_val.values(), labels = pie_val.keys(), colors = colors, autopct='%.0f%%',explode = exp, shadow = True)
  plt.legend(title = "Packets",bbox_to_anchor =(0.75,0.75))
  plt.show()

def dataextrC(dic):
  key=list(dic.keys())
  internal_keys= list(dic[key[0]].keys())
  hour=[]
  for tup in internal_keys:
    hour.append(tup[0])
  hour=list(set(hour))
  act=dict()
  for time in hour:
    val=dict()
    for value in ["SAFE","PORT","IP","FLAG"]:
      if ((time,f"[{value}]") in internal_keys):
        val[f"{value}"]=dic[key[0]][(time,f"[{value}]")]
        del dic[key[0]][(time,f"[{value}]")]
      else: val[f"{value}"]=0
    temp=[]
    if (len(dic[key[0]])>0):
      val["MULTIPLE_Com"]=0
      for multi in internal_keys:
        temp.append(multi[1])
      temp=list(set(temp))
      for hold in internal_keys:
        if(time==hold[0] and hold[1] in temp and hold[1] not in ["[FLAG]","[IP]","[SAFE]","[PORT]"]):
           val["MULTIPLE_Com"]=val["MULTIPLE_Com"]+dic[key[0]][(time,hold[1])]
    else:val["MULTIPLE_Com"]=0
    act[time]=val
    del val
  data=pd.DataFrame.from_dict(act).T
  return data

def dataextrF(dic):
  key=list(dic.keys())
  internal_keys= list(dic[key[0]].keys())
  hour=[]
  for tup in internal_keys:
    hour.append(tup[0])
  hour=list(set(hour))
  act=dict()
  for time in hour:
    val=dict()
    for value in ["F","A","P","R","S","U","N"]:
      if ((time,f"{value}") in internal_keys):
        val[f"Flag_{value}"]=dic[key[0]][(time,f"{value}")]
        del dic[key[0]][(time,f"{value}")]
      else: val[f"Flag_{value}"]=0
    temp=[]
    if (len(dic[key[0]])>0):
      val["Flag_Multi"]=0
      for multi in internal_keys:
        temp.append(multi[1])
      temp=list(set(temp))
      for hold in internal_keys:
        if(time==hold[0] and hold[1] in temp and hold[1] not in ["F","A","P","R","S","U","N"]):
           val["Flag_Multi"]=val["Flag_Multi"]+dic[key[0]][(time,hold[1])]
    else:val["Flag_Multi"]=0
    act[time]=val
    del val
  data=pd.DataFrame.from_dict(act).T
  #data.columns=['HOUR','SAFE','PORT','IP','FLAG','MULTIPLE']
  return data

def dataextrP(dic):
  key=list(dic.keys())
  internal_keys= list(dic[key[0]].keys())
  hour=[]
  for tup in internal_keys:
    hour.append(tup[0])
  hour=list(set(hour))
  act=dict()
  for time in hour:
    val=dict()
    for value in ["TCP","UDP"]:
      if ((time,f"{value}") in internal_keys):
        val[f"Proto_{value}"]=dic[key[0]][(time,f"{value}")]
        del dic[key[0]][(time,f"{value}")]
      else: val[f"Proto_{value}"]=0
    act[time]=val
    del val
  data=pd.DataFrame.from_dict(act).T
  return data

def dataextrO(dic):
  key=list(dic.keys())
  internal_keys= list(dic[key[0]].keys())
  hour=[]
  for tup in internal_keys:
    hour.append(tup[0])
  hour=list(set(hour))
  act=dict()
  for time in hour:
    val=dict()
    for value in ["O","W","L","M"]:
      if ((time,f"{value}") in internal_keys):
        val[f"OS_{value}"]=dic[key[0]][(time,f"{value}")]
        del dic[key[0]][(time,f"{value}")]
      else: val[f"OS_{value}"]=0
    act[time]=val
    del val
  data=pd.DataFrame.from_dict(act).T
  return data


def aggr(data):
  data["hour"] = data["DateTime"].dt.hour
  grouped = data.groupby('hour').agg(
       frequency=('Comments', 'count'),
       ModeS_IP=('Sourceip',lambda x: stats.mode(x)[0]),
       ModeD_IP=('Destinationip',lambda x: stats.mode(x)[0]),
       ModeS_Port=('Sourceport',lambda x: stats.mode(x)[0]),
       ModeD_Port=('Destinationport',lambda x: stats.mode(x)[0]),
       Mode_TTL=('TTL',lambda x: stats.mode(x)[0]),
       length=('Length',lambda x: stats.mode(x)[0])
       )
  grouped1=data.groupby(['hour','Comments'])[['Sourceip']].count()
  grouped1.columns = ['Packet']
  grpComm=dataextrC(grouped1.to_dict())
  grouped2=data.groupby(['hour','Flags'])[['Sourceip']].count()
  grouped2.columns = ['Packet']
  grpFlag=dataextrF(grouped2.to_dict())
  join_df_1= pd.merge(grpComm, grpFlag,right_index=True, left_index=True, how='inner')
  grouped3=data.groupby(['hour','Protocol'])[['Sourceip']].count()
  grouped3.columns = ['Packet']
  grpPro=dataextrP(grouped3.to_dict())
  grouped4=data.groupby(['hour','OS'])[['Sourceip']].count()
  grouped4.columns = ['Packet']
  grpOS=dataextrO(grouped4.to_dict())
  join_df_2= pd.merge(grpPro, grpOS,right_index=True, left_index=True, how='inner')
  join_df_inter= pd.merge(join_df_1, join_df_2,right_index=True, left_index=True, how='inner')
  join_df_final=pd.merge(join_df_inter,grouped,right_index=True, left_index=True, how='inner')
  return join_df_final

df=cleandata(df)
#df=fragment(df)
#df=labelize(df)
#df=unlabelize(df)
#df=unfragment(df)
#genpie(df)
#df.head()
ag=aggr(df)