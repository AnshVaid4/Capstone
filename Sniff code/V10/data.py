import glob, os    
import pandas as pd
import numpy as np
from sklearn import preprocessing
import matplotlib.pyplot as plt
import seaborn as sns
df = pd.concat(map(pd.read_csv, glob.glob(os.path.join('', "*.csv"))))
df.to_csv('hell.csv',index=False)

df = pd.read_csv('/content/2022-02-10.csv')
Encoder1 = preprocessing.LabelEncoder()
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
  data = data.reindex(columns=['DateTime','Source1','Source2','Source3','Source4','dest1','dest2','dest3','dest4','Sourceport','Destinationport','OS','Flags','Protocol','TTL','Length','Comments'])
  for item in ["1","2","3","4"]:
    feature="Source"+item
    data[feature]=pd.to_numeric(data[feature], downcast='unsigned')
  for item in ["1","2","3","4"]:
    feature="dest"+item
    data[feature]=pd.to_numeric(data[feature], downcast='unsigned')
  return data

def unfragment(data):
  for item in ["1","2","3","4"]:
    feature="Source"+item
    data[feature] = data[feature].astype(str)
  for item in ["1","2","3","4"]:
    feature="dest"+item
    data[feature] = data[feature].astype(str)
  data['Source1'].str.cat(data[['Source2','Source3','Source4']], sep='.')
  data["dest1"].str.cat(data[['dest2','dest3','dest4']], sep='.')
  #data.drop(['Source2','Source3','Source4','dest2','dest3','dest4'])
  data.rename(columns={'Source1': 'Sourceip', 'dest1': 'Destinationip'}, inplace=True)
  data = data.reindex(columns=['DateTime','Sourceip','Destinationip','Sourceport','Destinationport','OS','Flags','Protocol','TTL','Length','Comments'])
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

 


df=cleandata(df)
df=fragment(df)
df=labelize(df)
df=unlabelize(df)
df=unfragment(df)
