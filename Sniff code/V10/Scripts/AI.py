from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LinearRegression, Ridge
from sklearn.ensemble import RandomForestRegressor
from sklearn.svm import SVR
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_log_error
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler,MinMaxScaler
from sklearn.preprocessing import LabelEncoder
from sklearn.svm import SVR
from sklearn.tree import DecisionTreeRegressor
from sklearn.neighbors import KNeighborsRegressor
from sklearn.neural_network import MLPRegressor
from sklearn.model_selection import RandomizedSearchCV, train_test_split
from sklearn.linear_model import LinearRegression,RANSACRegressor,Lasso,BayesianRidge,ElasticNet
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_squared_log_error, mean_absolute_error,r2_score,mean_squared_error,accuracy_score,classification_report,confusion_matrix
from datetime import date
from datetime import *
import os
import pandas as pd
from glob import glob
import numpy as np
cwd = os.getcwd()
parent = os.path.dirname(cwd)
def getListOfFiles(dirName):
    listOfFile = os.listdir(dirName)# create a list of file and sub directories 
    allFiles = list()# names in the given directory 
    for entry in listOfFile:# Iterate over all the entries
        fullPath = os.path.join(dirName, entry)# Create full path
        if os.path.isdir(fullPath):# If entry is a directory then get the list of files in this directory
            allFiles = allFiles + getListOfFiles(fullPath)
        else:
            allFiles.append(fullPath)      
    return allFiles
dirAgg=parent+"\data\\aggregated"
listOfFilesAgg = getListOfFiles(dirAgg)
li=list()
forecast_out = 1 # forcasting out 5% of the entire dataset
#print(forecast_out)
for file in listOfFilesAgg:
    data = pd.read_csv(file)
    li.append(data)
df = pd.concat(li, axis=0, ignore_index=True)
df['label'] = df['frequency'].shift(-forecast_out)
scaler = StandardScaler()
X = np.array(df.drop(['label','ModeS_IP','ModeD_IP'], axis=1))
scaler.fit(X)
X = scaler.transform(X)
X_Predictions = X[-forecast_out:] # data to be predicted
X = X[:-forecast_out] # data to be trained
df.dropna(inplace=True)
y = np.array(df['label'])
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=42)
rf = RandomForestRegressor()
rf.fit(X_train, y_train)
rf_confidence = rf.score(X_test, y_test)
last_date = df.index[-1] #getting the lastdate in the dataset
last_unix = last_date.timestamp() #converting it to time in seconds
one_day = 86400 #one day equals 86400 seconds
next_unix = last_unix + one_day # getting the time in seconds for the next day
forecast_set = rf.predict(X_Predictions) # predicting forecast data
df['Forecast'] = np.nan
for i in forecast_set:
    next_date = datetime.fromtimestamp(next_unix)
    next_unix += 86400
    df.loc[next_date] = [np.nan for _ in range(len(df.columns)-1)]+[i]
plt.figure(figsize=(18, 10))
df['frequency'].plot()
df['Forecast'].plot()
plt.legend(loc=4)

plt.show()