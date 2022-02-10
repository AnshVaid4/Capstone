import glob, os    
import pandas as pd
df = pd.concat(map(pd.read_csv, glob.glob(os.path.join('', "*.csv"))))
df.to_csv('hell.csv',index=False)
