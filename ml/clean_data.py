import pandas as pd
from numpy import nan

def clean_data(df):
    df.replace('?', nan, inplace=True)
    
    return df
