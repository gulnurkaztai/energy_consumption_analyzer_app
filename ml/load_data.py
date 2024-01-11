import pandas as pd


dataset_path = '../data/household_power_consumption.txt'

def load_data(dataset_path):
    df = pd.read_csv(dataset_path, sep=';', header=0, low_memory=False, infer_datetime_format=True, parse_dates={'datetime':[0,1]}, index_col=['datetime'])
    return df
