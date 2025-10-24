import os
import pandas as pd
import mysql.connector
from sqlalchemy import create_engine
from mlxtend.frequent_patterns import apriori, association_rules 
import matplotlib.pyplot as plt


# ----------------------------- LOAD THE DATA SET -------------------------------

try:
        file_path = r"C:\Users\prade\Downloads\Global_Cybersecurity_Threats_2015-2024.csv"
        df = pd.read_csv(file_path)
        print("File loaded successfully.")

#------------------------------ Perform Different types of Transformations -----------------------------------

        df.drop_duplicates() #Remove Duplicate values
        print(df.head(10))
        print("-------------------------------------------------------------------------------------------")

        df.dropna() # Remove Missing values 
        print(df.head(10))

        print("----------------------------------After removing null values----------------------------------------")

        print(df.isnull().sum()) # Here we identify the missing values 

        print("----------------------------------------------------------------------------------------------------------")

       
        df['Year'] = pd.to_numeric(df['Year'], errors = 'coerce')
        df = df.dropna(subset=['Year'])
        df['Year'] = df['Year'].astype(int)






        df['Country'] = df['Country'].str.strip().str.lower()
        print(df['Country'].unique())                                                       #IT removes gthe trailing and removing white
                                                      #spaces and covert upper case to lower
                                                                              

        df.shape # It gives particular shape of rows and columns

      # Define the categorical columns based on your dataset
        categorical_columns = [
        'Attack Type',
        'Target Industry',
        'Attack Source',
        'Security Vulnerability Type',
        'Defense Mechanism Used'
         ]

# Normalize: strip whitespaces and convert to lowercase
        for col in categorical_columns:
            df[col] = df[col].astype(str).str.strip().str.lower()


        df.rename(columns={
        'Country': 'country',
        'Year': 'year',
        'Attack Type': 'attack_type',
        'Target Industry': 'target_industry',
        'Financial Loss (in Million $)': 'financial_loss_million',   # Rename the column names for easy understandability purpose
        'Number of Affected Users': 'affected_users',
        'Attack Source': 'attack_source',
        'Security Vulnerability Type': 'vulnerability_type',
        'Defense Mechanism Used': 'defense_mechanism',
        'Incident Resolution Time (in Hours)': 'resolution_time_hours'
          }, inplace=True)

        print(df)

except FileNotFoundError:
        print("File not found. Please check the path.")

except Exception as e:
        print(f"Error reading file : {e}")



# Connect to MySQL
conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password='Power@789',     # Replace with your actual MySQL password
      
)

cursor = conn.cursor()

cursor.execute("Create Database IF NOT EXISTS cybersecurity_data; ")
conn.commit()
cursor.close()
conn.close()


conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password='Power@789',     # Replace with your actual MySQL password
    database='cybersecurity_data'  # Make sure this DB exists
)

cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS THREATS (
    country VARCHAR(100),
    year INT,
    attack_type VARCHAR(100),
    target_industry VARCHAR(100),
    financial_loss_million FLOAT,
    affected_users BIGINT,
    attack_source VARCHAR(100),
    vulnerability_type VARCHAR(100),
    defense_mechanism VARCHAR(100),
    incident_resolution_time_hours FLOAT
)
''')


engine = create_engine("mysql+mysqlconnector://root:Power%40789@localhost/cybersecurity_data")

df.to_sql(name="threats", con=engine, if_exists="append", index=False)

print("Data has been Inserted successfully in to the MYSQL Database!!")


# -----------------------------------  Exploratory Data Analysis   -------------------------------------------

print(" -----------------------------------  Exploratory Data Analysis   -------------------------------------------")


print("Top 10 Countries Affected by Cyber Attacks:\n")
top_countries = df['country'].value_counts().head(10)
print(top_countries)

print("Most Common Attack types:\n")
Frequency = df['attack_type'].value_counts().head(10)
print(Frequency)


print("Yearly trends in global CyberSecurity Incidents:\n")
yearly_trends = df['year'].value_counts().sort_index().head(10)
print(yearly_trends)


print("\nTOTAL LOSS & USERS AFFECTED BY COUNTRY:")
Severity = df.groupby('country')[['financial_loss_million', 'affected_users']].sum().sort_values(by = 'financial_loss_million',
                ascending = False).head(20)
print(Severity)


print("\nCorrelation between attack type and sector targeted:")
Correlation = df.groupby(['attack_type', 'target_industry']).size().sort_values(ascending = False).head(20)
print(Correlation)

#Console Output
print("Console Output")

#Summary Statistics
print("\n******** SUMMARY STATISTICS *******")
print(df.describe(include="all").transpose())

#------------------------------- BAR GRAPHS ---------------------------------

df['country'].value_counts().head(10).plot(kind='bar')
plt.title("Top 10 Countries with Cyber Attacks")
plt.xlabel("Country")
plt.ylabel("Number of Attacks")
plt.show()

# 2. Attack types
df['attack_type'].value_counts().head(10).plot(kind='bar')
plt.title("Most Common Attack Types")
plt.xlabel("Attack Type")
plt.ylabel("Count")
plt.show()

# 3. Year-wise trend
df['year'].value_counts().sort_index().plot(kind='line')
plt.title("Year-wise Cyber Attack Trend")
plt.xlabel("Year")
plt.ylabel("Number of Incidents")
plt.show()


#_______________________________________ Association Analysis -----------------------------------------------

print("--------------------------Association Analysis -------------------------------")

assoc_df = df[['attack_type', 'target_industry']]

# Encoding both the columns attack type and target industry
assoc_encoded = pd.get_dummies(assoc_df)

# Apply Apriori Algorithm
frequent_items = apriori(assoc_encoded, min_support=0.02, use_colnames=True)

# Generate Rules
rules = association_rules(frequent_items, metric="lift", min_threshold=1)

# Display Top Rules
print(rules[['antecedents', 'consequents', 'support', 'confidence', 'lift']].head(10))





