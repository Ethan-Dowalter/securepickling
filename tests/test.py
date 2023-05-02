import sys
sys.path.insert(0, '../src/securepickle')
from securepickle import securedump, secureload

import pandas
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import sklearn.metrics

data = pandas.read_csv("winequality-white.csv", delimiter=";")
X = data.copy()
X.drop(columns='quality', inplace=True)
y = data['quality']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=0)

myModel = RandomForestClassifier(n_estimators=50, random_state=1)
print("Start training")
myModel.fit(X_train, y_train)
predictions = myModel.predict(X_test)
print("Accuracy score:", sklearn.metrics.accuracy_score(y_test, predictions))

SECRETKEY = bytes("eShVmYq3t6w9z$C&F)J@NcQfTjWnZr4u7x!A%D*G-KaPdSgUkXp2s5v8y/B?E(H+", 'utf-8')
SECRETKEY2 = bytes("eShVmYq3t6w9z$C&F)J@NcQfTjWnZr4u7x!A%D*G-KaPdSgUkXp2s5v8y/B?E(H+", 'utf-8')

print("Writing model to pickle file")
myfile = open("test.pickle", "wb")
securedump(myModel, myfile, SECRETKEY)

print("Reading model from pickle file")
myfile2 = open("test.pickle", "rb")
data = secureload(myfile2, SECRETKEY2)

predictions = data.predict(X_test)
print("Accuracy score:", sklearn.metrics.accuracy_score(y_test, predictions))