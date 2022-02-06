from pwn import *
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

p = remote('0.cloud.chals.io', 32947)

p.recvuntil(b"Transactions dataset:")

train_fet = open('training_features.txt', 'w')
train_lab = open('training_labels.txt', 'w')

while True:
    res = p.recvline()
    if b'==========================================================' in res:
        break
    if (len(res) > 2):
        label = res.split(b'Fraud:')[1].replace(b'\n', b'').replace(b' ', b'')
        feature = res.split(b']')[0].replace(b'[', b'')
        print(feature, label)
        train_fet.write(feature.decode()+"\n")
        train_lab.write(label.decode()+"\n")

train_fet.close()
train_lab.close()

p.recvuntil(b"id[features]:\n")

testing_fet = open('testing_features.txt', 'w')

while True:
    res = p.recvline()
    if b'Which transactions are fraud?' in res:
        break
    feature = res.split(b"[")[1].split(b"]")[0]
    testing_fet.write(feature.decode()+"\n")

testing_fet.close()

training_fet = pd.read_csv('training_features.txt', header=None)
training_lab = pd.read_csv('training_labels.txt', header=None)
testing_fet = pd.read_csv('testing_features.txt', header=None)

clf = RandomForestClassifier()
clf.fit(training_fet, training_lab[0])

fraud_transactions = []

item_cnt = 0
for prediction in clf.predict_proba(testing_fet):
    if (prediction[0] < prediction[1]):
        fraud_transactions.append(item_cnt)
    item_cnt += 1

print("Detected", str(fraud_transactions))
p.sendline(str(fraud_transactions).encode())
p.interactive()
