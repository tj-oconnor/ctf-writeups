## Question

Can you detect fraud in bank transactions? Here is the problem: we have a dataset that contains 50 examples of transactions that are labeled according to whether they are fraud or not. For each of them, we will send you the list of features that we collected and its label.

Here are the features we are talking about, in order:

Amount of money being transferred
Number of past failed transactions (originator account)
Number of past failed transactions (destination account)
Geographical distance between originator and destination
Number of transactions per week (originator account)
We will send you 10 new unlabeled transactions. Your goal is to detect which of them are fraud using the dataset as a reference. You have 10 seconds from when you receive the data to send back your answer.

nc 0.cloud.chals.io 32947

## Data 

```
~/workspace $ nc 0.cloud.chals.io 32947 
==========================================================
Transactions dataset:
[4943, 48, 5, 8871, 32] Fraud: yes
[25585, 46, 28, 8458, 40] Fraud: yes
[3280, 7, 20, 4661, 1] Fraud: no
[40085, 19, 45, 1596, 1] Fraud: no
<..snipped..>
==========================================================
id[features]:
0 [42023, 0, 42, 9740, 31]
1 [31019, 49, 15, 8843, 29]
2 [35374, 47, 21, 8824, 37]
3 [32526, 38, 3, 7650, 38]
4 [19698, 39, 5, 7833, 34]
5 [44704, 46, 40, 8956, 30]
6 [30928, 37, 1, 485, 5]
7 [3065, 6, 45, 1051, 5]
8 [2615, 5, 4, 1851, 18]
9 [12026, 2, 34, 2003, 18]
Which transactions are fraud? (answer format: [id0, id1, id2...], ex: [0, 3, 7])
```

## Solution

Since, this contains training and testing data, we though this might be a good approach for machine learning. We approached this by reading in the training features, training labels and then used a Random Forrest classifer to develop a prediction model. We then read in the testing features and predicted the result for each possible fraud case. 


```python
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

```

Running this yields the flag:

```
==========================================================
Good job! Here is your flag: FLAG{H0w_C4n_u_l34Rn_fr0m_ur_Mi5t4K3s_iF_u_c4nT_r3mEMb3r_Th3m}
```
