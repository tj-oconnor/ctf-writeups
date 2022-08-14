f = open('dis.txt','r')
flag =''
for line in f.readlines():
    if '""' not in line:
       flag+=line.split('"')[1].split('"')[0]
print(flag)