# How to defeat a dragon

## Description

Dragonairre,the dragon with the hexadecimal head has attacked the village to take revenge on his last defeat,we need to get the ultimate weapon.
Flag Format : SHELLCTF{}.

## Files

* [vault](vault)

## Solution

```
0000126c  751a               jne     0x1288

0000126e  488d4590           lea     rax, [rbp-0x70 {var_78}]
00001272  4889c6             mov     rsi, rax {var_78}
00001275  488d3dbc0d0000     lea     rdi, [rel data_2038]  {"Yeahh!!,we did it,We defeated th…"}
0000127c  b800000000         mov     eax, 0x0
00001281  e8fafdffff         call    printf
```

```
$ ./vault                                                       
Help us defeat the dragon!! Enter the code:69420
Yeahh!!,we did it,We defeated the dragon.Thanks for your help here's your reward : SHELLCTF{5348454c4c4354467b31355f523376337235316e675f333473793f7d}#  

$ unhex 5348454c4c4354467b31355f523376337235316e675f333473793f7d
SHELLCTF{15_R3v3r51ng_34sy?}                        
```