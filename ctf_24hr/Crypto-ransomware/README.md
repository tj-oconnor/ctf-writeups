## Question

There was a ransomware attack at your company! The security team managed to get the malicious script, but it seems to be encrypted. You think it might have something to do with XOR. Can you help decrypt it?

Files 
 - [ransomaware.py](ransomaware.py)

## Solution

Since the solution likely contained some python3 codee, we used [xortool](https://github.com/hellman/xortool) to guess the possible key. Checking the results produced the flag. 

```
~/workspace $ xortool -l 16 -o ransomaware.py 
~/workspace $ cat xortool_out/*.out | grep -a -i FLAG

# FLAG{1_t0u6ht_x0r_w45_53cur3}
```
