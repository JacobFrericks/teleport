## Level 1:

### Description
Write a program that reads `/proc/net/tcp` every 10 seconds, and reports any new connections.

Sample Output:
```
2021-04-28 15:28:05: New connection: 192.0.2.56:5973 -> 10.0.0.5:80
2021-04-28 15:28:05: New connection: 203.0.113.105:31313 -> 10.0.0.5:80
2021-04-28 15:28:15: New connection: 203.0.113.94:9208 -> 10.0.0.5:80
2021-04-28 15:28:15: New connection: 198.51.100.245:14201 -> 10.0.0.5:80
```

Include a readme with the program that explains any dependencies and how to build and execute the program. The interview panel will build and test the program.

### Questions
Please answer all questions in response to your final solution. For example: if you complete the challenge at Level 3, the answer to "How would you prove the code is correct?" should include proving that portscans are actually blocked.

1. How would you prove the code is correct?
2. How would you make this solution better?
3. Is it possible for this program to miss a connection?
4. If you weren't following these requirements, how would you solve the problem of logging every new connection?