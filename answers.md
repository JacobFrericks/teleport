Please answer all questions in response to your final solution. For example: if you complete the challenge at Level 3, the answer to "How would you prove the code is correct?" should include proving that portscans are actually blocked.

1. How would you prove the code is correct?

   I have created Unit tests to verify that the code does what it is supposed to do.

2. How would you make this solution better?

   I would suggest saving the dictionary that contains the IPs into a database (or even a file), so you can reboot the program without issues

3. Is it possible for this program to miss a connection?

   Yes, if the program is stopped and restarted, it is possible to not only miss a new connection, but also a port scan

4. If you weren't following these requirements, how would you solve the problem of logging every new connection?

   I love the idea of using a docker container for this. Especially since it will be tested outside my environment. It would also save some future work if my computer crashed. 

   However, if I were running this only on my computer, and only for a short time, I wouldn't use the container just to keep things simple.

5. Why did you choose `x` to write the build automation?

   I chose to use a makefile because it can be used across multiple operating systems and is very easy to read. It is also easy to edit and update.

6. Is there anything else you would test if you had more time?

   I would write an integration test. I was unable to send TCP packets to this program, and an integration test would be a reproducible way to do that.

7. What is the most important tool, script, or technique you have for solving problems in production? Explain why this tool/script/technique is the most important.

   kubectl. It has a variety of options to view possible issues inside kubernetes, and it can give a status on different containers and their issues.

8. If you had to deploy this program to hundreds of servers, what would be your preferred method? Why?

   It depends on how those servers are set up. If they are set up to be in a kubernetes cluster, then using that tool would be best since kubernetes can manage all of those servers itself. 
   If that's not an option, however, then we have two options. We can attempt to do this ourselves, or we can ask the admins to do this for us. Each has their own advantages and disadvantages.
   If we ask the admins to do it, then we rely on their expertise on Docker (or at least, running a script we provide them). We also rely on their priorities, and hope we end up near the top.
   If we do it ourselves, then we need to manage and deploy the containers ourselves (probably by a script, if we can manage that).

9. What is the hardest technical problem or outage you've had to solve in your career? Explain what made it so difficult?

   Getting all developers onto Workload Identity. Since we have hundreds of projects, each one needed to be transferred to workload identity. Unfortunately, no matter how often we tell some people how high of a priority it should be, it just ends up on the back of the list. So I end up having to create pull requests to our shared vpc environment as well as each repository (as well as prod devs to merge that PR)