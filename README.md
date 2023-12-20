This is a short report on our 1st end semester project, which was a presentation on the cyber security threat, Buffer overflow attack. A significant portion of the presentation was dedicated to a step-by-step demonstration of a simple stack-based buffer overflow attack. The demo showcased the following steps:

# Vulnerable Code Example:
A vulnerable C program with a buffer that lacks proper boundary checks was presented. The code snippet demonstrated how an attacker could input a string longer than the buffer size, leading to a buffer overflow.

# Exploitation:
Using a simulated environment, the presenter demonstrated how an attacker could craft a malicious input to overwrite the return address on the stack. The modified return address directed the program to execute the injected shellcode, ultimately gaining control over the compromised system.

# Countermeasures:
The presentation concluded by addressing potential countermeasures to mitigate stack-based buffer overflow attacks. Suggestions included input validation, stack canaries, and the use of modern programming languages with built-in security features.

# Conclusion:
The presentation successfully conveyed the severity of stack-based buffer overflow attacks and provided valuable insights into their mechanics. The step-by-step demonstration effectively illustrated the vulnerability in a controlled environment, enhancing the audience's awareness of the importance of secure coding practices and robust cybersecurity measures.
