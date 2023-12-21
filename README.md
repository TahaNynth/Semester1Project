This is a short report on our 1st end semester project, which was a presentation on the cyber security threat, Buffer overflow attack. The presentation was divided into: Details of the vulnerability and how it arises, a detailed exploitation of the vulnerability, Details about the tools used to exploit the vulnerability (their usage ([and] a demo if possible), and tips o how to patch the said vulnerability.

# BUFFER-OVERFLOW
# Details of Vulnerability and How it arises:

# 1. Buffer OverFlow:
A buffer overflow is a type of software vulnerability that occurs when a program writes more data to a block of memory, or buffer, than it was allocated for. This can lead to the overflow of adjacent memory space, potentially causing unintended consequences such as crashes, unpredictable behavior, or even unauthorized access to the system.
*For Example:* a programmer declares array of integer 4 for string input, as in string last bit is left for null character \0 .
> | A | B | C | \0|
> 
Now an attacker overflows the buffer by entering 4 characters:
> | W | X | Y | Z |
# 2. Languages vulnerable to this Attack:
- In *Python* and *Java* it is impossible to have buffer overflow because they use Run Time Bounds Checking( How Many Spaces Left.).
- There is performance cost for te extra code we are running everytime we want to insert an element into the array .Thus *C* and *C++* hae chosen not to use runtime bounds checking by default.
# 3. Damage it can cause:
The extra data that the attacker over writes is called *return address*. Following can be the results of buffer overflow:
- Normally buffer overflow results in a **Program Crash**. Because return address does not points to a valid program instruction.
  > Just like package addressed to a place that does not exists.
- If someone were able to control the contents of return address they can litterally do anything . That return address could be anything:
  1. Reading a file
  2. Dumping a Password
  3. Starting a shell
  4. Eexecuting a malicious code etc.
# 4. How it Arises:
*1. Input with Excessive Data:* An attacker provides input that exceeds the allocated space in a program's buffer. This input can come from user inputs, network data, or other external sources.
>
*2. Lack Of Input Validation:* The program fails to check the size of the input data against the size of the buffer. As a result, when the input is copied into the buffer, it overflows beyond the allocated memory.
>
*3. Overwriting Adjacent Memory:* The excess data overwrites adjacent memory locations, including critical data structures like return addresses, function pointers, or control flags.
>
*4. Exploiting Control Flow:* By carefully crafting the overflowed input, an attacker can manipulate the program's control flow. This might involve overwriting a return address to redirect program execution to a malicious code snippet injected into the input.
>
*5. Executing Malicious Code:* With control flow manipulated, the attacker's injected code gets executed by the compromised program, potentially leading to unauthorized access, privilege escalation, or other malicious actions.
# 5. Goals:
The attacker uses the control gained through the buffer overflow to achieve their specific objectives, which may include stealing sensitive data, compromising the system's integrity, or disrupting normal operation.

# Concept of A Stack Overflow and its Exploitation Process Using A Simple analogy:

## 1. Step-by-Step Walkthrough:
### a. Building a Stack:

Picture a stack like a pile of plates in a cafeteria. Each plate represents a task or function that the computer is handling.
### b. Function Calls:

When a function is called, a plate is added to the stack. The computer keeps track of where it should go back to after finishing each task.
### c. Limited Space:

Just like there's limited space on the plate rack, the computer's stack has a limited capacity. It can only handle a certain number of function calls at once.
### d. Overflowing the Stack:

Now, imagine someone keeps adding plates without considering the limited space. Eventually, the plates start falling off the rack – this is the "stack overflow."
### e. Changing the Order:

When the plates fall, they disrupt the order. Similarly, in a computer, overflowing the stack can disrupt the program's normal flow.
### f. Redirecting Execution:

The fallen plates can be strategically placed to change the order of tasks. In a computer, this is like changing the normal flow of the program.
### g. Executing Malicious Code:

If the fallen plates (altered program flow) contain specific instructions, it's like the computer following a different set of tasks – potentially running malicious code.
## 2. Exploitation Techniques:
### a. Injecting Malicious Code:

An attacker might overflow the stack with more data than it can handle. If this data includes carefully crafted instructions (malicious code), the program might execute those instructions.
### b. Altering Function Pointers:

Function pointers are like arrows pointing to tasks. By manipulating these pointers during a stack overflow, an attacker can make the computer jump to unexpected tasks.
### c. Manipulating the Stack:

Changing the order of tasks on the stack can lead to unexpected outcomes. An attacker can manipulate this to control the program's behavior.
## 3. Examples of Exploitation:
### a. Buffer Overflow in a Password Field:

Imagine a login system where an attacker inputs a ridiculously long password. If the program doesn't check the input length, it might overflow the stack, allowing the attacker to alter the program's behavior and gain unauthorized access.
### b. Web Server Vulnerability:

In web servers, input from users is a potential entry point. If an attacker sends data that overflows the stack, they might be able to inject code that manipulates the server's behavior, potentially leading to data breaches or service disruptions.
### c. SQL Injection Attack:

In database systems, a poorly sanitized input can lead to a stack overflow. An attacker can then inject SQL commands, altering the intended database queries and gaining unauthorized access to sensitive information.
Preventing stack overflow vulnerabilities involves robust input validation, using secure coding practices, and implementing protective mechanisms within the software.

# Vulnerable Code Example:
A vulnerable C program with a buffer that lacks proper boundary checks was presented. The code snippet demonstrated how an attacker could input a string longer than the buffer size, leading to a buffer overflow.

# Exploitation:
Using a simulated environment, the presenter demonstrated how an attacker could craft a malicious input to overwrite the return address on the stack. The modified return address directed the program to execute the injected shellcode, ultimately gaining control over the compromised system.

# Countermeasures:
The presentation concluded by addressing potential countermeasures to mitigate stack-based buffer overflow attacks. Suggestions included input validation, stack canaries, and the use of modern programming languages with built-in security features.

# Conclusion:
The presentation successfully conveyed the severity of stack-based buffer overflow attacks and provided valuable insights into their mechanics. The step-by-step demonstration effectively illustrated the vulnerability in a controlled environment, enhancing the audience's awareness of the importance of secure coding practices and robust cybersecurity measures.
