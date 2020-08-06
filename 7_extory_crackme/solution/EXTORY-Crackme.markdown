#EXTORY's Crackme

![Thumbnail](imgs/thumb.png) 

This will be a detailed writeup of EXTORY crackme from crackmes.one. As always I'll try to make it easy to understand as much as possible so It'll be longer than usual (with more than 30 screenshots XD). Also Make sure to leave some feedback as it took much more time as compared to my previous writeups.   

## TLDR;
Basically this crackme has 4 anti-debug checks(acc. to me). And I think its hard to solve it statically. There are many techniques that is often found in malwares. So it is worth to check it out. If you have not tried it, I'd advice you to please do and then continue with this writeup. I've also used a no. of tools for different purposes.  

### Challenge

> Download <a href="https://crackmes.one/crackme/5e0618c633c5d419aa013483"  target="_blank">EXTORY's Crackme</a>    
    
  
***

## Initial Analysis  

As usual, We have to guess the right password and it will show the 'Correct' text in the app.  

For this I used DIE tool. Its a 64bit exe and uses MSVCP.    
So I began by searching for some strings and found that there is no **'Correct'** and **'Wrong'** string.  
But searching in Unicode strings I found some interesting stuff.  

![](imgs/die.png)  

Also In crypto tab we find an anti-debug technique.  

![](imgs/die2.png)  

Cool, Now its time to hop over to IDA.  
Make sure to enable UNICODE strings.  

![](imgs/unicode.png)  

So we find their references and I observed that there is some thread stuff.  

After that I find that the ExitCode of that Thread is being compared to 1 and if its true we continue to use some **'hgblelelbkjjgldd'** else **'hielblaldkdd'**.  
Ahh it seems like these could be our 'Correct' and 'Wrong' strings but encrypted.  

![](imgs/cmp.png)  
  
Now We can switch over to our nice Decompiler View to get more insight into this encryption function and maybe our password is encrypted in the same way.  
  
![](imgs/1.png)  
   
We can observe that *WaitForSingleObject* is called which checks whether the function has exited then the handle to the thread and the pointer to variable which stores the exitcode is passed to the *GetExitCodeThread* function. And Finally it compares the exitcode to 1.  

![](imgs/2.png)  
  
The decryption algo is pretty simple and the same for both the strings.  
It is as follows:  
`(enc[i] + 10 * enc[i+1] - 1067)`

![](imgs/3.png)  

So I wrote a short python script to break it down what it does.  
It is self explanatory.  

```python
enc = "hgblelelbkjjgldd" #Correct!
#enc = "hielblaldkdd"     Wrong!
dec = ""
v23 = len(enc)
v25 = 0
while(v25 < v23):
  c = ord(enc[v25])
  d = ord(enc[v25+1])
  v27 = c + 10 * d;
  v25 += 2;
  dec += chr(v27-1067)
print dec
```
  
So now whats next?  
Well I started to study the decompiled code of the Thread which does all the work in this crackme.  
But It was troublesome to analyse it further statically so I used IDA to debug it.  

So I placed a breakpoint just before the execution of the thread and it exited :(


<img src="imgs/idaexit.gif" alt="idaexit"/>  

***

## Dynamic Analysis

So In this tutorial/writeup I'll toggle between IDA and x64dbg as it becomes more easy to understand and patch it at the same time.    

Also first things first.. You should disable ASLR with the help of CFF Explorer.
  
![](imgs/cff.png)  

Just uncheck the **DLL can move** option and save the executable.    
Now load the exe in x64dbg and just keep on stepping.
By Trial and Error we get to know that the **fcn.1000** is responsible for closing our debugger.   

![](imgs/p1.png)  
  
We step into it and again find another function ie. **fcn.1D10** and please keep in mind keep on saving our database so that our breakpoints are remembered by x64dbg.  

![](imgs/p2.png)  
   
We now step within the fcn.1D10 function and start analysing it as it looks interesting.  
At the very beginning it calls a function 4 times ie. **fcn.2050**  

![](imgs/p3.png)  
  
It'd be easy to just look into IDA's decompiled version of the function as it has some weird assembly.  

![](imgs/p4.png)  
  
Cool The decompiled version matches and some data is passed to the function  

![](imgs/p5.png)  
  
If you'll check it, the function is a little bit scary at first.
But basically it justs *xors the bytes with 0xD9* from the data passed to it and returns it.  
  
![](imgs/p6.png)  
Like the bytes above decrypts to **x64dbg.exe**.  
    
![](imgs/p7.png)  

And after it executes 4 times, the registers look like this and the 4 strings decrypted are :
- x64dbg.exe  
- Taskmgr.exe  
- javaw.exe  
- ida64.exe  
  
![](imgs/p8.png)  
   
Now we continue with the decompiled code and at the last its looking suspicious hmm..  
  
![](imgs/p9.png)  
  
It checks the return code of the **fcn.2370** which later decides whether to terminate the process. And the fcn.2370 uses some functions to get the list of running processes.  
I keep on stepping and find that it finds `smss.exe, csrss.exe, wininit.exe, services.exe, winlogon.exe, etc`.

*Reference* :  
https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes  

I guess here it simply checks whether the list contains any string which we decrypted previously and decides the return code accordingly. 

> It'll close every process from those 4 .. Not your current debugger.   

***

## Patching & Fun

Now we can patch the if statement in such a way that it has a minimum effect over the program and also keeping in mind that it should work  with and without a debugger.  
PS We can also just rename our debugger to bypass this check though.  

![](imgs/p10.png)  

In the screenshot above, the *`TEST EAX,EAX`*  checks whether the return code of **fcn.2370** is 0. We want to always skip the terminate instructions so I patched it to *a XOR and JMP* and saved it.   
  	
![](imgs/p11.png)  
  
But I guess there is more to it.  
After executing the patched version the EIP gets to an invalid instruction ie. 0x12345678.    

![](imgs/p12.png)
  
Upon analysing it again I found  that we still can't pass the fcn.1000.  
![](imgs/p13.png)  
    
Just somewhat below the fcn.1D10 in fcn.1000 we get **fcn.2540** which does this.  



![](imgs/p14.png)  
Its a very short one and just loads the address of Process Environment Block(ie. value of GS:[60] from the Thread Information Block), loads the byte at 0x2 index ie. BeingDebugged flag. If its true then it will load `0x12345678` into EAX and calls it which halts the program execution.  

*Reference* :  
https://en.wikipedia.org/wiki/Win32_Thread_Information_Block  
https://www.aldeid.com/wiki/PEB-Process-Environment-Block/BeingDebugged  

![](imgs/p15.png)  

![](imgs/p16.png)    

We can simply NOP those *MOV and CALL instructions* and save it.  
  
![](imgs/p17.png)    
  
Ahh There is another too... but this looks same but instead of 0x12345678, it sets EIP to `0xDEADC0DE`.  

![](imgs/p18.png)    
   
This is also just below the previous antidebug check. But it compares some other parts from PEB. So I checked out at 0x20 .. there is *FastPebLockRoutine*  which has the address of fast-locking routine for PEB. I didn't get anything about why is it comparing bytes at that address to 0x2001.    

![](imgs/p19.png)   
    
I just nopped the faulty instructions and again saved it.  
Just to keep a track, this was our 3rd patched exe.   

![](imgs/p20.png)      
   
Again after executing the patched executable we get another `DEADC0DE`.  
This is not cool anymore lol.  
We can now just check how much `DEADC0DE` exists. Just Right Click and ..  
 `Search for -> Current Module -> Constant`   
And enter `DEADC0DE`

![](imgs/p21.png)      
   
Cool There is only one found. We jump to the location and find that it is pretty much similar to the one we just patched.  

![](imgs/p22.png)      

So we patch it in the same way we did the previous one.  
And to my surprise it doesn't halt or exits anymore.. That means we have bypassed all anti-debug checks.  
  
***

## KeyGen

For getting our correct key, I'll use IDA WinDebugger as its graph view is helpful for now.    
  
![](imgs/p23.png)      
  
Ok, The StartAddress is loaded and passed into CreateThread.  
  
![](imgs/p24.png)      

So our main function to put a breakpoint is **sub.1A30**.  
  
![](imgs/p25.png)      
   
The first cmp instruction is the same we just patched as you can refer from the multiple nop instructions just after it.   

![](imgs/p26.png)      
  
After that we have a loop that stores our input_key's length into rax basically by looping it and checking it against a null byte. And If it is below 0x10 ie. 16 characters it displays wrong_key so the next time I entered something random like **hell65abhell78cd**.  

![](imgs/p27.png)      
  
Later it xors our input_key bytes with 0xCD in a loop.  
  
![](imgs/p28.png)      
   
And In next loop it xors 16 bytes (step = 2) at **var_68** and **var_40**.
![](imgs/p29.png)      
  
And now something obvious happens.. It compares our xored input_key with the bytes we got from xoring var_68 and Var_40.  

![](imgs/p30.png)      
  
Now we know that it is a simple XOR encryption which we can easily reverse.  

So I wrote an IDApython script which gets our key.  
PS The addresses here can vary on your system.  

```python
v68, v40 = [], []
v68_beg = 0x0020FFEF0
v68_end = v68_beg + 32
v40_beg = 0x0020FFF18
v40_end = v40_beg + 32
for ea in range(v68_beg,v68_end,2):
	v68.append( Byte(ea) )
for ea in range(v40_beg,v40_end,2):
	v40.append( Byte(ea) )
key = ""
for x,y in zip(v68,v40):
	key += chr((x^y) ^ 0xCD)
print key
```

This outputs
```
5AquUR%mH4tE=Yn9
```

![](imgs/solved.png)      

And Hey Finally We get the `Correct!` Text in green.  
That was very satisfying, I hope the feeling is mutual.  

<img src="https://media.giphy.com/media/g7X5T9PuUBAzu/giphy.gif" alt="drawing" width="300"/>  

See yall in next writeup about another crackme.  
Next time I'm thinking maybe .NET will be fun.  

Don't forget to hit me up on <a href="https://twitter.com/MrT4ntr4"  target="_blank">Twitter</a>. 
