# Solving Java Reversing Challenges - Noverify's Java Crackme 3

![Thumbnail](imgs/thumb.png) 

## TLDR

This time, we solve a Java crackme which focuses on InvokeDynamic instruction and has some basic obfuscation. We analyse the java bytecode instructions and use regex to bypass obfuscation. 
And then, experiment with dynamic instrumentation to later debug and understand it. Also we talk about the tooling process often required to solve java reversing challenges.  


### Challenge

> Download <a href="https://crackmes.one/crackme/5eded0f533c5d449d91ae783"  target="_blank">noverify's crackme 3</a>


***

# Introduction

Ahh, So It's been a while I've written anything!  

The last two weeks I've been fiddling around with reversing java apps and got to try these cool crackmes by [@graxcoding](https://github.com/GraxCode/java-crackmes).  
So the third one checks our input of a 64 bit long integer to validate it.  

[![sample_run](imgs/sample_run.PNG)](imgs/sample_run.PNG)  

Jadx fails to extract any classes, not cool!  

[![jadx_classes](imgs/jadx_classes.PNG)](imgs/jadx_classes.PNG)  
  
Also I tried using the jar tool's `xf` option and other tools like Bytecode Viewer but got the same result ¯\\_(ツ)_/¯   
Then I remembered a video from [MalwareAnalysisForHedgehogs](https://youtu.be/QAzs66psLjY) where he used this [dumper](https://github.com/Securityinbits/blog-posts/tree/master/java_agent) as a java agent to dump the classes from an obfuscated jar file.  
Basically our agent class must implement a public static premain method similar in principle to main method. After the JVM has initialized, the premain method will be called, then the real application main method.  

[![dumper](imgs/dumper.PNG)](imgs/dumper.PNG)  

It worked perfectly and we have the `me_nov_crackme_CrackMe.class` file and can work on it.  


***

# Static Analysis

At first I tried using JADX again but failed...  

[![jadx_err](imgs/jadx_err.PNG)](imgs/jadx_err.PNG)  

Then I used [Bytecode Viewer](https://bytecodeviewer.com/) and some of the decompilers it comes with but sadly those didn't work too and I'd had to go with the bytecode.  

I'll only dig up into some of the bytecode instructions, so if you are not quite experienced with JVM I'd recommend the following tutorials :  
[JavaCode To ByteCode - James D Bloom](https://blog.jamesdbloom.com/JavaCodeToByteCode_PartOne.html)  
[Java Bytecode Crash Course - David Buck](https://youtu.be/e2zmmkc5xI0)

Also, And as a reference for the JVM instruction set we have the following:  
[Oracle Java SE 7 Doc - The JVM Instruction Set](https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-6.html)  
[Wikipedia - Java Bytecode instruction Listings](https://en.wikipedia.org/wiki/Java_bytecode_instruction_listings)  

I just copied the bytecode from Bytecode Viewer and started analysing it.  

It looks obfuscated but we can easily notice what is it doing ...   
For instance look at the following bytecode:  

```java
 L1 {
     aload0
     arraylength
     ldc 1163059851 (java.lang.Integer)  
     ldc 1163059850 (java.lang.Integer)
     swap
     ixor	// 1163059851 ^ 1163059850 = 1
     if_icmpeq L34
 }
 L37 {
     getstatic java/lang/System.out:java.io.PrintStream
     ldc "Welcome to noverify's crackme! Please enter a numeric 64-bit key to play! The goal is to find a valid key!" (java.lang.String)
     invokevirtual java/io/PrintStream.println(Ljava/lang/String;)V
 }
 L38 {
     return
 }
```


This can be interpreted as the following pseudocode :
```java
if(args.length != 1) {
    System.out.println("Welcome to noverify\'s crackme! Please enter a numeric 64-bit key to play! The goal is to find a valid key!");
    return;
}
```

And just after this we have what looks like a try-catch block.  

```java
 L34 { // try block
     f_new (Locals[1]: [Ljava/lang/String;) (Stack[0]: null)
     aload0
     ldc 705718574 (java.lang.Integer)
     dup
     dup_x1
     pop
     ixor	// 705718574 ^ 705718574 = 0
     aaload
     invokestatic java/lang/Long.parseLong(Ljava/lang/String;)J
     lstore1
 }
 L3 { // no exception
     goto L5	// continue execution
 }
 L4 { //catch exception
     f_new (Locals[1]: [Ljava/lang/String;) (Stack[1]: java/lang/Throwable)
     astore3
 }
 L6 {
     getstatic java/lang/System.out:java.io.PrintStream
     ldc "Invalid key!" (java.lang.String)
     invokevirtual java/io/PrintStream.println(Ljava/lang/String;)V
 }
```

Could easily be converted to the following:  
```java
try {
    myinput = Long.parseLong(args[0]);
}
catch(Throwable e) {
    System.out.println("Invalid key!");
    return;
}
```

Actually I noticed quite a pattern with the xor instructions and wrote a short python script to just comment the result for it.  

```python
import re

bytecode =  open('noverify_bytecode.java').read()

def repl1(m):
	xor_res = int(m.group(1)) ^ int(m.group(2))
	return re.sub(r"($)", "// "+ m.group(1) + " ^ "\
			+ m.group(2) + " = [" + str(xor_res) + "]"+ "\n\t\t\t "\
			, m.group())
 
def repl2(m):
	return re.sub(r"($)", "// "+ m.group(1) + " ^ " \
			+ m.group(1) + " = [0]" + "\n\t\t\t "\
			, m.group())


regex1 = r" {13}ldc (.*) \(java\.lang\.Integer\)\n" \
			+" {13}ldc (.*) \(java\.lang\.Integer\)\n {13}"

regex2 = r" {13}ldc (.*) \(java\.lang\.Integer\)\n {13}dup\n {13}"

got1 = re.sub(regex1, repl1, bytecode)
got2 = re.sub(regex2, repl2, got1)

out = open('formatted_bytecode.java', 'w')
out.write(got2)
out.close()
```

The first regex searches for two consecutive **`ldc`** instruction on Integers.
And the latter one just checks for one **`ldc`** and other **`dup`** which always results in 0.  
The result of these xors is used as predefined integers in the program.  
And after some such xors we find some Congratulations and sorry strings which leads us to the checking instruction that makes use of one of the methods ie. *`method 0`* and passes an array to it as an argument.  

[![method_call_0](imgs/method_call_0.PNG)](imgs/method_call_0.PNG)  


Tracing back to the array initialisation I found that there were actually two arrays :  

```java
 L5 {
     f_new (Locals[2]: [Ljava/lang/String;, 4) (Stack[0]: null)
     ldc -1563720133 (java.lang.Integer)
     ldc -1563720130 (java.lang.Integer)
     // -1563720133 ^ -1563720130 = [5]
     swap
     ixor
     newarray 8  //arr1[5]
     astore3
 }
 L7 {
     ldc -2143046895 (java.lang.Integer)
     ldc -2143046894 (java.lang.Integer)
     // -2143046895 ^ -2143046894 = [3]
     swap
     ixor
     newarray 8  //arr2[3]
     astore4
 }
```


Taking help from the instruction set manual we see that they are both byte arrays.  

[![arr_type_codes](imgs/arr_type_codes.PNG)](imgs/arr_type_codes.PNG)  


Subsequently we observe **`bastore`** in every label below which does some calculations and store the result in these bytearrays.  
So only the array with length as 3 is passed and which depends on our input.  
Then we can see that there are several methods named numerically other than 0 and I explored them the other day.  


### Indy in Action

Continuing further it is important we understand about invokedynamic.  
We can easily observe the InvokeDynamic instruction at the return of every other method other than main.  

```java
invokedynamic me/nov/crackme/CrackMe.127([Ljava/lang/Object;)Ljava/lang/Object; : 64([Ljava/lang/Object;)Ljava/lang/Object; ([Ljava/lang/Object;)Ljava/lang/Object;
areturn
```

The invokedynamic (or simply Indy) is used for optimization and creating efficient java programs and implements a runtime system that can choose the most appropriate implementation of a method or function after the program has been compiled.

[InvokeDynamic 101](https://www.infoworld.com/article/2860079/invokedynamic-101.html)  
[InvokeDynamic for Mere Mortals](https://youtu.be/KhiECfzyVt0)  
Also checkout how are lambdas in java implemented with making use of invokedynamic [here](https://youtu.be/MLksirK9nnE)  

For examples we have the following implementations :  
- Lambda Expressions in Java 8+: `LambdaMetafactory`
- String Concatenation in Java 9+: `StringConcatFactory`

For instance, in newer versions of Java, String Concatenation is not done by appending the string elements multiple times using StringBuilder append function, instead it places those in an array and makes use of invokedynamic and StringConcatFactory to have a single method call.  

Furthering researching about the topic I came across this post by the official JEB blog.  
https://www.pnfsoftware.com/blog/android-o-and-dex-version-38-new-dalvik-opcodes-to-support-dynamic-invocation/  

And I thought to give [JEB Pro](https://www.pnfsoftware.com/) a try to see how well it handles it. Apart from some ambiguous variable names all is fine.  

So basically for indy there is a bootStrap method that creates a callsite which points to a handle to a predefined method.  

Here **`127`** looks like the bootstrap method!  

```java
public static Object 127(Object[] arg8) {
    try {
        char v3 = (char)((Thread.currentThread().getStackTrace()[2].getMethodName().hashCode() * arg8[0].toString().hashCode() * 32767 << 3 | 127) & 127);
        if(Thread.currentThread().getStackTrace().length > 127) {
            return v3 > 127 ? Boolean.valueOf(false) : Boolean.valueOf(true);
        }
        return new MutableCallSite(((MethodHandles.Lookup)arg8[0]).findStatic(CrackMe.class, String.valueOf(CrackMe.fun), ((MethodType)arg8[3])));
    }
    catch(Throwable unused_ex) {
        return CrackMe.0(new Object[]{arg8[3].toString()});
    }
}
```

Basically, it returns a callsite which points to a method handle it finds when searching for a static method with the value of fun in the class Crackme.  

Reference - [MutableCallSite](https://developer.android.com/reference/java/lang/invoke/MutableCallSite)
### Algorithm

```java
public static Object 0(Object[] arg5) {
    char v5 = (char)((Thread.currentThread().getStackTrace()[2].getMethodName().hashCode() * Integer.parseInt(arg5[0].toString()) * 32767 << 3 | 127) & 65535);
    if(Thread.currentThread().getStackTrace().length > 127) {
        return v5 >= 127 ? Boolean.valueOf(false) : Boolean.valueOf(true);
    }

    CrackMe.fun = new String(new String(new char[]{v5}).getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8).charAt(0);
    return InvokeCustoms.CallSite0_64(new Object[]{((int)(v5 ^ 64))});
}
```

It converts the string passed as an array to a 3 digit integer and does the following operation on it.  

```python
(( get_hashcode(callee_fcn) * arg) * 0x7FFF << 3 | 127) & 0xFFFF  
```

So, It monitors the execution flow and depends on the callee function. And later converts it to a utf-8 string and stores it into a static variable **`fun`**.  
It passes the integer result xored with a specific value as an argument to the method called as a result of invokedynamic.  

All the other methods are mostly similar to this except that they differ in this xor operand value.  
For extracting those, we can just use a simple regex. Also for 127 we can just fake it with a 0.  
```python
import re

filedata = open("jeb_decompiled_code.java").read().split("\n")

desired_lines1, desired_lines2 = filedata[0::10], filedata[7::10]

for x,y in zip(desired_lines1, desired_lines2):
	x = re.search(r"Object (.*)\(Object", x).group(1)
	y = re.search(r"\(new Object\[\]\{\(\(int\)\(v5 \^ (.*)\)\)\}\);", y).group(1)
	if '0x' in y:
		y = int(y,16)

	
	print x,":",y
```

```java
(Thread.currentThread().getStackTrace().length > 127)
```

We see that it checks if the no. of functions executed in a run is greater than 127 it returns true which should then validate out input.  
Perfect this is all we need to know to write a short python script.  


```python
nice_fcns = [0,63,127,255,462,740,896,1217,1721,1914,2457,2697,3300,3994,4535,4647,5078,5256,5311,5594,5680,5751,6139,6273,6544,6640,6740,6866,6956,7039,7127,7205,7334,8392,8489,8591,8963,9828,10245,10310,10359,11024,11208,11394,11775,12009,12071,12505,12531,12689,13158,13529,13910,13946,14071,14256,14643,14981,15004,15021,15170,15725,15889,15903,15999,16632,17038,17270,17362,17470,17594,18318,18415,18642,18809,18943,19300,19493,19699,19813,20069,20753,21238,21380,21522,21855,21867,22095,22909,22966,23046,23167,23469,23651,23762,23979,24112,24303,24352,24395,24440,25087,25167,25366,25592,25895,26142,26206,26442,26746,27153,27647,27728,27903,28356,28537,29070,29177,29329,29648,29760,30695,30827,31246,31314,31533,31709,31797,32014,32263,32384,32681,32815,32896,32937,33201,33323,33467,33511,34315,34374,35511,35812,36141,36234,36256,36382,36556,37137,37298,37790,37918,37995,38143,38435,38867,38940,38974,39041,39108,39166,39309,40355,40726,40791,40986,41166,41503,42447,42534,42704,43135,43263,43521,43557,43730,43779,44178,44677,44734,44797,44943,45007,45966,46337,46396,46528,46979,47000,47533,47846,47921,47948,48207,48557,48726,48975,48996,49636,49667,50383,51030,51358,51578,51583,51692,51702,52032,52101,52184,52396,52500,52530,52538,52556,52931,53184,53275,53324,53564,53774,53887,54212,54764,55039,55295,55342,55359,55375,55774,55938,56138,56452,56564,56816,57016,57107,57508,57569,57611,57779,57796,58153,59099,59380,59406,59575,59829,59875,60282,60756,61041,61087,61428,61495,61565,61664,61703,61839,62288,62561,62614,62719,62991,63231,63256,63670,63882,64009,64051,64127,64191,64625,64934,65018,65155,]
xor_values_map = {0 : 64, 10245 : 48, 10310 : 244, 10359 : 160, 11024 : 56, 11208 : 24, 11394 : 200, 11775 : 236, 12009 : 32, 12071 : 156, 1217 : 36, 12505 : 220, 12531 : 56, 12689 : 168, 127 : 0, 13158 : 184, 13529 : 24, 13910 : 168, 13946 : 92, 14071 : 36, 14256 : 192, 14643 : 184, 14981 : 132, 15004 : 192, 15021 : 20, 15170 : 232, 15725 : 40, 15889 : 108, 15903 : 160, 15999 : 236, 16632 : 192, 17038 : 132, 1721 : 44, 17270 : 44, 17362 : 156, 17470 : 164, 17594 : 216, 18318 : 244, 18415 : 124, 18642 : 12, 18809 : 152, 18943 : 252, 1914 : 20, 19300 : 20, 19493 : 232, 19699 : 200, 19813 : 184, 20069 : 236, 20753 : 228, 21238 : 32, 21380 : 208, 21522 : 40, 21855 : 220, 21867 : 24, 22095 : 208, 22909 : 120, 22966 : 220, 23046 : 124, 23167 : 124, 23469 : 40, 23651 : 252, 23762 : 56, 23979 : 152, 24112 : 192, 24303 : 48, 24352 : 72, 24395 : 140, 24440 : 200, 2457 : 112, 25087 : 208, 25167 : 4, 25366 : 192, 255 : 56, 25592 : 148, 25895 : 252, 26142 : 148, 26206 : 48, 26442 : 200, 26746 : 236, 2697 : 248, 27153 : 216, 27647 : 176, 27728 : 160, 27903 : 228, 28356 : 72, 28537 : 244, 29070 : 248, 29177 : 216, 29329 : 244, 29648 : 244, 29760 : 88, 30695 : 108, 30827 : 0, 31246 : 40, 31314 : 32, 31533 : 100, 31709 : 248, 31797 : 100, 32014 : 176, 32263 : 64, 32384 : 64, 32681 : 64, 32815 : 76, 32896 : 40, 32937 : 8, 3300 : 128, 33201 : 244, 33323 : 176, 33467 : 108, 33511 : 236, 34315 : 40, 34374 : 4, 35511 : 116, 35812 : 100, 36141 : 148, 36234 : 192, 36256 : 192, 36382 : 216, 36556 : 244, 37137 : 252, 37298 : 12, 37790 : 216, 37918 : 16, 37995 : 252, 38143 : 148, 38435 : 124, 38867 : 48, 38940 : 64, 38974 : 124, 39041 : 36, 39108 : 244, 39166 : 20, 39309 : 40, 3994 : 188, 40355 : 228, 40726 : 68, 40791 : 244, 40986 : 84, 41166 : 176, 41503 : 212, 42447 : 220, 42534 : 160, 42704 : 204, 43135 : 48, 43263 : 192, 43521 : 108, 43557 : 32, 43730 : 236, 43779 : 152, 44178 : 56, 44677 : 40, 44734 : 160, 44797 : 108, 44943 : 32, 45007 : 40, 4535 : 180, 45966 : 160, 462 : 64, 46337 : 108, 46396 : 72, 4647 : 172, 46528 : 220, 46979 : 92, 47000 : 140, 47533 : 184, 47846 : 228, 47921 : 108, 47948 : 24, 48207 : 236, 48557 : 244, 48726 : 100, 48975 : 244, 48996 : 56, 49636 : 48, 49667 : 56, 50383 : 116, 5078 : 16, 51030 : 252, 51358 : 152, 51578 : 152, 51583 : 176, 51692 : 116, 51702 : 76, 52032 : 56, 52101 : 236, 52184 : 64, 52396 : 244, 52500 : 32, 52530 : 108, 52538 : 76, 52556 : 92, 5256 : 136, 52931 : 24, 5311 : 136, 53184 : 4, 53275 : 184, 53324 : 228, 53564 : 108, 53774 : 168, 53887 : 92, 54212 : 176, 54764 : 168, 55039 : 168, 55295 : 200, 55342 : 124, 55359 : 100, 55375 : 252, 55774 : 48, 55938 : 136, 5594 : 84, 56138 : 108, 56452 : 192, 56564 : 184, 5680 : 92, 56816 : 144, 57016 : 116, 57107 : 40, 57508 : 212, 5751 : 136, 57569 : 40, 57611 : 48, 57779 : 100, 57796 : 184, 58153 : 208, 59099 : 80, 59380 : 36, 59406 : 40, 59575 : 132, 59829 : 212, 59875 : 184, 60282 : 184, 60756 : 8, 61041 : 56, 61087 : 176, 6139 : 60, 61428 : 196, 61495 : 236, 61565 : 92, 61664 : 92, 61703 : 196, 61839 : 52, 62288 : 168, 62561 : 48, 62614 : 76, 62719 : 180, 6273 : 160, 62991 : 108, 63 : 204, 63231 : 116, 63256 : 168, 63670 : 184, 63882 : 108, 64009 : 84, 64051 : 72, 64127 : 32, 64191 : 20, 64625 : 84, 64934 : 144, 65018 : 32, 65155 : 184, 6544 : 68, 6640 : 16, 6740 : 204, 6866 : 120, 6956 : 112, 7039 : 68, 7127 : 196, 7205 : 128, 7334 : 204, 740 : 116, 8392 : 176, 8489 : 204, 8591 : 108, 896 : 108, 8963 : 136, 9828 : 44 }

def get_hashcode(s):
	s = str(s)
	n = len(s)
	res = 0
	for i in range(n):
		res += ord(s[i])*31**(n-(i+1))
	return res

for arg in range(1000):
	visited = [0]
	#init with call to fcn_0
	v5 = (( get_hashcode('main') * arg) * 0x7FFF << 3 | 127) & 0xFFFF
	if v5 in nice_fcns:
		print arg,": END @",
		visited.append(v5)
		arg = v5 ^ xor_values_map[0]
	else:
		#print "Not eligible !!"
		continue

	while True:
		v5 = (( get_hashcode(visited[-2]) * arg) * 0x7FFF << 3 | 127) & 0xFFFF

		if v5 in nice_fcns:
			arg = v5 ^ xor_values_map[visited[-1]]
			visited.append(v5)
			continue
		else:
			print v5
			break

	print ("len(stackTrace) = " + str(len(visited)+2),visited)
```

Here we check for maximum length of stacktrace which can be achieved and to my surprise it was 22!  
Also there are 3 results(191,465,739) with the same stacktrace which ends at 7039.  

```python
('len(stackTrace) = 22', [0, 55295L, 25087L, 255L, 15999L, 64127L, 63231L, 11775L, 23167L, 62719L, 43135L, 27647L, 18943L, 38143L, 51583L, 53887L, 27903L, 55039L, 43263L, 7039L])
```


Then I moved on and wrote used z3 to find the exact 64 bit integer which results in those 3 digit values. Note the operations on the input.  

```python
from z3 import *

s = Solver()
inp = BitVec('inp',64)

res1 = ((inp >> 24 & 15 | (inp >> 56 & 15) << 4)& 0xFF)
res2 = ((inp >> 8 & 15 | (inp >> 40 & 15) << 4)& 0xFF)
res3 = ((inp >> 0 & 15 | (inp >> 0x20 & 15) << 4)& 0xFF)

s.add(And(res1 >= 48,res1 <= 57))
s.add(And(res2 >= 48,res2 <= 57))
s.add(And(res3 >= 48,res3 <= 57))

got = (res1-48)*100 + (res2-48)*10 + (res3-48)
#got can be : 191, 465, 739

s.add(got == 191)

print s.check()
print s.model()
# Multiple solutions possible
'''
while s.check() == sat:
	solution = s.model()
	block = []
	c = inp
	print solution[c] 
	block.append(c != solution[c])
	s.add(Or(block))
'''
```

But indeed it validated successfully !!  

[![solved](imgs/solved.PNG)](imgs/solved.PNG)  

<img src="https://media.giphy.com/media/kHmBzIxx4LRSM/giphy.gif" alt="drawing" width="300"/>  

***

# Dynamic Analysis

***So, what did I miss?*** 

I wanted to check what was going under the hood and tried some debuggers like jdb(didn't work).  
Also I came across [Dr Garbage Tool's](http://drgarbagetools.sourceforge.net/) Bytecode Visualizer.  
This is an old eclipse plugin set and doesn't work with newer versions of eclipse.  

I was able to install it but alas I don't know why it wasn't able to identify the main method.  
![](imgs/bytecode_visualizer_err.png)  

At last, I reached out for some java bytecode editors to add debug print statements.  

- [Recaf - A modern bytecode editor](https://github.com/Col-E/Recaf)  
- [JByteMod - Java bytecode editor](https://github.com/GraxCode/JByteMod-Beta)  


Recaf is very easy to use and got a nice UI as well so I went with it.  

Also I asked Col-E(Recaf's Developer) about any good bytecode debuggers and unfortunately, it turns out there aren't any as of now!   
I also shared the weirdness of this jar in extracting the class.  

[![jar_extract](imgs/jar_extract.PNG)](imgs/jar_extract.PNG)  

And, Then I got to know about the forward slash trick which was pretty obvious from the jar verbose extraction that I didn't observe carefully before.  

[![fwd_slash](imgs/fwd_slash.PNG)](imgs/fwd_slash.PNG)  

Obviously the decompiler view doesn't work so we'd have to switch to the class table mode.  

[![class_mode](imgs/class_mode.PNG)](imgs/class_mode.PNG)  

Select method_0 and edit with assembler.  

[![edit_assembler](imgs/edit_assembler.PNG)](imgs/edit_assembler.PNG)  

We can just add a `System.out.println()` for variable null1 shown.  

[![edit_0](imgs/edit_0.PNG)](imgs/edit_0.PNG)  

If everything goes well, we should see this output.  

[![edited_0_output](imgs/edited_0_output.PNG)](imgs/edited_0_output.PNG)  

We can do the same for the fun variable.  
But we need some automation for adding these instructions in every method. 
And currently Recaf doesn't have any [Automation API](https://github.com/Col-E/Recaf/issues/151).  
So to resolve this problem I turned to dynamic instrumentation.  

### Dynamic Instrumentation using ASM

Just FYI I'm new to the instrumentation part so I checked out some frameworks/libraries which could help me with it. 
As it turns out there are several options and I tried some of them such as [JavaAssist](http://www.javassist.org/), [ByteBuddy](https://bytebuddy.net/) and [ASM](https://asm.ow2.io/). 
But ASM is at the lowest level and is the base for Bytebuddy and [cglib](https://github.com/cglib/cglib) as well, so I went with it!  

Checkout this stackoverflow answer for more on [Analysis of bytecode libraries](https://stackoverflow.com/a/45891652)


##### ASM User Guide and Tutorials 
- https://asm.ow2.io/asm4-guide.pdf  
- http://www.egtry.com/java/bytecode/asm/  
- https://www.tomsquest.com/blog/2014/01/intro-java-agent-and-bytecode-manipulation/  
- https://stackoverflow.com/questions/tagged/java-bytecode-asm

For verifying your ASM Implementation and how ASM reads your class you can checkout [ASMifier](https://github.com/iridescent995/ASM_bytecode_manipulation/tree/master/ASMifier).  

Here we have `v5` as `var_1` and the following condition adds these three lines of code after it encounters any `(ISTORE, 1)` instruction.  

```java
if (opcode == ISTORE && var == 1) {
	mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
	mv.visitVarInsn(ILOAD, 1);
	mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(I)V", false);
}
```

Same goes for logging the static variable ie. `fun`.  

```java
if(opcode == PUTSTATIC && name.equals("fun")) {
	mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
	mv.visitFieldInsn(GETSTATIC, "me/nov/crackme/CrackMe", "fun", "C");
	mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(I)V", false);
}
```

I added a string ie. `CrackMe.fun =` to differentiate both of them. 

[![agent_1](imgs/agent_1.PNG)](imgs/agent_1.PNG)  

Cool lets see how it ends.   

[![agent_2](imgs/agent_2.PNG)](imgs/agent_2.PNG)  

#### Weirdness of method_63

Ahh as you can see, I missed the most important part of this crackme, ie. UTF-8 LOL !  
So single surrogates are illegal and are converted to **' ? '** character (ie. 63).  
FYI Surrogates are characters in the Unicode range U+D800 - U+DFFF.  
And Here we notice 56575 which is then converted to 63.  

Here it inverts the comparision sign and validates if the length of stacktrace is less than 127.  
```python
(Thread.currentThread().getStackTrace().length < 0x7F)
```

So the stacktrace length check for other methods is bogus and is only used for deception.  

Also the v5 in method_63 always results in 127 which returns true halting the program.  

```python
(( get_hashcode(callee_fcn) * arg) * 0x7FFF << 3 | 127) & 127
```

So now we know what were we missing.  

*** 

# Solution and Source files

>I've uploaded all of my solution files along with the ASM Agent project for this crackme on my github.  
https://github.com/mrT4ntr4/solution-noverify-crackme-3

Also krakatau does a good job that I got to know about from the author.  
Also some of the source files were disclosed by him:  

- [Original Driver Source code](https://hastebin.com/bacuwijuwe  )
- [Keygen for methods](https://hastebin.com/cexomojesu  )
- [Final Keygen](https://hastebin.com/rujanapeso)
- [Original ASMifier source code for final crackme](https://hastebin.com/retilapila)

And, some manual obfuscation was done afterwards.  

I enjoyed this challenge, all thanks to [@graxcoding](https://twitter.com/graxcoding) for making it!  
