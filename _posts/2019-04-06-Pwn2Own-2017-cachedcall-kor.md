---
title: "[번역] Pwn2Own 2017: UAF in JSC::CachedCall"
layout: post
date: 2019-04-06 15:24:00
tag:
- browser
headerImage: false
projects: false
hidden: false
category: blog
headerImage: true
author: null2root
---

# Pwn2Own 2017: UAF in JSC::CachedCall (WebKit)


출처 : https://phoenhex.re/2017-05-04/pwn2own17-cachedcall-uaf  
번역 및 보완 : LiLi, y0ny0ns0n, powerprove, cheese @ null2root


이 문서는 Samuel Groß(saelo), Niklas Baumstark 에 의해 작성되었다. Pwn2Own 팀을 결성하기 이전부터 함께 CTF 를 참가하곤 했다. 

우리는 Pwn2Own 에서 찾은 취약점(Safari 공격 및 루트 권한상승)을 설명하는 Write-up 시리즈를 작성했으며 이 문서는 그 중 일부이다. 여기서는 Safari 브라우저(10.0.3)의 렌더러 프로세스에서 발생하는 Use-After-Free 버그 및 RCE 익스플로잇에 대해 설명하고자 한다.  


## 웹킷 버그에 대한 두 가지 슬픈 이야기

Pwn2Own 에서의 데모 시연은 조금 특이했는데, 우리는 Sarafi 렌더러 내부에서 RCE 를 일으키기 위해 1-day 버그를 사용했다. 이는 불행하게도 우리가 찾은 취약점이 Pwn2Own 시점에 1-day 취약점이 되어버렸기 때문이었다. 2월 초쯤에 Saelo 는 CachedCall 클래스에서 버그를 발견했는데, 처음에는 익스플로잇이 불가능해 보였다. 그러다 2주 정도 뒤에 익스플로잇을 한번 시도해 보기로 결정했고 결국 실행할 수 있는 익스플로잇으로 만들었다. 그 시점에 saelo 는 정말 단순한 poc 파일(poc-cachedcall-uaf.js)의 SHA-256 해시값을 트위터에 올렸는데, 불과 7시간 후(!) 애플의 한 직원이 이에 관한 버그 리포트를 열었다. 이 버그가 Tracker 에 등록되었을 때 hidden 상태가 아니었던 걸 보면, 개발자들이 이 이슈를 보안 이슈로 생각하지는 않았던 것 같다. 나중에서야 우리는 사파리 팀의 내부 퍼저가 버그를 일으켜서 수정을 했어야만 했다는 것을 알게 되었다. 어쨌거나 이 버그를 통해 Full 0-day 익스플로잇 체인을 구성하고자 했던 우리의 바람은 사라지고 말았다.

대회까지 약 한 달여를 남겨두고, 우리는 Safari 10.1 업데이트에 적용되는 새로운 WebKit 코드에 집중하기로 했다. 거기서 버그를 찾아내 활용하는 데는 성공했는데, 애플에서는 Pwn2Own 콘테스트 이전에 진행될 macOS 10.12.4 업데이트에 Safari 10.1 을 포함하지 않기로 결정하는 바람에 우리는 또 한번 고배를 마셔야 했다. 우리는 이 두 번째 버그를 보고했으며, 패치가 되기 전까지는 Sarafi 10.1 버전에서 영향을 미친다. 버그가 수정되면 이 버그에 대한 Write-up도 작성할 것이다. 


## Overview

우리가 Pwn2Own에서 사용한 WebKit 버그는 CVE-2017-2491 / ZDI-17-231로, JavaScriptCore 내 JSString 객체에서 발생하는 Use-After-Free 버그이다. 버그가 발생하면 자바스크립트 콜백에서 JSString 객체에 대한 댕글링 포인터를 얻을 수 있다. 처음에는 이 취약점을 익스플로잇으로 만들어 내기 어려워 보였지만 안정적으로 read/write 할 수 있는 좀 더 일반적인 기법을 찾을 수 있었다. 우리는 28GiB 에 달하는 매우 넓은 영역에 힙 스프레이를 진행했고, macOS 의 페이지 압축 메커니즘 덕분에 8GB RAM 을 가진 맥북에서도 스프레이가 가능하다.

우리는 아래와 같은 순서로 취약점에 대해 설명하고자 한다.

- 코드상에서의 버그
- 익스플로잇
- 버그 트리거하기
- fakeobj/addrof 를 이용한 Read/Write
- 박살난 힙 구조로부터 살아남기

cachedcall-uaf.html 파일에서 주석이 포함된 full exploit 코드를 확인할 수 있다.



##  코드상에서의 버그

String.prototype.replace 을 호출할 때 첫 번째 인자로 RegExp 객체를 넘기면, WebKit의 JavaScript 엔진인 JSC(JavaScriptCore)에서는 다음과 같은 네이티브 함수를 호출한다.

```c++
static ALWAYS_INLINE EncodedJSValue replaceUsingRegExpSearch(
    VM& vm, ExecState* exec, JSString* string, JSValue searchValue, CallData& callData,
    CallType callType, String& replacementString, JSValue replaceValue)
{
    // ...

    // [[ 정규식이 g flag 를 가지고 && 두번째 인자가 JS function 인 경우 진입 ]]
    if (global && callType == CallType::JS) {
        // regExp->numSubpatterns() + 1 for pattern args, + 2 for match start and string
        int argCount = regExp->numSubpatterns() + 1 + 2;
        JSFunction* func = jsCast<JSFunction*>(replaceValue);
        CachedCall cachedCall(exec, func, argCount);        // [[ 0 ]]
        RETURN_IF_EXCEPTION(scope, encodedJSValue());
        if (source.is8Bit()) {
            while (true) {
                int* ovector;
                MatchResult result = regExpConstructor->performMatch(vm, regExp, string, source, startPosition, &ovector);
                if (!result)
                    break;

                if (UNLIKELY(!sourceRanges.tryConstructAndAppend(lastIndex, result.start - lastIndex)))
                    OUT_OF_MEMORY(exec, scope);

                unsigned i = 0;
                for (; i < regExp->numSubpatterns() + 1; ++i) {
                    int matchStart = ovector[i * 2];
                    int matchLen = ovector[i * 2 + 1] - matchStart;

                    if (matchStart < 0)
                        cachedCall.setArgument(i, jsUndefined());
                    else
                        // [[ 1 ]]
                        cachedCall.setArgument(i, jsSubstring(&vm, source, matchStart, matchLen));
                }

                cachedCall.setArgument(i++, jsNumber(result.start));
                cachedCall.setArgument(i++, string);

                cachedCall.setThis(jsUndefined());
                JSValue jsResult = cachedCall.call();           // [[ 2 ]]
                replacements.append(jsResult.toWTFString(exec));
                RETURN_IF_EXCEPTION(scope, encodedJSValue());

                lastIndex = result.end;
                startPosition = lastIndex;

                // special case of empty match
                if (result.empty()) {
                    startPosition++;
                    if (startPosition > sourceLen)
                        break;
                }
            }
        }

    // ...
```

[[ 0 ]] 에서는 CachedCall 인스턴스를 생성하는데, 이는 나중에 콜백 함수를 호출할 때 사용된다. Safari 10.0.3 에서 사용하는 Webkit 보관소의 branch에서 CachedCall 클래스는 아래와 같이 구성되어 있다.

```c++
class CachedCall {

    // ...

    private:
        bool m_valid;
        Interpreter* m_interpreter;
        VM& m_vm;
        VMEntryScope m_entryScope;
        ProtoCallFrame m_protoCallFrame;
        Vector<JSValue> m_arguments;
        CallFrameClosure m_closure;
};
```

`m_arguments` 라는 변수명에서 볼 수 있듯이, Cachedcall 에서는 인자값을 저장하기 위해 WTF::Vector 타입을 사용하고 있다. 그리고 코드에서는 [[1]] 의 jsSubstring 에서만 `m_arguments` 멤버변수를 참조하고 있다. 

이 변수와 타입의 문제점을 이야기하기 전에 먼저 가비지 컬렉터에 대해 알아볼 필요가 있다. JavaScriptCore에서 가비지 컬렉터에 의해 수명이 관리되는 모든 객체는 JSCell 로부터 상속된다. 가비지 컬렉터의 동작 알고리즘(Mark & sweep)에 따라, JSCell에 대한 참조를 탐색하기 위해 주로 찾아가는 루트가 있다.

- 현재의 call stack
- 흔히 전역 객체(global object) 라고 불리는  전역 자바스크립트 실행 컨텍스트(global JavaScript execution context)
- 몇몇 특별한 버퍼 - MarkedArgumentBuffer 등등
- 기타 등등

이러한 위치로부터 탐색한 결과, 어떤 곳에서도 참조를 하지 않는(도달하지 않는) 객체의 경우, 가비지 컬렉터의 sweep 단계에서 free 될 수 있다. 

다시 `m_arguments` 로 돌아가 보자. CachedCall 에서 `m_arguments` 가 사용하는 `WTF::Vector` 타입은 Opaque 데이터 타입으로, 외부 인터페이스에서는 타입의 내부 구조를 명확히 알 수 없도록 구성되어 있다. 이런 특징으로 인해 가비지 컬렉터는 `m_arguments` 내부에서 어떤 객체를 참조하고 있는지 정확히 체크할 수 없다. 따라서, 만약 특정 객체에 대한 유일한 참조가 `WTF::Vector` 타입 안에 들어 있다면 가비지 컬렉터는 해당 객체의 참조를 찾지 못해 그 객체를 free 해 버리는 경우가 생길 수 있다.

이런 문제점을 활용하기 위해, 위 코드의 [[1]] 에서 새로운 string 인자를 할당하는 중에 가비지 컬렉팅이 일어났다고 가정해 보자(가비지 컬렉팅은 언제든 발생할 수 있으므로 충분히 일어날 수 있는 일이다). 그 결과 이전에 사용하던 인자값(JSString 인스턴스)들은 sweep 및 free 가 될 것이다. 이후 [[2]] 에서 `cachedCall.call()` 을 호출하면, cachedCall 의 콜백 함수 내에서는 앞서 free 되고 남은 JSCells 포인터를 인자값으로 착각하고 사용(Use-After-Free)하게 된다. 가비지 컬렉팅은 콜백 전에 발생해야 한다. 

poc-cached call-uaf.js 파일은 위 가정을 증명하는 PoC 코드로, Safari 10.0.3에서 작동한다. 스크립트 마지막의 i_am_free 는 JSString 이 free 되고 남은 포인터이다. JSCell 헤더가 free-list 포인터(역주 - heap exploit의 bin과 유사)로 덮어 씌워지기 때문에, `typeof()` 이외의 작업을 하면 크래시가 발생할 가능성이 있다. 관련 소스 코드는 다음과 같다.


```javascript
function i_want_to_break_free() {
    var n = 0x40000;
    var m = 10;
    var regex = new RegExp("(ab)".repeat(n), "g"); // g flag to trigger the vulnerable path // (ab)(ab)(ab)(ab)(ab)...(ab)
    var part = "ab".repeat(n); // matches have to be at least size 2 to prevent interning
    var s = (part + "|").repeat(m); // ab|ab|ab|ab|ab|ab|ab|....ab|ab|
    while (true) {
        var cnt = 0;
        var ary = [];
        s.replace(regex, function() {
            for (var i = 1; i < arguments.length-2; ++i) {
                if (typeof arguments[i] !== 'string') {
                    i_am_free = arguments[i];
                    throw "success";
                }
                ary[cnt++] = arguments[i];  // root everything to force GC
            }
            return "x";
        });
    }
}
try { i_want_to_break_free(); } catch (e) { }
console.log(typeof(i_am_free));  // will print "object" 
```


이 버그는 CachedCall 클래스의 Vector 타입을 MarkedArgumentBuffer 로 교체함으로써 수정되었다.


## 익스플로잇

브라우저에서 UAF 취약점을 공략할 때에는 객체가 free 된 공간에 새로운 객체를 할당하여 type confusion 을 일으켜 익스플로잇으로 이어나가는 것이 일반적이다. 그러나 JSC 에서는 상황이 조금 다른데, JSCell 객체들은 자신의 타입 정보를 자신의 객체 내에 저장하고 있다. 따라서 free 된 위치에 다른 JSCell 이 할당되더라도 기존의 댕글링 포인터를 직접적으로 익스플로잇에 이용할 수 없다. 하지만 free 된 객체 내부에 또 다른 free 된 객체(가비지 컬렉터 등에 의해)를 포함하고 있다면, 혹은 댕글링 포인터가 정렬이 잘못되어 다른 JSCell 의 내부를 가리키게 된다면 여전히 공격은 가능할 것이다(역주 - 2-staged 공격에서처럼 free 된 두 개의 객체를 타고 들어가 공격을 진행할 수 있다). 전자의 공격 방법을 사용한 대표적인 예로 페가수스 익스플로잇이 있는데, free 된 JSArray 객체의 댕글링 포인터를 통해 JSArray 내부 버퍼에 접근하여 익스플로잇을 하도록 구성되어 있다.

추가로, 공격을 위해 활용한 다음 2가지 사실에 대해서는 별도의 설명을 하지 않는다.

1. replace() 코드에서 jsSubstring 호출 결과로 생성되는 JSString 객체는 기존의 JSString 과 내용을 공유하며, 기존의 JSString 객체는 계속 유지된다. 
2. 24 bytes 또는 32 bytes 크기의 JSCell 들을 할당하기 위해 별도로 마련된 힙 공간이 있으며, JSString 객체 또한 32 bytes 로 정렬되어 해당 힙 공간에 할당된다.

적용할 만한 일반적인 기술들을 떠올려 보았지만 생각나는 유일한 방법은 아레나를 포함하는 전체 힙 블록을 free 하고 그 자리에 다른 타입의 새로운 아레나를 할당하는 것이었다. 우리는 다른 방법을 찾기 위해 애썼고 마침내 Pwn2Own 에서 적용할 만한 매우 일반적인 접근법을 찾을 수 있었다.


## JSCell free-list pointer type confusion

가비지 컬렉터가 JSCell 을 모아서 처리할 때, JSCell 의 첫 8바이트는 같은 힙 블록 내에 있는 다음 free 된 JSCell 대한 포인터로 대체된다(역주 - heap exploit의 bin과 유사). JSCell 의 나머지 부분은 바뀌지 않는다. 이 때문에 free 된 JSString 객체의 영역에 다른 객체를 할당하지 않고 댕글링 포인터를 사용하려고 하면 충돌이 발생한다.

Crash 를 우회하기 위해 JSCell의 처음 8바이트가 어떻게 구성되는지 살펴보자.

```c++
StructureID m_structureID;           // dword
IndexingType m_indexingTypeAndMisc;  // byte
JSType m_type;                       // byte
TypeInfo::InlineTypeFlags m_flags;   // byte
CellState m_cellState;               // byte
```

이 8바이트가 포인터로 대체되기 때문에, 각각의 값들이 valid 한 값으로 인식되려면 힙 주소가 주로 어떤 범위의 값을 갖는지를 알 필요가 있다. 이 점을 고려했을 때, Safari 의 Heap ASLR 이 예측 가능한 범위 내에서 일어난다는 사실은 매우 유용하게 쓰일 수 있다. macOS 10.12.3 의 Safari 에서 힙 주소는 0x110000000 - 0x120000000 범위에서 시작하여 쭉 증가한다. 이 범위의 포인터로 JSCell 헤더를 덮어쓰게 되면 주소값의 하위 32비트가 `m_structureID` 와 중첩되고, 비트 32-39가 `m_indexingTypeAndMisc`, 나머지 3개 필드는 0이 된다.

익스플로잇에 활용하기에 편리한 JSObject 객체를 array 버퍼를 활용하여 스프레이 하기로 하자. JSObject 는 NonArrayWithContiguous 이므로 IndexingType 을 8 로 맞춰주어야 한다. 따라서 `0x8000000 ~ 0x8ffffffffffe` 주소 범위에 객체가 위치해야 하며, 4 GiB 크기의 스프레이를 7 번 정도 진행해야 한다. 이 정도 크기의 스프레이는 MacOS 에서 지원하는 페이지 압축을 통해 어렵지 않게 가능하지만,  Pwn2Own 에서 사용했던 타깃 머신(2016년형 13.3인치 MacBook Pro, 16GB 메모리)에서는 스프레이에 대략 50초 정도가 걸린다.

IndexingType 8 은 좀 더 정확하게는 `JSValues (ContinuousShape)` 의 `fast contiguous storage` 에 해당한다. 이러한 타입의 객체에 `obj[0], obj[1]...` 와 같이 인덱스로 접근하면, 객체의 속성 전부를 검색하는 대신 객체의 butterfly 를 직접 참조하게 된다(butterfly 의 동작은 saelo의 프랙 문서 1.2절에 설명되어 있다). butterfly 포인터는 JSObject 의 두 번째 qword 로, free 된 JSString 인스턴스의 `flags(dword) - length(dword)` 영역과 겹치게 된다. 우리는 이 값을 힙 스프레이 영역 내부를 가리키는 `0x200000001` 값이 되도록 익스플로잇을 구성했다. 다음 그림은 JSCell 헤더를 `0x8xxxxxx` 형식의 힙 포인터로 덮어쓴 후 발생한 JSString 과 JSObject 간의 중첩을 나타낸다.



```
Original JSString:


 JSCell fields                                              JSString fields
+---------------------------------------------------------------------------+
| dword        | byte         | byte   | byte  | byte      | dword | dword  |
| StructureID  | IndexingType | JSType | flags | CellState | flags | length |
|              |              |        |       |           |       |        |
| *            | *            | *      | *     | *         | 0x01  | 0x02   |
+---------------------------------------------------------------------------+


After header is overwritten by the pointer 0x8xxxxxxxx, we get a JSObject:


 JSCell fields                                              JSObject fields
+---------------------------------------------------------------------------+
| dword        | byte         | byte   | byte  | byte      | qword          |
| StructureID  | IndexingType | JSType | flags | CellState | butterfly ptr  |
|              |              |        |       |           |                |
| xxxxxxxx     | 0x08         | 0      | 0     | 0         | 0x200000001    |
+---------------------------------------------------------------------------+

```


이렇게 생성된 fake JSObject 는 `0x20000001` 영역을 butterfly 로 인식하게 되며,  `fast-path indexing` 에 따라 인덱스를 통해 butterfly 영역에 직접 접근할 수 있다. 또한 butterfly(`0x20000001`)의 주소는 앞서 힙 스프레이를 통해 ArrayBuffer 로 덮어놓은 영역으로, 컨트롤 가능한 상태이다.  이는 프랙문서 4절에서 설명한 것처럼, 가짜 JSObject 에 값을 쓰고 ArrayBuffer 에서 값을 읽음으로써 fakeobj/addrof 를 구현했던 것과 완전히 동일한 형태이다. 여기서부터는 프랙 문서와 완전히 동일하게 익스플로잇이 진행된다. 임의의 읽기/쓰기가 가능한 객체를 만들고, 자바스크립트 함수를 JIT 코드로 만들어 쉘코드로 덮어 쓴 후 함수를 실행한다.

이제 StructureID 변수만 고려해 주면 된다. 코드 실행 과정에서 엔진이 fake JSObject 의 structure 에 접근하기 때문에 StructureID 또한 valid 한 값을 가져야 한다. structure 인스턴스의 포인터들을 보관하는 테이블이 존재하며, structure ID 를 인덱스로 하여 테이블에서 structure 를 얻어올 수 있다. 문제는 StructureID 영역을 우리가 원하는 대로 컨트롤 할 수 없기 때문에(free-list 포인터로 덮어쓰이기 때문), 포인터를 인덱스한 접근은 테이블의 범위를 넘어서 앞서 우리가 스프레이한 메모리 영역에 접근하게 된다. 그러므로 우리는 우리의 힙 스프레이 영역에 미리 fake structure 를 만들어 두어야 한다.

수 GB 에 달하는 스프레이 영역 중에서 어느 위치에 fake structure 인스턴스 를 두어야 할까 ? 이를 위해서는 free-list 포인터가 어떤 값을 갖게 될 것인지 어느 정도 예측해야 한다. 우선 free list 포인터는 JSC 메모리 할당 단위인 16 bytes 로 정렬된다. 또한 structure 테이블을 통해 structure 인스턴스에 접근하는 경우, 인덱스에 8을 곱한다(포인터 사이즈 만큼).  그러므로 우리는 스프레이를 할 때에 128 bytes (16 * 8) 마다 structure 포인터를 포함시켜 주면 된다. 익스플로잇 코드에서 스프레이를 할 때 모든 fake 테이블 포인터 값을  `0x150000008` 고정값으로 설정하고, 스프레이 되는 데이터 블록의 시작 부분마다 fake structure 인스턴스를 만들도록 했다.

## 버그 트리거하기

앞서 살펴본 접근방법은 꽤나 직관적이고 심플해 보인다.

1. 힙이 `0x8xxxxxxxx` 주소 영역까지 사용하도록 스프레이하기
2. 버그 트리거하기

하지만 두 번째 단계는 사실 그렇게 쉽지 않다.  Safari 10.0.3 환경에서 PoC 코드를 실행해 보면 즉시 버그가 트리거되는 것 같지만, 사실 PoC 에서는 힙이 너무 작아서 가비지 컬렉팅이 매우 자주 발생하기 때문에 빠르게 트리거된 것이다. JSC allocator 의 휴리스틱 때문에, 28 GB 의 메모리를 할당한 상황에서 가비지 컬렉터가 동작할 확률은 거의 없다.

그러나 다행스러운 것은, 가비지 컬렉터는 결정론적 알고리즘으로 동작한다는 것이다. 최신 웹킷에는 Riptide 라는 새로운 동시성 가비지 컬렉터(Concurrent GC)가 등장하긴 했지만, 최소한 Safari 10.0.3 의 JSC 버전에서는 그렇다. 그래서 우리는 `0x8xxxxxx` 영역에서 버그를 안정적으로 트리거할 수 있는 [힙 스프레이-정규식-입력 문자열]의 조합을 찾아낼 때까지 반복문을 계속 돌렸다. 익스플로잇 코드에서는 `String.prototype.replace` 함수를 반복적으로 호출하기 이전에 14 GiB 의 array 버퍼를 스프레이하도록 했다. 이 과정은 이후 free 된 JSString 의 IndexType 이 결국 8 값으로 덮어씌여지는 상황을 안정적으로 만들어 준다.

우리는 최신 웹킷에서도 익스플로잇을 동작시킬 수 있는 몇 가지 아이디어를 가지고 있었지만, 애플이 버그를 수정하여 더 이상 진행하지 않았다. 다만 이를 통해 우리가 작성한 익스플로잇이 힙의 상태에 매우 의존적이라는 것을 알 수 있다. 만약 익스플로잇의 메모리 할당 패턴을 너무 많이 바꾸면, 그 버그는 더 이상 정확한 시간에 트리거되지 않으며 익스플로잇에 실패하게 된다

## fakeobj/addrof 를 이용한 Read/Write

Saelo의 프랙문서에서는 임의의 읽기/쓰기를 하기 위해 가짜 JSC 객체를 활용했다. 접근 방법은 아래와 같다.


1. Float64Array structure들을 대량 스프레이한다. 그러면 비교적 신뢰성 있게 올바른 structure ID 를 게싱할 수 있다.
2. JSObject 의 inline 속성을 활용하여, Float64Array 타입의 fake 객체를 구성한다. 이 fake 객체를 `fakearray` 라고 하자. `fakearray` 의 JSCell 은 앞서 얻은 structureID 를 가지며, 데이터 포인터(hax라고 하자)는 Uint8Array 객체를 가리키도록 한다.
3. `fakearray[2] = <target address>` 로 세팅함으로써 hax 를 통한 read/write 가 가능해진다.

위 단계의 레이아웃을 아래와 같이 그려볼 수 있다.

```
   fakearray                             hax
+----------------+                  +----------------+
|  Float64Array  |   +------------->|  Uint8Array    |
|                |   |              |                |
|  JSCell        |   |              |  JSCell        |
|  butterfly     |   |              |  butterfly     |
|  vector  ------+---+              |  vector        |
|  length        |                  |  length        |
|  mode          |                  |  mode          |
+----------------+                  +----------------+
```

Pwn2Own 에 사용할 익스플로잇에서도 위와 같은 방식으로 공격하려고 했지만, 1단계에서 힙 레이아웃이 엉망진창이 되는 바람에 그대로 활용할 수가 없었다. 익스플로잇을 복잡하게 만들고 싶지는 않았기에, 우리는 새로 배운 트릭을 활용했다.

1. 다른 객체의 inline 속성을 활용하여, `fakearray` 라는 이름의 fake JSObject 객체를 만든다. `fakearray` 의 Indexing type 은 8, structure ID 는 0, butterfly(hax 라고 하자) 는 Uint8Array 객체를 가리키도록 구성한다. 
2. hax2 라는 이름의 Uint8Array 객체를 추가로 만든다.
3. `fakearray[2] = hax2` 가 되도록 세팅한다. 그러면 hax 의 데이터 버퍼는 hax2 를 가리키게 된다.
4. read/write 를 위해 `hax[16]`, 즉 hax 의 데이터 포인터 에 target address 를 쓴다. 그러면 hax2 의 데이터 버퍼가 target 을 가리키게 될 것이다. 그러면 hax 를 통해 read/write 가 가능하게 된다.

이 트릭은 Safari 10.0.3 환경에서 ID 값이 0인 structure 가 항상 존재하기 때문에 효과가 있다. 이 단계의 레이아웃을 아래와 같이 그려볼 수 있다.


```
     fakearray                        hax                       hax2
+--------------------+         +------------------+        +--------------+
|  JSObject          |   +---->|  Uint8Array      |  +---->|  Uint8Array  |
|                    |   |     |                  |  |     |              |
|  structureID = 0   |   |     |  JSCell          |  |     |  JSCell      |
|  indexingType = 8  |   |     |  butterfly       |  |     |  butterfly   |
|  <rest of JSCell>  |   |     |  vector       ------+     |  vector      |
|  butterfly       ------+     |  length = 0x100  |        |  length      |
|                    |         |  mode            |        |  mode        |
+--------------------+         +------------------+        +--------------+
```


## 박살난 힙 구조로부터 살아남기

free된 JSStrings 중 하나에 JSCell을 할당함으로써, JSString이 저장된 힙 블록의 free list 를 잘 손상시킬 수 있었다. 여기서 할당자를 완전히 망가뜨렸기 때문에, 익스플로잇을 할 때 24 bytes 혹은 32 bytes 크기의 할당은 하지 않도록 주의해야 한다. 말은 간단해서, 아예 객체 생성을 안해버릴 수도 있을 것이다. 그러나 자바스크립트 함수를 호출한다거나 혹은 16번 이상의 반복문 실행으로 인해 JIT 컴파일이 발생한다거나 하는 경우가 발생하면, 엔진 내부에서는 이 문제 있는 사이즈로 메모리 할당을 하게 되고 즉시 크래시로 이어지게 된다.

망가진 free list 를 고쳐 그나마 문제없이 돌아갈 정도의 힙 상태로 복구할 수는 있었겠지만 그러기 위해서는 반복문, 함수호출/정의, 또는 다른 위험한 작업을 필요로 할 것 같았다. Pwn2Own 의 목적을 위해 우리는 지저분하더라도 reliable 한 코드를 작성하기로 결정했다. 2단계에서 우리는 SIGSEGV, SIGBUS, SIGALRM 의 시그널 핸들러가 sleep 함수를 호출하도록 했다. 이렇게 하면 sandbox escape 가 진행되는 동안, 실행 중인 어떤 쓰레드도 프로세스를 파괴할 수 없다.

주석이 포함된 전체 익스플로잇 코드는  cachedcall-uaf.html 파일에서 찾을 수 있다.



