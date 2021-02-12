---
layout: "post"
title: "[Writeup] GitHub Security Lab CTF 1: SEGV hunt"
date: "2021-02-12 19:00"
tag:
- CodeQL
headerImage: true
category: blog
author: y0ny0ns0n
---

작성 - y0ny0ns0n @ null2root


# 목차
1. [소개](#1-소개)
2. [환경 구축](#2-환경-구축)
3. [문제 풀이](#3-문제-풀이)<br>
	3.0.0. [Question 0.0](#300-question-00)<br>
	3.1.0. [Question 1.0](#310-question-10)<br>
	3.1.1. [Question 1.1](#311-question-11)<br>
	3.2.0. [Question 2.0](#320-question-20)<br>
	3.2.1. [Question 2.1](#321-question-21)<br>
	3.2.2. [Question 2.2](#322-question-22)<br>
	3.2.3. [Question 2.3](#323-question-23)<br>
	3.2.4. [Question 2.4](#324-question-24)<br>
	3.2.5. [Question 2.5](#325-question-25)<br>
	3.3.0. [Question 3.0](#330-question-30)<br>
	3.4.0. [Question 4.0](#340-question-40)<br>
	3.4.1. [Question 4.1](#341-question-41)<br>
	3.5.0. [Question 5.0(optional)](#350-question-50optional)<br>
4. [후기](#4-후기)


# 1. 소개
CodeQL은 [LINQ](https://ko.wikipedia.org/wiki/LINQ) 형식의 언어로, source code가 있는 프로젝트들을 대상으로 Data Flow Analysis, Global Value Numbering, Taint Tracking과 같은 static analysis 기능을 제공해 줍니다. CodeQL은 이미 Microsoft\[[1](https://msrc-blog.microsoft.com/2018/08/16/vulnerability-hunting-with-semmle-ql-part-1/)\]\[[2](https://msrc-blog.microsoft.com/2019/03/19/vulnerability-hunting-with-semmle-ql-part-2/)\], Google\[[3](https://bugs.chromium.org/p/project-zero/issues/list?q=label%3AMethodology-static-analysis&can=1)\]과 같은 major software를 유지보수하는 회사들과 여러 security researcher들\[[4](https://github.com/github/securitylab/tree/main/CodeQL_Queries)\]이 실제로 사용하며 그 효용성을 계속 증명해 나가고 있습니다. 보통 취약점 연구를 할때 security researcher들은 거의 대부분 Code Auditing을 기반해 연구를 진행하는데 CodeQL은 (최소한 Open Source 프로젝트에 한해) 이에 대해 많은 도움을 줄 수 있는 좋은 보완재라 생각해 간단하게 사용해 보고 Writeup으로 정리해 보려고 합니다.

[GitHub Security Lab CTF 1: SEGV hunt](https://securitylab.github.com/ctf/segv) 는 Github Security Lab에서 주최했으며 CodeQL 사용법을 익히는데 도움을 주고자 만든 일종의 challenge 형식의 프로젝트입니다. 다른 CTF들도 있지만 제가 관심을 가지는 대상이 거의 대부분 C/C++ 관련 프로젝트들이기 때문에 이 CTF를 골랐습니다. 이 CTF는 CodeQL로 [GNU C Library](https://www.gnu.org/software/libc/)에 있는 [alloca()](http://man7.org/linux/man-pages/man3/alloca.3.html) 함수의 취약점을 step-by-step으로 찾아나가며 CodeQL을 학습하는데 목적을 두고 있습니다.



# 2. 환경 구축
[CodeQL U-Boot Challenge](https://lab.github.com/githubtraining/codeql-u-boot-challenge-(cc++))라고 CodeQL 튜토리얼 같은게 있는데, 기본적인 CodeQL 환경구성과 사용법에 대해 30분~1시간 내외의 짧은 시간안에 배울 수 있으니 Writeup을 보기 전에 한번 해보고 오는 것을 추천드립니다. 

이 CTF는 친절하게도 분석할 glibc의 [CodeQL DB snapshot](https://downloads.lgtm.com/snapshots/cpp/GNU/glibc/bminor_glibc_cpp-srcVersion_333221862ecbebde60dd16e7ca17d26444e62f50-dist_odasa-lgtm-2019-04-08-af06f68-linux64.zip)을 제공해 주는데 만약 해당 DB를 직접 만들어 보고 싶다면 [bminor/glibc repo의 3332218 commit](https://github.com/bminor/glibc/tree/333221862ecbebde60dd16e7ca17d26444e62f50)을 가져와 컴파일하면 제공받은 snapshot과 같은 DB를 만들 수 있습니다\[[5](https://codeql.github.com/docs/codeql-cli/creating-codeql-databases/#specifying-build-commands)\].  __VS Code__ 의 [CodeQL 플러그인](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql)으로 분석할 CodeQL DB를 가져오고 [CodeQL repository](https://github.com/github/codeql)도 cloning해서 `cpp/ql/src` 디렉토리의 하위에 query 문을 작성한 뒤 아래와 같이 정상적으로 실행되면 환경구축이 완료된 것입니다.

![vs code codeql working](/assets/images/segv-hunt-codeql-img-1.png)



# 3. 문제 풀이
## 3.0.0. Question 0.0
- Question 0.0: `alloca` is a macro. Find the definition of this macro and the name of the function that it expands to.

CodeQL의 [Macro Class](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/Macro.qll/type.Macro$Macro.html)를 사용하면 됩니다.

![qustion 0.0 done](/assets/images/segv-hunt-codeql-img-2.png)

glibc의 `alloca` 매크로는 gcc built-in 함수인 `__builtin_alloca`를 확장해 사용합니다.


## 3.1.0. Question 1.0
- Question 1.0: Find all the calls to `alloca` (using the function name that you found in step 0).

`__builtin_alloca` 는 매크로가 아닌 함수이기에, [FunctionCall Class](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/exprs/Call.qll/type.Call$FunctionCall.html)를 사용해 호출자를 찾을 수 있습니다.

![qustion 1.0 done](/assets/images/segv-hunt-codeql-img-3.png)


## 3.1.1. Question 1.1
- Question 1.1: Use the `upperBound` and `lowerBound` predicates from the `SimpleRangeAnalysis` library to filter out results which are safe because the allocation size is small. You can classify the allocation size as small if it is less than `65536`. But don't forget that negative sizes are very dangerous.

[upperBound](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/rangeanalysis/SimpleRangeAnalysis.qll/predicate.SimpleRangeAnalysis$SimpleRangeAnalysisCached$upperBound.1.html) 와 [lowerBound](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/rangeanalysis/SimpleRangeAnalysis.qll/predicate.SimpleRangeAnalysis$SimpleRangeAnalysisCached$lowerBound.1.html) predicate는 특정 expression이 가질 수 있는 최대 범위와 최소 범위를 알아내는데 사용되며 Out-Of-Bound 취약점이나 Integer Overflow 취약점을 찾을 때 유용하게 사용할 수 있을 것입니다.

![qustion 1.1 done](/assets/images/segv-hunt-codeql-img-4.png)


## 3.2.0. Question 2.0
- Question 2.0: Find all calls to `__libc_use_alloca`.

glibc는 `alloca` 매크로를 호출하기 전 `__libc_use_alloca` 함수로 할당하고자 하는 size를 체크한 뒤, 만약 size가 범위를 벗어나면 `malloc` 함수를 사용합니다\[[6](https://github.com/bminor/glibc/blob/333221862ecbebde60dd16e7ca17d26444e62f50/posix/getopt.c#L252-L254)\]. 그렇기 때문에 `alloca` 매크로 호출전에 `__libc_use_alloca` 함수가 호출된다면 해당 매크로 호출은 __안전__ 하다고 할 수 있을 것입니다.

![qustion 2.0 done](/assets/images/segv-hunt-codeql-img-5.png)


## 3.2.1. Question 2.1
- Question 2.1: Find all `guard conditions` where the condition is a call to `__libc_use_alloca`.

[GuardCondition Class](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/controlflow/Guards.qll/type.Guards$GuardCondition.html)는 특정 [Basic Block](https://ko.wikipedia.org/wiki/%EA%B8%B0%EB%B3%B8_%EB%B8%94%EB%A1%9D)으로 진입할지 말지 여부를 결정하는 조건 분기( __switch~case__ 문 제외 )에 대한 Class로 아래와 같이 `__alloca` 매크로를 호출하는 Basic Block으로 진입하는 조건에 `__libc_use_alloca` 함수를 호출하는 경우의 수도 탐지할 수 있습니다.

![qustion 2.1 done](/assets/images/segv-hunt-codeql-img-6.png)

( P.S. `FunctionCall` -> `boolean` 으로 변환하는 방법을 몰라서 아래와 같이 [getAChild predicate](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/exprs/Expr.qll/predicate.Expr$Expr$getAChild.0.html)에 `Transitive Closure *`을 사용했습니다. )


## 3.2.2. Question 2.2
- Question 2.2: Sometimes the result of `__libc_use_alloca` is assigned to a variable, which is then used as the guard condition. For example, this happens at `setsourcefilter.c:38-41`. Enhance your query, using `local dataflow`, so that it also finds this guard condition.

조건 분기에서 `__libc_use_alloca` 함수 호출을 직접적으로 하지 않고 반환값을 사용할 경우 기존의 query문으로는 탐할 수 없고, 아래와 같이 [localFlow predicate](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/dataflow/internal/DataFlowUtil.qll/predicate.DataFlowUtil$localFlow.2.html)를 사용해 `source`를 `__libc_use_alloca` 함수 호출, `sink`를 조건 분기로 설정하면 탐지할 수 있습니다.

![qustion 2.2 done](/assets/images/segv-hunt-codeql-img-7.png)


## 3.2.3. Question 2.3
- Question 2.3: Sometimes the call to `__libc_use_alloca` is wrapped in a call to `__builtin_expect`. For example, this happens at `setenv.c:185`. Enhance your query so that it also finds this guard condition.

만약 조건 분기에서 `__libc_use_alloca` 함수 호출에 대한 반환값을 간접적으로 사용한다면, 아래와 같이 `sink`로 `gc` 대신 `gc.getAChild*()`를 사용해 탐지조건에 포함할 수 있습니다. [Transitive Closure](https://codeql.github.com/docs/ql-language-reference/recursion/#transitive-closures)에서 `*`는 재귀의 꼬리를 포함한 전체집합, `+`는 꼬리를 제외한 여집합을 의미하기 때문에 `sink`로 조건분기 expression의 전체집합을 줌으로써 `__bultin_expect`나 그외 다른 wrapper로 감싸져 있어도 탐지할 수 있게 되는 것입니다.

![qustion 2.3 done](/assets/images/segv-hunt-codeql-img-8.png)


## 3.2.4. Question 2.4
- Question 2.4: Sometimes the result of `__libc_use_alloca` is negated with the `!` operator. For example, this happens at `getaddrinfo.c:2291-2293`. Enhance your query so that it can also handle negations.

이 문제는 `DataFlow Analysis`를 할때 `source`의 범위를 단순히 함수 호출이 아니라 그 이상으로 확장 시켜줘야 합니다. 저는 `__libc_use_alloca` 함수 호출을 `BasicBlock`으로 감싼 뒤, 해당 BB의 [ControlFlowNode](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/controlflow/ControlFlowGraph.qll/type.ControlFlowGraph$ControlFlowNode.html)를 `source`로 지정해 해결했습니다.

![qustion 2.4 done](/assets/images/segv-hunt-codeql-img-9.png)


## 3.2.5. Question 2.5
- Question 2.5: Find calls to `alloca` that are safe because they are guarded by a call to `__libc_use_alloca`.

이후에 사용하기 쉽게 지금까지 찾은 조건들을 `predicate`로 만들었습니다.

![qustion 2.5 done](/assets/images/segv-hunt-codeql-img-10.png)


## 3.3.0. Question 3.0
- Question 3.0: use your answer from step 2 to enhance your query from step 1 by filtering out calls to `alloca` that are safe because they are guarded by a call to `__libc_use_alloca`.

[Question 1.1](#311-_Question-1_1)에서 찾은 조건들도 `predicate`로 만들어 취약할거라고 의심되는 함수 호출 목록을 만들었습니다.

![qustion 3.0 done](/assets/images/segv-hunt-codeql-img-11.png)


## 3.4.0. Question 4.0
- Question 4.0: Find calls to `fopen`. (Be aware that `fopen` is another macro.)

`fopen` 매크로는 [_IO_new_fopen](https://github.com/bminor/glibc/blob/333221862ecbebde60dd16e7ca17d26444e62f50/include/stdio.h#L159-L160) 함수를 호출합니다.

![qustion 4.0 done](/assets/images/segv-hunt-codeql-img-12.png)


## 3.4.1. Question 4.1
-  Question 4.1: Write a taint tracking query. The source should be a call to `fopen` and the sink should be the size argument of an unsafe call to `alloca`. To help you get started, here is the boilerplate for the query:

```text
/**
  * @name 41_fopen_to_alloca_taint
  * @description Track taint from fopen to alloca.
  * @kind path-problem
  * @problem.severity warning
  */

import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.models.interfaces.DataFlow
import semmle.code.cpp.controlflow.Guards
import DataFlow::PathGraph

// replace deprecated predicates name by @y0ny0ns0n

// Track taint through `__strnlen`.
class StrlenFunction extends DataFlowFunction {
  StrlenFunction() { this.getName().matches("%str%len%") }

  override predicate hasDataFlow(FunctionInput i, FunctionOutput o) {
    i.isParameter(0) and o.isReturnValue()
  }
}

// Track taint through `__getdelim`.
class GetDelimFunction extends DataFlowFunction {
  GetDelimFunction() { this.getName().matches("%get%delim%") }

  override predicate hasDataFlow(FunctionInput i, FunctionOutput o) {
    i.isParameter(3) and o.isParameterDeref(0)
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "fopen_to_alloca_taint" }

  override predicate isSource(DataFlow::Node source) {
    // TODO
  }

  override predicate isSink(DataFlow::Node sink) {
    // TODO
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "fopen flows to alloca"
```

우선 위의 query문을 보면, 이미 존재하는 [GetDelimFunction Class](https://github.com/github/codeql/blob/7502c6f/cpp/ql/src/semmle/code/cpp/models/implementations/GetDelim.qll#L9)와 [StrlenFunction Class](https://github.com/github/codeql/blob/f534f09/cpp/ql/src/semmle/code/cpp/models/implementations/Pure.qll#L82)를 재정의하는데, 아마 [Global Taint Tracking](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-cpp/#using-global-taint-tracking)으로 __`fopen` 호출__ -> __`alloca` 의 크기 인자__ 로 이어지는 data flow를 추적하는 과정에서 해당 함수들( `__getdelim`, `__strnlen` )의 data flow를 따로 정의해줄 필요가 있어서 그런것 같습니다. 

query문이 상당히 길어 스크린샷 대신 code snippet을 첨부하겠습니다.

```text
/**
  * @name 41_fopen_to_alloca_taint
  * @description Track taint from fopen to alloca.
  * @kind path-problem
  * @problem.severity warning
  */

 import cpp
 import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
 import semmle.code.cpp.dataflow.TaintTracking
 import semmle.code.cpp.models.interfaces.DataFlow
 import semmle.code.cpp.controlflow.Guards
 import semmle.code.cpp.dataflow.DataFlow
 import DataFlow::PathGraph


 predicate isSafeAllocaCall(FunctionCall allocaCall) {
  exists(FunctionCall fc, DataFlow::Node source, DataFlow::Node sink, GuardCondition guard, BasicBlock block |
    fc.getTarget().hasQualifiedName("__libc_use_alloca") and
    guard.controls(allocaCall.getBasicBlock(), _) and
    DataFlow::localFlow(source, sink) and
    block.contains(fc) and
    source.asExpr() = block.getANode() and
    sink.asExpr() = guard.getAChild*()
  )
}

predicate isOOBAllocaCall(FunctionCall allocaCall) {
  exists(Expr sizeArg | 
    sizeArg = allocaCall.getArgument(0).getFullyConverted() and
    (upperBound(sizeArg) >= 65536 or lowerBound(sizeArg) < 0)
  )
}

// Track taint through `__strnlen`.
class StrlenFunction extends DataFlowFunction {
  StrlenFunction() { this.getName().matches("%str%len%") }

  override predicate hasDataFlow(FunctionInput i, FunctionOutput o) {
    i.isParameter(0) and o.isReturnValue()
  }
}

// Track taint through `__getdelim`.
class GetDelimFunction extends DataFlowFunction {
  GetDelimFunction() { this.getName().matches("%get%delim%") }

  override predicate hasDataFlow(FunctionInput i, FunctionOutput o) {
    i.isParameter(3) and o.isParameterDeref(0)
  }
}
 
 class Config extends TaintTracking::Configuration {
   Config() { this = "fopen_to_alloca_taint" }
 
   override predicate isSource(DataFlow::Node source) {
     exists(FunctionCall fopenCall | 
        fopenCall.getTarget().hasName("_IO_new_fopen") and
        source.asExpr() = fopenCall
      )
   }
 
   override predicate isSink(DataFlow::Node sink) {
     exists(
       Expr sizeArg, FunctionCall allocaCall |
       allocaCall.getTarget().hasQualifiedName("__builtin_alloca") and
       not isSafeAllocaCall(allocaCall) and
       isOOBAllocaCall(allocaCall) and
       sizeArg = allocaCall.getArgument(0).getFullyConverted() and
       sink.asExpr() = sizeArg
     )
   }
 }
 
 from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink, source, sink, "fopen flows to alloca"
```

![qustion 4.1 done](/assets/images/segv-hunt-codeql-img-13.png)


## 3.5.0. Question 5.0(optional)
- Question 5.0: The GNU C Library includes several command-line applications. (It contains 24 main functions.) Demonstrate that the bug is real by showing that you can trigger a `SIGSEGV` in one of these command-line applications.

crash 터트리는 PoC 코드 짜는게 마지막 문제인데, 저는 CodeQL 사용법을 익히기 위해서 시작한거라 해당 문제는 스킵하겠습니다.


# 4. 후기
[Variant Analysis](https://semmle.com/variant-analysis)란 용어가 있습니다. 변인(變因) 분석이라는 뜻 답게 이미 '알려진' 취약점들을 마치 fuzzing의 seed 값처럼 __Control flow analysis__, __Data flow analysis__, __Taint tracking__, __Range analysis__ 등의 정적 분석 방법론들에 활용하며 새로운 취약점을 찾는 분석기법이며, __CodeQL__ 을 사용해 취약점을 찾는 모든 행위를 __Variant Analysis__ 라고 봐도 무방할 것입니다. 제가 다른 정적분석도구를 써본적은 없어 잘 모르지만 [CodeQL은 취약점 분석에 필요한 대부분의 요소들을 이미 구현](https://codeql.github.com/docs/codeql-language-guides/codeql-library-for-cpp/)해 놨고, 실제로 이를 활용해 발견된 취약점도 점점 늘어나고 있습니다.

물론 이를 활용하기 위해선 내가 분석하고자 하는 프로그램의 attack vector와 패치된 취약점 패턴들을 충분히 이해한 상태여야 겠지만, 내가 생각한 취약점 패턴을 단순히 직감의 일부로 넘기는 것이 아니라 나중에 활용할 수 있도록 코드로 저장할 수 있고, 실제로 Github Security Lab에선 Bounty까지 주며 이를 장려하고 있다는 것은 굉장히 큰 장점으로 여겨집니다\[[7](https://securitylab.github.com/bounties)\]. 다음번 포스팅때는 실제로 CodeQL을 활용해 취약점을 찾고 RCA( Root Cause Analysis )까지 하는 것을 목표로 잡고 특정 프로그램을 분석중인데 잘 됐으면 좋겠습니다 ㄷㄷ.

